// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.Message;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.InsecureServerCredentials;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.ServiceDescriptor;
import io.grpc.Status;
import io.grpc.stub.ServerCalls;
import io.grpc.stub.StreamObserver;
import io.rustegon.driver.errors.ErrorCodes;
import io.rustegon.driver.internal.proto.AuthServiceGrpc;
import io.rustegon.driver.internal.proto.AuthSuccess;
import io.rustegon.driver.internal.proto.AuthenticateRequest;
import io.rustegon.driver.internal.proto.AuthenticateResponse;
import io.rustegon.driver.internal.proto.DocumentServiceGrpc;
import io.rustegon.driver.internal.proto.ErrorDetail;
import io.rustegon.driver.internal.proto.ExecuteResponse;
import io.rustegon.driver.internal.proto.InsertRequest;
import io.rustegon.driver.internal.proto.InsertResponse;
import io.rustegon.driver.internal.proto.QueryServiceGrpc;
import io.rustegon.driver.internal.proto.ResultBatch;
import io.rustegon.driver.internal.proto.SchemaServiceGrpc;
import io.rustegon.driver.internal.proto.SessionServiceGrpc;
import io.rustegon.driver.internal.proto.TransactionServiceGrpc;
import io.rustegon.driver.internal.proto.WriteResult;
import io.rustegon.driver.rdoc.RDocReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The in-process fake gRPC server of {@code drivers/conformance/retry.yaml} (PD-073), on the
 * gRPC server shipped in grpc-netty-shaded (found at run time by
 * {@link Grpc#newServerBuilderForPort}); the services are generic handlers over the generated
 * service descriptors.
 *
 * <p>Contract (retry.yaml header): plaintext HTTP/2 on a local port; {@code script} maps an RPC
 * name ({@code DocumentService.Get}) to replies consumed one per call, the last one repeating;
 * unscripted RPCs answer the defaults of README.md §8. A reply is {@code {ok: json}},
 * {@code {error: {code, retryable, committed?, details?, retryAfterMs?}}} (the catalog's gRPC
 * status with a packed {@code ErrorDetail}) or {@code {transport: STATUS}}, optionally with
 * {@code delayMs}. With {@code scram} the server runs the SCRAM-SHA-256 server side for
 * {@code fake} / {@code fake-password-123} (4096 iterations). Every call is recorded.
 */
final class FakeServer implements AutoCloseable {
    static final String SCRAM_USER = "fake";
    static final String SCRAM_PASSWORD = "fake-password-123";
    static final String TXN_ID = "0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60";
    private static final Context.Key<String> REQUEST_ID = Context.key("rgn-request-id");
    private static final Context.Key<String> CAUSALITY = Context.key("rgn-causality-token");
    private static final Metadata.Key<String> REQUEST_ID_HEADER =
            Metadata.Key.of("rgn-request-id", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> CAUSALITY_HEADER =
            Metadata.Key.of("rgn-causality-token", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<byte[]> STATUS_DETAILS =
            Metadata.Key.of("grpc-status-details-bin", Metadata.BINARY_BYTE_MARSHALLER);
    private static final int SCRAM_ITERATIONS = 4096;

    /** One recorded call. */
    static final class Call {
        final String rpc;
        final String requestId;
        /** The {@code rgn-causality-token} the client sent, or {@code null}. */
        final String causalityToken;
        final boolean deadline;
        final long arrivalNanos;
        final Message request;
        volatile long replyNanos;
        volatile boolean failed;

        Call(String rpc, String requestId, boolean deadline, Message request) {
            this.rpc = rpc;
            this.requestId = requestId;
            this.causalityToken = CAUSALITY.get();
            this.deadline = deadline;
            this.arrivalNanos = System.nanoTime();
            this.request = request;
        }
    }

    private final Map<String, List<Map<String, Object>>> script;
    private final Map<String, Integer> consumed = new HashMap<>();
    private final Function<Object, Object> toValue;
    private final List<Call> calls = new CopyOnWriteArrayList<>();
    private final Server server;
    private int tokens;
    private final java.util.concurrent.atomic.AtomicInteger causalityTokens =
            new java.util.concurrent.atomic.AtomicInteger();

    /**
     * Starts the server.
     *
     * @param script replies per RPC (may be empty)
     * @param toValue turns extended-JSON nodes of replies into driver values
     */
    FakeServer(Map<String, List<Map<String, Object>>> script, Function<Object, Object> toValue)
            throws IOException {
        this.script = script;
        this.toValue = toValue;
        ServerInterceptor recorder = new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call,
                    Metadata headers, ServerCallHandler<Q, R> next) {
                Context ctx = Context.current().withValue(REQUEST_ID,
                        headers.get(REQUEST_ID_HEADER)).withValue(CAUSALITY,
                        headers.get(CAUSALITY_HEADER));
                // Every successful reply carries a new causality token ct-<n> (a session
                // must echo the last one it saw).
                ServerCall<Q, R> tokened = new io.grpc.ForwardingServerCall
                        .SimpleForwardingServerCall<>(call) {
                    @Override
                    public void close(Status status, Metadata trailers) {
                        if (status.isOk()) {
                            trailers.put(CAUSALITY_HEADER, "ct-"
                                    + causalityTokens.incrementAndGet());
                        }
                        super.close(status, trailers);
                    }
                };
                return Contexts.interceptCall(ctx, tokened, headers, next);
            }
        };
        var b = Grpc.newServerBuilderForPort(0, InsecureServerCredentials.create());
        for (ServiceDescriptor sd : List.of(DocumentServiceGrpc.getServiceDescriptor(),
                QueryServiceGrpc.getServiceDescriptor(),
                TransactionServiceGrpc.getServiceDescriptor(),
                SessionServiceGrpc.getServiceDescriptor(), AuthServiceGrpc.getServiceDescriptor(),
                SchemaServiceGrpc.getServiceDescriptor())) {
            ServerServiceDefinition.Builder def = ServerServiceDefinition.builder(sd);
            for (MethodDescriptor<?, ?> m : sd.getMethods()) {
                add(def, m);
            }
            b.addService(ServerInterceptors.intercept(def.build(), recorder));
        }
        this.server = b.build().start();
    }

    /** {@code 127.0.0.1:port}. */
    String endpoint() {
        return "127.0.0.1:" + server.getPort();
    }

    List<Call> calls() {
        return List.copyOf(calls);
    }

    /** {@code rustegon.v1.DocumentService/Get} → {@code DocumentService.Get}. */
    static String rpcName(MethodDescriptor<?, ?> m) {
        String service = m.getServiceName();
        return service.substring(service.lastIndexOf('.') + 1) + "." + m.getBareMethodName();
    }

    @SuppressWarnings("unchecked")
    private <Q, R> void add(ServerServiceDefinition.Builder def, MethodDescriptor<Q, R> m) {
        switch (m.getType()) {
            case UNARY -> def.addMethod(m, ServerCalls.asyncUnaryCall((req, obs) ->
                    reply(m, req, obs)));
            case SERVER_STREAMING -> def.addMethod(m, ServerCalls.asyncServerStreamingCall(
                    (req, obs) -> reply(m, req, obs)));
            case BIDI_STREAMING -> def.addMethod(m, ServerCalls.asyncBidiStreamingCall(
                    obs -> (StreamObserver<Q>) authenticate(
                            (StreamObserver<AuthenticateResponse>) obs)));
            default -> throw new IllegalStateException("unexpected method type " + m);
        }
    }

    private synchronized Map<String, Object> next(String rpc) {
        List<Map<String, Object>> replies = script.get(rpc);
        if (replies == null || replies.isEmpty()) {
            return null;
        }
        int i = consumed.merge(rpc, 1, Integer::sum) - 1;
        return replies.get(Math.min(i, replies.size() - 1));
    }

    private Call record(String rpc, Message request) {
        Call c = new Call(rpc, REQUEST_ID.get(), Context.current().getDeadline() != null,
                request);
        calls.add(c);
        return c;
    }

    @SuppressWarnings("unchecked")
    private <Q, R> void reply(MethodDescriptor<Q, R> m, Q req, StreamObserver<R> obs) {
        String rpc = rpcName(m);
        Call call = record(rpc, (Message) req);
        Map<String, Object> reply = next(rpc);
        try {
            if (reply != null && reply.get("delayMs") instanceof Number delay) {
                Thread.sleep(delay.longValue());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        call.replyNanos = System.nanoTime();
        if (reply != null && reply.containsKey("error")) {
            call.failed = true;
            obs.onError(error((Map<String, Object>) reply.get("error")));
            return;
        }
        if (reply != null && reply.containsKey("transport")) {
            call.failed = true;
            obs.onError(Status.fromCode(Status.Code.valueOf((String) reply.get("transport")))
                    .asRuntimeException());
            return;
        }
        Map<String, Object> ok = reply == null ? null : (Map<String, Object>) reply.get("ok");
        if (rpc.equals("QueryService.Execute")) {
            List<Map<String, Object>> batches = ok == null ? List.of(Map.of())
                    : (List<Map<String, Object>>) ok.get("batches");
            for (Map<String, Object> batch : batches) {
                obs.onNext((R) ExecuteResponse.newBuilder().setBatch(ProtoJson.fill(
                        ResultBatch.newBuilder(), batch, toValue)).build());
            }
            obs.onCompleted();
            return;
        }
        Message prototype = (Message) ((MethodDescriptor.PrototypeMarshaller<R>)
                m.getResponseMarshaller()).getMessagePrototype();
        Message response = ok != null
                ? ProtoJson.fill(prototype.newBuilderForType(), ok, toValue).build()
                : defaultReply(rpc, (Message) req, prototype);
        obs.onNext((R) response);
        obs.onCompleted();
    }

    /** README.md §8 defaults. */
    private Message defaultReply(String rpc, Message req, Message prototype) {
        return switch (rpc) {
            case "SessionService.GetServerInfo" -> ProtoJson.fill(prototype.newBuilderForType(),
                    Map.of("serverVersion", "0.0.0-fake", "protocolVersion", "1.0"), toValue)
                    .build();
            case "TransactionService.Begin" -> ProtoJson.fill(prototype.newBuilderForType(),
                    Map.of("txnId", TXN_ID, "heartbeatIntervalMs", 1000), toValue).build();
            case "TransactionService.Status" -> ProtoJson.fill(prototype.newBuilderForType(),
                    Map.of("state", "TRANSACTION_STATE_COMMITTED"), toValue).build();
            case "DocumentService.Insert" -> {
                InsertResponse.Builder r = InsertResponse.newBuilder();
                for (var d : ((InsertRequest) req).getDocumentsList()) {
                    Object id = RDocReader.decode(d.getRdoc().toByteArray()).get("_id");
                    r.addResults(WriteResult.newBuilder().setId(Ast.value(id)));
                }
                yield r.build();
            }
            default -> prototype.getDefaultInstanceForType();
        };
    }

    /** A gRPC status with the catalog's code and a packed {@code ErrorDetail}. */
    @SuppressWarnings("unchecked")
    private static RuntimeException error(Map<String, Object> e) {
        int code = ((Number) e.get("code")).intValue();
        ErrorCodes.Info info = ErrorCodes.find(code);
        ErrorDetail.Builder d = ErrorDetail.newBuilder().setCode(code).setName(info.name())
                .setRetryable((Boolean) e.get("retryable")).setTraceId("0af7651916cd43dd8448eb211c80319c");
        if (e.get("committed") instanceof Boolean c) {
            d.setCommitted(c);
        }
        if (e.get("retryAfterMs") instanceof Number n) {
            d.setRetryAfterMs(n.intValue());
        }
        if (e.get("details") instanceof Map<?, ?> m) {
            ((Map<String, Object>) m).forEach((k, v) -> d.putDetails(k, String.valueOf(v)));
        }
        try {
            ByteArrayOutputStream any = new ByteArrayOutputStream();
            CodedOutputStream a = CodedOutputStream.newInstance(any);
            a.writeString(1, "type.googleapis.com/rustegon.v1.ErrorDetail");
            a.writeBytes(2, d.build().toByteString());
            a.flush();
            ByteArrayOutputStream status = new ByteArrayOutputStream();
            CodedOutputStream s = CodedOutputStream.newInstance(status);
            s.writeInt32(1, info.grpcStatusCode());
            s.writeString(2, info.name());
            s.writeBytes(3, ByteString.copyFrom(any.toByteArray()));
            s.flush();
            Metadata trailers = new Metadata();
            trailers.put(STATUS_DETAILS, status.toByteArray());
            return Status.fromCodeValue(info.grpcStatusCode()).withDescription(info.name())
                    .asRuntimeException(trailers);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    // ------------------------------------------------------------------ SCRAM server side

    private StreamObserver<AuthenticateRequest> authenticate(
            StreamObserver<AuthenticateResponse> out) {
        Call call = record("AuthService.Authenticate", null);
        return new StreamObserver<>() {
            private String clientFirstBare;
            private String serverFirst;
            private byte[] salted;

            @Override
            public void onNext(AuthenticateRequest r) {
                String payload = r.getPayload().toString(StandardCharsets.UTF_8);
                try {
                    if (clientFirstBare == null) {
                        clientFirstBare = payload.substring(payload.indexOf("n=", 3));
                        String clientNonce = clientFirstBare.substring(
                                clientFirstBare.indexOf(",r=") + 3);
                        byte[] salt = new byte[16];
                        new SecureRandom().nextBytes(salt);
                        salted = pbkdf2(salt);
                        serverFirst = "r=" + clientNonce + "fake-server-nonce-0123456789,s="
                                + Base64.getEncoder().encodeToString(salt) + ",i="
                                + SCRAM_ITERATIONS;
                        out.onNext(AuthenticateResponse.newBuilder().setChallenge(
                                ByteString.copyFromUtf8(serverFirst)).build());
                        return;
                    }
                    String withoutProof = payload.substring(0, payload.indexOf(",p="));
                    byte[] proof = Base64.getDecoder().decode(payload.substring(
                            payload.indexOf(",p=") + 3));
                    String authMessage = clientFirstBare + "," + serverFirst + "," + withoutProof;
                    byte[] clientKey = hmac(salted, "Client Key");
                    byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
                    byte[] signature = hmac(storedKey, authMessage);
                    for (int i = 0; i < proof.length; i++) {
                        proof[i] ^= signature[i];
                    }
                    if (!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(proof),
                            storedKey)) {
                        call.failed = true;
                        out.onError(Status.UNAUTHENTICATED.asRuntimeException());
                        return;
                    }
                    String verifier = "v=" + Base64.getEncoder().encodeToString(hmac(
                            hmac(salted, "Server Key"), authMessage));
                    out.onNext(AuthenticateResponse.newBuilder().setSuccess(AuthSuccess
                            .newBuilder().setServerFinal(ByteString.copyFromUtf8(verifier))
                            .setSessionToken(token()).setUser(SCRAM_USER)).build());
                    out.onCompleted();
                    call.replyNanos = System.nanoTime();
                } catch (GeneralSecurityException | RuntimeException e) {
                    call.failed = true;
                    out.onError(Status.INTERNAL.withDescription(e.toString()).asRuntimeException());
                }
            }

            @Override
            public void onError(Throwable t) {}

            @Override
            public void onCompleted() {}
        };
    }

    private synchronized String token() {
        return "fake-session-token-" + (++tokens);
    }

    private static byte[] pbkdf2(byte[] salt) throws GeneralSecurityException {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(
                new PBEKeySpec(SCRAM_PASSWORD.toCharArray(), salt, SCRAM_ITERATIONS, 256))
                .getEncoded();
    }

    private static byte[] hmac(byte[] key, String data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /** Calls of {@code rpc}, in arrival order. */
    List<Call> calls(String rpc) {
        List<Call> out = new ArrayList<>();
        for (Call c : calls) {
            if (c.rpc.equals(rpc)) {
                out.add(c);
            }
        }
        return out;
    }

    @Override
    public void close() {
        server.shutdownNow();
        try {
            server.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
