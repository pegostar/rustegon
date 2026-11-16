// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package io.rustegon.driver.internal;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.WireFormat;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.rustegon.driver.AuthenticationException;
import io.rustegon.driver.AuthorizationException;
import io.rustegon.driver.CommitOutcomeUnknownException;
import io.rustegon.driver.DocumentValidationException;
import io.rustegon.driver.DuplicateKeyException;
import io.rustegon.driver.QuerySyntaxException;
import io.rustegon.driver.RateLimitedException;
import io.rustegon.driver.RustegonClientException;
import io.rustegon.driver.RustegonError;
import io.rustegon.driver.RustegonException;
import io.rustegon.driver.RustegonServerException;
import io.rustegon.driver.RustegonTimeoutException;
import io.rustegon.driver.TransactionAbortedException;
import io.rustegon.driver.TransactionConflictException;
import io.rustegon.driver.UnavailableException;
import io.rustegon.driver.errors.ErrorCodes;
import io.rustegon.driver.internal.proto.ErrorDetail;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;

/**
 * Turns failed gRPC calls into the driver's exception hierarchy (java-driver.md §6; protocol.md
 * §3, §7), by the table of {@code drivers/conformance/errors-map.yaml} compiled as
 * {@link ErrorCodes} (PD-075): the class follows from {@code ErrorDetail.code} only, the retry
 * and commit flags from the response.
 *
 * <p>The server packs {@code ErrorDetail} as a {@code google.protobuf.Any} inside a standard
 * {@code google.rpc.Status} in the {@code grpc-status-details-bin} trailer. That {@code Status}
 * is decoded here with the protobuf wire reader rather than through
 * {@code io.grpc.protobuf.StatusProto}, so the driver needs no {@code proto-google-common-protos}
 * types on its module path. A failure without {@code ErrorDetail} (transport errors, a proxy in
 * between) is mapped from the gRPC status code.
 */
public final class ErrorMapper {
    /** The trailer holding the serialized {@code google.rpc.Status}. */
    static final Metadata.Key<byte[]> STATUS_DETAILS =
            Metadata.Key.of("grpc-status-details-bin", Metadata.BINARY_BYTE_MARSHALLER);
    /** Type URL suffix of {@code ErrorDetail} inside an {@code Any}. */
    private static final String ERROR_DETAIL_TYPE = "/rustegon.v1.ErrorDetail";
    // Field numbers of google.rpc.Status and google.protobuf.Any.
    private static final int STATUS_DETAILS_FIELD = 3;
    private static final int ANY_TYPE_URL_FIELD = 1;
    private static final int ANY_VALUE_FIELD = 2;

    private ErrorMapper() {}

    /**
     * The driver exception for a failed call.
     *
     * @param e the gRPC failure
     * @return the mapped exception (cause = {@code e})
     */
    public static RustegonException map(StatusRuntimeException e) {
        Status status = e.getStatus();
        String message = status.getDescription() == null ? status.getCode().name()
                : status.getDescription();
        Optional<ErrorDetail> detail = errorDetail(e.getTrailers());
        RustegonError error = detail.map(ErrorMapper::fromDetail)
                .orElseGet(() -> fromStatus(status));
        return create(message, error, e);
    }

    /**
     * The {@code ErrorDetail} of a failed call's trailers, if present and well-formed.
     *
     * @param trailers the trailers (may be {@code null})
     * @return the detail
     */
    public static Optional<ErrorDetail> errorDetail(Metadata trailers) {
        if (trailers == null) {
            return Optional.empty();
        }
        byte[] raw = trailers.get(STATUS_DETAILS);
        if (raw == null) {
            return Optional.empty();
        }
        try {
            CodedInputStream in = CodedInputStream.newInstance(raw);
            while (true) {
                int tag = in.readTag();
                if (tag == 0) {
                    return Optional.empty();
                }
                if (WireFormat.getTagFieldNumber(tag) == STATUS_DETAILS_FIELD
                        && WireFormat.getTagWireType(tag) == WireFormat.WIRETYPE_LENGTH_DELIMITED) {
                    Optional<ErrorDetail> d = anyErrorDetail(in.readBytes().newCodedInput());
                    if (d.isPresent()) {
                        return d;
                    }
                } else if (!in.skipField(tag)) {
                    return Optional.empty();
                }
            }
        } catch (IOException ex) {
            // A malformed details trailer is ignored: the status code still classifies it.
            return Optional.empty();
        }
    }

    private static Optional<ErrorDetail> anyErrorDetail(CodedInputStream in) throws IOException {
        String typeUrl = "";
        com.google.protobuf.ByteString value = null;
        while (true) {
            int tag = in.readTag();
            if (tag == 0) {
                break;
            }
            switch (WireFormat.getTagFieldNumber(tag)) {
                case ANY_TYPE_URL_FIELD -> typeUrl = in.readStringRequireUtf8();
                case ANY_VALUE_FIELD -> value = in.readBytes();
                default -> in.skipField(tag);
            }
        }
        if (value == null || !typeUrl.endsWith(ERROR_DETAIL_TYPE)) {
            return Optional.empty();
        }
        try {
            return Optional.of(ErrorDetail.parseFrom(value));
        } catch (InvalidProtocolBufferException ex) {
            return Optional.empty();
        }
    }

    /**
     * The structured error of an {@code ErrorDetail}.
     *
     * @param d the detail
     * @return the error
     */
    public static RustegonError fromDetail(ErrorDetail d) {
        return new RustegonError(d.getCode(), d.getName(), d.getRetryable(),
                d.hasCommitted() ? d.getCommitted() : null, d.getDetailsMap(), d.getTraceId(),
                d.hasRetryAfterMs() ? Duration.ofMillis(Integer.toUnsignedLong(d.getRetryAfterMs()))
                        : null);
    }

    /**
     * The structured error of a failure without {@code ErrorDetail}: the transport fallback of
     * {@code errors-map.yaml} for its gRPC status (synthesized code and retry flag).
     *
     * @param status the gRPC status
     * @return the error
     */
    static RustegonError fromStatus(Status status) {
        ErrorCodes.TransportFallback fallback = transportFallback(status.getCode());
        return new RustegonError(fallback.code(), ErrorCodes.find(fallback.code()).name(),
                fallback.retryable(), null, Map.of(), "", null);
    }

    private static ErrorCodes.TransportFallback transportFallback(Status.Code code) {
        ErrorCodes.TransportFallback any = null;
        for (ErrorCodes.TransportFallback f : ErrorCodes.transportFallbacks()) {
            if (f.grpcStatusName().equals(code.name())) {
                return f;
            }
            if (f.grpcStatusName().equals("default")) {
                any = f;
            }
        }
        if (any == null) {
            // The generator always emits a `default` row (driver_tables.rs checks it).
            throw new IllegalStateException("the error table has no default transport fallback");
        }
        return any;
    }

    /**
     * The exception of an error: the class named by the table for its code, the base class for
     * a code unknown to this driver version (protocol.md §9: new codes never break old drivers).
     *
     * @param message the message
     * @param error the structured error
     * @param cause the cause, or {@code null}
     * @return the exception
     */
    public static RustegonException create(String message, RustegonError error, Throwable cause) {
        ErrorCodes.Info info = ErrorCodes.find(error.code());
        String type = info == null ? ErrorCodes.UNKNOWN_CODE_EXCEPTION_TYPE : info.exceptionType();
        return switch (type) {
            case "RustegonClientException" -> new RustegonClientException(message, error, cause);
            case "QuerySyntaxException" -> new QuerySyntaxException(message, error, cause);
            case "DuplicateKeyException" -> new DuplicateKeyException(message, error, cause);
            case "DocumentValidationException" ->
                    new DocumentValidationException(message, error, cause);
            case "TransactionConflictException" ->
                    new TransactionConflictException(message, error, cause);
            case "TransactionAbortedException" ->
                    new TransactionAbortedException(message, error, cause);
            case "CommitOutcomeUnknownException" ->
                    new CommitOutcomeUnknownException(message, error, cause);
            case "AuthenticationException" -> new AuthenticationException(message, error, cause);
            case "AuthorizationException" -> new AuthorizationException(message, error, cause);
            case "UnavailableException" -> new UnavailableException(message, error, cause);
            case "RateLimitedException" -> new RateLimitedException(message, error, cause);
            case "RustegonTimeoutException" ->
                    new RustegonTimeoutException(message, error, cause);
            case "RustegonServerException" -> new RustegonServerException(message, error, cause);
            // RustegonException, and any class a newer table may name that this code does not
            // know yet (ErrorMappingTest keeps the two in step).
            default -> new RustegonException(message, error, cause);
        };
    }

    /**
     * An error built by the driver itself (no server involved), from the catalog entry; the
     * retry flag is {@code true} only for codes the catalog marks as always retryable.
     *
     * @param code catalog code
     * @param message message
     * @param cause cause or {@code null}
     * @return the exception
     */
    public static RustegonException local(int code, String message, Throwable cause) {
        ErrorCodes.Info entry = ErrorCodes.find(code);
        if (entry == null) {
            throw new IllegalArgumentException("not a catalog code: " + code);
        }
        RustegonError error = new RustegonError(code, entry.name(),
                entry.retryable() == ErrorCodes.Retryable.YES, null, Map.of(), "", null);
        return create(message, error, cause);
    }

    /**
     * Whether a failed call was cancelled because the calling thread was interrupted: such a
     * cancellation is the caller's, reported as {@link java.util.concurrent.CancellationException}
     * rather than a {@link RustegonException} ({@code errors-map.yaml}).
     *
     * @param e the gRPC failure
     * @return {@code true} for an interrupted call
     */
    public static boolean isCallerCancellation(StatusRuntimeException e) {
        return e.getStatus().getCode() == Status.Code.CANCELLED
                && e.getCause() instanceof InterruptedException;
    }

    /**
     * The cancellation reported for an interrupted thread; the interrupt flag is set again so
     * that the caller's own code can still observe it.
     *
     * @param what what was interrupted
     * @param cause the interruption
     * @return the exception to throw
     */
    public static CancellationException cancelled(String what, Throwable cause) {
        Thread.currentThread().interrupt();
        CancellationException c = new CancellationException(what + " was interrupted");
        c.initCause(cause);
        return c;
    }
}
