// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Rustegon.Driver.Errors;
using V1 = Rustegon.V1;

namespace Rustegon.Driver.Tests.Conformance;

/// <summary>One call seen by the fake server.</summary>
/// <param name="Rpc">"Service.Method".</param>
/// <param name="RequestId">The <c>rgn-request-id</c> header.</param>
/// <param name="TxnId">The request's <c>txn_id</c> or <c>rgn-txn-id</c>, if any.</param>
/// <param name="GrpcTimeout">The <c>grpc-timeout</c> header, if any.</param>
/// <param name="Arrival">Arrival time (since the server was created).</param>
/// <param name="Request">The (first) request message.</param>
internal sealed record FakeCall(string Rpc, string? RequestId, string? TxnId, string? GrpcTimeout, TimeSpan Arrival, IMessage? Request)
{
    /// <summary>When the reply was sent (null while pending or when the client gave up first).</summary>
    internal TimeSpan? Replied { get; set; }

    /// <summary>Whether the reply was a failure.</summary>
    internal bool Failed { get; set; }

    /// <summary>The request headers.</summary>
    internal Dictionary<string, string> RequestHeaders { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A request header, or null.</summary>
    internal string? Headers(string name) => RequestHeaders.GetValueOrDefault(name);
}

/// <summary>
/// The in-process fake gRPC server of retry.yaml (PD-073, conformance README §8): an
/// <see cref="HttpMessageHandler"/> given to the driver's <c>GrpcChannel</c> that decodes gRPC
/// frames, answers each RPC with the next scripted reply (the last one repeats; unscripted RPCs
/// get README §8's defaults) and records every call. No sockets and no ASP.NET Core: requests
/// and responses are HTTP/2-shaped messages handled in memory; the duplex
/// <c>AuthService.Authenticate</c> stream is served through <see cref="Pipe"/>s, running the
/// SCRAM-SHA-256 server side for user <c>fake</c> / <c>fake-password-123</c>.
/// </summary>
internal sealed class FakeGrpcServer : HttpMessageHandler
{
    internal const string ScramUser = "fake";
    internal const string ScramPassword = "fake-password-123";
    internal const string FakeTxnId = "0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60";

    private static readonly Dictionary<string, MethodDescriptor> Methods = LoadMethods();

    private readonly Dictionary<string, List<object?>> _script;
    private readonly Dictionary<string, int> _consumed = new(StringComparer.Ordinal);
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly List<FakeCall> _calls = [];
    private int _sessions;

    /// <param name="script">retry.yaml <c>server</c>: RPC name → list of replies.</param>
    internal FakeGrpcServer(Dictionary<string, object?>? script)
    {
        _script = (script ?? []).ToDictionary(kv => kv.Key, kv => (List<object?>)kv.Value!, StringComparer.Ordinal);
    }

    /// <summary>When set, successful replies carry this <c>rgn-causality-token</c> trailer (session tests).</summary>
    internal string? CausalityToken { get; set; }

    /// <summary>A snapshot of the calls so far.</summary>
    internal List<FakeCall> Calls
    {
        get
        {
            lock (_calls)
            {
                return [.. _calls];
            }
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string[] path = request.RequestUri!.AbsolutePath.Trim('/').Split('/');
        string rpc = path[0]["rustegon.v1.".Length..] + "." + path[1];
        if (!Methods.TryGetValue(rpc, out MethodDescriptor? method))
        {
            return Response(request, StatusHeaders(StatusCode.Unimplemented, "unknown method " + rpc, null));
        }

        if (method.IsClientStreaming)
        {
            return await AuthenticateAsync(request, rpc, cancellationToken);
        }

        byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
        IMessage message = method.InputType.Parser.ParseFrom(body.AsSpan(5).ToArray());
        FakeCall call = Record(request, rpc, message);
        Dictionary<string, object?> reply = NextReply(rpc);
        if (reply.GetValueOrDefault("delayMs") is long delay)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(delay), cancellationToken);
        }

        HttpResponseMessage response;
        if (reply.GetValueOrDefault("error") is Dictionary<string, object?> error)
        {
            response = Response(request, ErrorHeaders(error));
            call.Failed = true;
        }
        else if (reply.GetValueOrDefault("transport") is string transport)
        {
            response = Response(request, StatusHeaders(ParseStatus(transport), transport, null));
            call.Failed = true;
        }
        else
        {
            var frames = new MemoryStream();
            foreach (IMessage m in OkMessages(rpc, method, message, reply.GetValueOrDefault("ok")))
            {
                WriteFrame(frames, m.ToByteArray());
            }

            response = Response(request, null, frames.ToArray());
            response.TrailingHeaders.Add("grpc-status", "0");
            if (CausalityToken is { } token)
            {
                response.TrailingHeaders.Add("rgn-causality-token", token);
            }
        }

        call.Replied = _clock.Elapsed;
        return response;
    }

    private FakeCall Record(HttpRequestMessage request, string rpc, IMessage? message)
    {
        string? Header(string name) => request.Headers.TryGetValues(name, out IEnumerable<string>? v) ? v.FirstOrDefault() : null;
        string? txn = Header("rgn-txn-id");
        if (message?.Descriptor.FindFieldByName("txn_id") is { } f && f.Accessor.GetValue(message) is string { Length: > 0 } id)
        {
            txn = id;
        }

        var call = new FakeCall(rpc, Header("rgn-request-id"), txn, Header("grpc-timeout"), _clock.Elapsed, message)
        {
            RequestHeaders = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase),
        };
        lock (_calls)
        {
            _calls.Add(call);
        }

        return call;
    }

    private Dictionary<string, object?> NextReply(string rpc)
    {
        lock (_consumed)
        {
            if (!_script.TryGetValue(rpc, out List<object?>? replies) || replies.Count == 0)
            {
                return [];
            }

            int n = _consumed.GetValueOrDefault(rpc);
            _consumed[rpc] = n + 1;
            return (Dictionary<string, object?>)replies[Math.Min(n, replies.Count - 1)]!;
        }
    }

    /// <summary>The response messages of an <c>ok</c> reply, or of README §8's default for the RPC.</summary>
    private static List<IMessage> OkMessages(string rpc, MethodDescriptor method, IMessage request, object? ok)
    {
        if (ok is null)
        {
            return [Default(rpc, method, request)];
        }

        if (rpc == "QueryService.Execute")
        {
            var batches = (List<object?>)((Dictionary<string, object?>)ok)["batches"]!;
            return [.. batches.Select(b => (IMessage)new V1.ExecuteResponse { Batch = (V1.ResultBatch)Build(V1.ResultBatch.Descriptor, b) })];
        }

        return [Build(method.OutputType, ok)];
    }

    private static IMessage Default(string rpc, MethodDescriptor method, IMessage request) => rpc switch
    {
        "SessionService.GetServerInfo" => new V1.GetServerInfoResponse { ServerVersion = "0.0.0-fake", ProtocolVersion = "1.0" },
        "TransactionService.Begin" => new V1.BeginResponse { TxnId = FakeTxnId, HeartbeatIntervalMs = 1000 },
        "TransactionService.Status" => new V1.StatusResponse { State = V1.TransactionState.Committed },
        "DocumentService.Insert" => InsertDefault((V1.InsertRequest)request),
        "QueryService.Execute" => new V1.ExecuteResponse { Batch = new V1.ResultBatch() },
        _ => (IMessage)Activator.CreateInstance(method.OutputType.ClrType)!,
    };

    private static V1.InsertResponse InsertDefault(V1.InsertRequest request)
    {
        var response = new V1.InsertResponse();
        foreach (V1.Document d in request.Documents)
        {
            RDocValue id = RDocReader.ReadDocument(d.Rdoc.Span)["_id"];
            response.Results.Add(new V1.WriteResult { Id = new V1.Value { RdocValue = ByteString.CopyFrom(RDocWriter.ValueToBytes(id.IsMissing ? RDocValue.FromObjectId(ObjectId.NewObjectId()) : id)) } });
        }

        return response;
    }

    /// <summary>
    /// A message from retry.yaml's response JSON: the protobuf JSON mapping (lowerCamel names, enum
    /// value names), except that <c>Document</c> and <c>Value</c> fields hold canonical extended
    /// JSON which is encoded to RDoc here.
    /// </summary>
    internal static IMessage Build(MessageDescriptor descriptor, object? json)
    {
        var message = (IMessage)Activator.CreateInstance(descriptor.ClrType)!;
        foreach ((string key, object? value) in (Dictionary<string, object?>)json!)
        {
            FieldDescriptor field = descriptor.Fields.InDeclarationOrder().FirstOrDefault(f => f.JsonName == key || f.Name == key)
                ?? throw new FormatException($"{descriptor.Name} has no field '{key}'");
            if (field.IsRepeated)
            {
                var list = (IList)field.Accessor.GetValue(message);
                foreach (object? item in (List<object?>)value!)
                {
                    list.Add(FieldValue(field, item));
                }
            }
            else
            {
                field.Accessor.SetValue(message, FieldValue(field, value));
            }
        }

        return message;
    }

    private static object FieldValue(FieldDescriptor field, object? value) => field.FieldType switch
    {
        FieldType.Message when field.MessageType.FullName == "rustegon.v1.Document" =>
            new V1.Document { Rdoc = ByteString.CopyFrom(ConformanceValues.ToDocument((Dictionary<string, object?>)value!).ToBytes()) },
        FieldType.Message when field.MessageType.FullName == "rustegon.v1.Value" =>
            new V1.Value { RdocValue = ByteString.CopyFrom(RDocWriter.ValueToBytes(ConformanceValues.ToValue(value))) },
        FieldType.Message => Build(field.MessageType, value),
        FieldType.Enum => System.Enum.ToObject(field.EnumType.ClrType, field.EnumType.FindValueByName((string)value!).Number),
        FieldType.String => (string)value!,
        FieldType.Bool => (bool)value!,
        FieldType.UInt32 or FieldType.Fixed32 => Convert.ToUInt32(value, System.Globalization.CultureInfo.InvariantCulture),
        FieldType.UInt64 or FieldType.Fixed64 => Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture),
        FieldType.Int32 or FieldType.SInt32 => Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture),
        FieldType.Int64 or FieldType.SInt64 => Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture),
        FieldType.Bytes => ByteString.CopyFromUtf8((string)value!),
        _ => throw new FormatException($"field type {field.FieldType} is not supported by the fake server"),
    };

    /// <summary>A scripted Rustegon error: the catalog's gRPC status with a packed <c>ErrorDetail</c> (protocol.md §3).</summary>
    private static List<KeyValuePair<string, string>> ErrorHeaders(Dictionary<string, object?> error)
    {
        int code = (int)(long)error["code"]!;
        ErrorCodeInfo info = ErrorCodes.Find(code) ?? throw new FormatException($"unknown code {code}");
        var detail = new V1.ErrorDetail
        {
            Code = (uint)code,
            Name = info.Name,
            Retryable = error.GetValueOrDefault("retryable") is true,
            TraceId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
        };
        if (error.GetValueOrDefault("committed") is bool committed)
        {
            detail.Committed = committed;
        }

        if (error.GetValueOrDefault("retryAfterMs") is long after)
        {
            detail.RetryAfterMs = (uint)after;
        }

        if (error.GetValueOrDefault("details") is Dictionary<string, object?> details)
        {
            foreach ((string k, object? v) in details)
            {
                detail.Details[k] = (string)v!;
            }
        }

        var status = new Google.Rpc.Status { Code = info.GrpcStatusCode, Message = info.Name, Details = { Any.Pack(detail) } };
        return StatusHeaders((StatusCode)info.GrpcStatusCode, info.Name, status);
    }

    private static List<KeyValuePair<string, string>> StatusHeaders(StatusCode code, string message, Google.Rpc.Status? status)
    {
        var headers = new List<KeyValuePair<string, string>>
        {
            new("grpc-status", ((int)code).ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("grpc-message", Uri.EscapeDataString(message)),
        };
        if (status is not null)
        {
            headers.Add(new("grpc-status-details-bin", Convert.ToBase64String(status.ToByteArray())));
        }

        return headers;
    }

    private static StatusCode ParseStatus(string name) =>
        System.Enum.Parse<StatusCode>(name.Replace("_", string.Empty, StringComparison.Ordinal), ignoreCase: true);

    /// <summary>A gRPC response: a trailers-only status (headers given) or a body of frames.</summary>
    private static HttpResponseMessage Response(HttpRequestMessage request, List<KeyValuePair<string, string>>? trailersOnly, byte[]? body = null)
    {
        var content = new ByteArrayContent(body ?? []);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Version = HttpVersion.Version20, RequestMessage = request, Content = content };
        foreach (KeyValuePair<string, string> h in trailersOnly ?? [])
        {
            response.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }

        return response;
    }

    private static void WriteFrame(Stream output, byte[] message)
    {
        Span<byte> header = stackalloc byte[5];
        header[0] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(header[1..], (uint)message.Length);
        output.Write(header);
        output.Write(message);
    }

    private static async Task<byte[]?> ReadFrameAsync(Stream input, CancellationToken cancellationToken)
    {
        byte[] header = new byte[5];
        int read = await input.ReadAtLeastAsync(header, 5, throwOnEndOfStream: false, cancellationToken);
        if (read < 5)
        {
            return null;
        }

        byte[] message = new byte[BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1))];
        await input.ReadExactlyAsync(message, cancellationToken);
        return message;
    }

    /// <summary>
    /// <c>AuthService.Authenticate</c> (duplex): the request body is pumped into a pipe while the
    /// response streams through another one, so each SCRAM step answers before the client sends
    /// the next. Server side of RFC 5802 / 7677 without channel binding (PD-074).
    /// </summary>
    private async Task<HttpResponseMessage> AuthenticateAsync(HttpRequestMessage request, string rpc, CancellationToken cancellationToken)
    {
        FakeCall call = Record(request, rpc, null);
        var inbound = new Pipe();
        var outbound = new Pipe();
        _ = PumpAsync(request.Content!, inbound.Writer, cancellationToken);
        var content = new StreamContent(outbound.Reader.AsStream());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Version = HttpVersion.Version20, RequestMessage = request, Content = content };
        _ = ScramAsync(inbound.Reader.AsStream(), outbound.Writer, response, call, cancellationToken);
        await Task.Yield();
        return response;
    }

    private static async Task PumpAsync(HttpContent content, PipeWriter writer, CancellationToken cancellationToken)
    {
        try
        {
            await content.CopyToAsync(writer.AsStream(leaveOpen: true), cancellationToken);
            await writer.CompleteAsync();
        }
        catch (Exception e)
        {
            await writer.CompleteAsync(e);
        }
    }

    private async Task ScramAsync(Stream input, PipeWriter output, HttpResponseMessage response, FakeCall call, CancellationToken cancellationToken)
    {
        Stream outStream = output.AsStream(leaveOpen: true);
        try
        {
            byte[] first = await ReadFrameAsync(input, cancellationToken) ?? throw new InvalidDataException("no client-first");
            string clientFirst = V1.AuthenticateRequest.Parser.ParseFrom(first).Payload.ToStringUtf8();
            string bare = clientFirst["n,,".Length..];
            string clientNonce = bare[(bare.IndexOf(",r=", StringComparison.Ordinal) + 3)..];
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            const int iterations = 4096;
            string serverFirst = $"r={clientNonce}{Convert.ToBase64String(RandomNumberGenerator.GetBytes(18))},s={Convert.ToBase64String(salt)},i={iterations}";
            WriteFrame(outStream, new V1.AuthenticateResponse { Challenge = ByteString.CopyFromUtf8(serverFirst) }.ToByteArray());
            await outStream.FlushAsync(cancellationToken);

            byte[] final = await ReadFrameAsync(input, cancellationToken) ?? throw new InvalidDataException("no client-final");
            string clientFinal = V1.AuthenticateRequest.Parser.ParseFrom(final).Payload.ToStringUtf8();
            int proofAt = clientFinal.IndexOf(",p=", StringComparison.Ordinal);
            string authMessage = $"{bare},{serverFirst},{clientFinal[..proofAt]}";
            byte[] salted = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(ScramPassword), salt, iterations, HashAlgorithmName.SHA256, 32);
            byte[] clientKey = HMACSHA256.HashData(salted, Encoding.UTF8.GetBytes("Client Key"));
            byte[] clientSignature = HMACSHA256.HashData(SHA256.HashData(clientKey), Encoding.UTF8.GetBytes(authMessage));
            byte[] proof = Convert.FromBase64String(clientFinal[(proofAt + 3)..]);
            for (int i = 0; i < proof.Length; i++)
            {
                proof[i] ^= clientSignature[i];
            }

            if (!proof.AsSpan().SequenceEqual(clientKey))
            {
                throw new InvalidDataException("wrong SCRAM proof");
            }

            byte[] serverSignature = HMACSHA256.HashData(HMACSHA256.HashData(salted, Encoding.UTF8.GetBytes("Server Key")), Encoding.UTF8.GetBytes(authMessage));
            var success = new V1.AuthSuccess
            {
                ServerFinal = ByteString.CopyFromUtf8("v=" + Convert.ToBase64String(serverSignature)),
                SessionToken = "fake-session-" + Interlocked.Increment(ref _sessions),
                ExpiresAtUnixMs = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds(),
                User = ScramUser,
            };
            WriteFrame(outStream, new V1.AuthenticateResponse { Success = success }.ToByteArray());
            response.TrailingHeaders.Add("grpc-status", "0");
            call.Replied = _clock.Elapsed;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            response.TrailingHeaders.Add("grpc-status", ((int)StatusCode.Unauthenticated).ToString(System.Globalization.CultureInfo.InvariantCulture));
            response.TrailingHeaders.Add("grpc-message", "fake-authentication-failed");
            call.Failed = true;
        }
        finally
        {
            await outStream.FlushAsync(CancellationToken.None);
            await output.CompleteAsync();
        }
    }

    private static Dictionary<string, MethodDescriptor> LoadMethods()
    {
        var methods = new Dictionary<string, MethodDescriptor>(StringComparer.Ordinal);
        foreach (FileDescriptor file in new[]
        {
            V1.DocumentReflection.Descriptor, V1.QueryReflection.Descriptor, V1.TransactionReflection.Descriptor,
            V1.SessionReflection.Descriptor, V1.SchemaReflection.Descriptor, V1.AuthReflection.Descriptor, V1.AdminReflection.Descriptor,
        })
        {
            foreach (ServiceDescriptor service in file.Services)
            {
                foreach (MethodDescriptor m in service.Methods)
                {
                    methods[service.Name + "." + m.Name] = m;
                }
            }
        }

        return methods;
    }
}
