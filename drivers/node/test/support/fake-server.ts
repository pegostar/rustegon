// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * The in-process fake gRPC server of retry.yaml (PD-073): serves every rustegon.v1 service on a
 * local plaintext HTTP/2 port with replies scripted per RPC (the last one repeats), the README §8
 * defaults otherwise, the SCRAM server side for `fake` / `fake-password-123`, and records every
 * call (RPC, request id, transaction id, deadline, arrival and reply times).
 */

import * as grpc from '@grpc/grpc-js';
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { create, fromBinary, toBinary, type DescField, type DescMessage, type DescService, type Message } from '@bufbuild/protobuf';
import { BinaryWriter } from '@bufbuild/protobuf/wire';
import { DocumentService } from '../../src/generated/rustegon/v1/document_pb.js';
import { QueryService } from '../../src/generated/rustegon/v1/query_pb.js';
import { SchemaService } from '../../src/generated/rustegon/v1/schema_pb.js';
import { SessionService } from '../../src/generated/rustegon/v1/session_pb.js';
import { TransactionService } from '../../src/generated/rustegon/v1/transaction_pb.js';
import { AuthService } from '../../src/generated/rustegon/v1/auth_pb.js';
import { AdminService } from '../../src/generated/rustegon/v1/admin_pb.js';
import { ErrorDetailSchema } from '../../src/generated/rustegon/v1/error_pb.js';
import { ObjectId, decodeDocument, encodeDocument, encodeValue } from '../../src/index.ts';
import { CODES } from '../../src/errors/codes.generated.ts';
import { asMap, type Yaml, type YamlMap } from './files.ts';
import { isMap, toDocument, toValue } from './conformance/values.ts';

export const SCRAM_USER = 'fake';
export const SCRAM_PASSWORD = 'fake-password-123';
export const FAKE_TXN_ID = '0190f3a4-7b1c-7cc1-8a9e-1d2c3b4a5f60';

export interface FakeCall {
  readonly rpc: string;
  readonly requestId: string | undefined;
  readonly txnId: string | undefined;
  readonly hasDeadline: boolean;
  readonly arrival: number;
  replied: number | undefined;
  failed: boolean;
  readonly request: Message | undefined;
  readonly headers: grpc.Metadata;
}

const SERVICES: DescService[] = [DocumentService, QueryService, SchemaService, SessionService, TransactionService, AuthService, AdminService];

export class FakeServer {
  readonly calls: FakeCall[] = [];
  /** Trailer `rgn-causality-token` sent with every OK reply, when set. */
  causalityToken: string | undefined;
  private readonly script: YamlMap;
  private readonly consumed = new Map<string, number>();
  private readonly server = new grpc.Server();
  private readonly t0 = performance.now();
  private sessions = 0;
  port = 0;

  constructor(script: YamlMap | undefined) {
    this.script = script ?? {};
    for (const service of SERVICES) {
      const definition: Record<string, grpc.MethodDefinition<Message, Message>> = {};
      const handlers: grpc.UntypedServiceImplementation = {};
      for (const method of service.methods) {
        const rpc = `${service.name}.${method.name}`;
        definition[method.name] = {
          path: `/${service.typeName}/${method.name}`,
          requestStream: method.methodKind === 'client_streaming' || method.methodKind === 'bidi_streaming',
          responseStream: method.methodKind === 'server_streaming' || method.methodKind === 'bidi_streaming',
          requestSerialize: (m: Message) => Buffer.from(toBinary(method.input, m)),
          requestDeserialize: (b: Buffer) => fromBinary(method.input, b),
          responseSerialize: (m: Message) => Buffer.from(toBinary(method.output, m)),
          responseDeserialize: (b: Buffer) => fromBinary(method.output, b),
          originalName: method.localName,
        };
        switch (method.methodKind) {
          case 'unary':
            handlers[method.name] = (call: grpc.ServerUnaryCall<Message, Message>, callback: grpc.sendUnaryData<Message>) => {
              void this.unary(rpc, method.output, call, callback);
            };
            break;
          case 'server_streaming':
            handlers[method.name] = (call: grpc.ServerWritableStream<Message, Message>) => {
              void this.stream(rpc, method.output, call);
            };
            break;
          default:
            handlers[method.name] = (call: grpc.ServerDuplexStream<Message, Message>) => {
              void this.authenticate(rpc, call);
            };
        }
      }
      this.server.addService(definition, handlers);
    }
  }

  async start(): Promise<string> {
    this.port = await new Promise<number>((resolve, reject) => {
      this.server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, port) => (err === null ? resolve(port) : reject(err)));
    });
    return `127.0.0.1:${this.port}`;
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.tryShutdown(() => resolve());
      // Calls left open (a client that never read the stream) must not hold the run.
      setTimeout(() => this.server.forceShutdown(), 2_000).unref();
    });
  }

  callsOf(rpc: string): FakeCall[] {
    return this.calls.filter((c) => c.rpc === rpc);
  }

  private now(): number {
    return performance.now() - this.t0;
  }

  private record(rpc: string, call: { metadata: grpc.Metadata; getDeadline(): grpc.Deadline }, request: Message | undefined): FakeCall {
    const header = (name: string): string | undefined => {
      const v = call.metadata.get(name)[0];
      return typeof v === 'string' ? v : undefined;
    };
    const txnField = (request as unknown as { txnId?: unknown } | undefined)?.txnId;
    const deadline = call.getDeadline();
    const c: FakeCall = {
      rpc,
      requestId: header('rgn-request-id'),
      txnId: typeof txnField === 'string' && txnField.length > 0 ? txnField : header('rgn-txn-id'),
      hasDeadline: deadline instanceof Date || (typeof deadline === 'number' && Number.isFinite(deadline)),
      arrival: this.now(),
      replied: undefined,
      failed: false,
      request,
      headers: call.metadata,
    };
    this.calls.push(c);
    return c;
  }

  private next(rpc: string): YamlMap {
    const replies = this.script[rpc];
    if (!Array.isArray(replies) || replies.length === 0) {
      return {};
    }
    const n = this.consumed.get(rpc) ?? 0;
    this.consumed.set(rpc, n + 1);
    return asMap(replies[Math.min(n, replies.length - 1)]);
  }

  private async unary(rpc: string, output: DescMessage, call: grpc.ServerUnaryCall<Message, Message>, callback: grpc.sendUnaryData<Message>): Promise<void> {
    const record = this.record(rpc, call, call.request);
    const reply = this.next(rpc);
    if (typeof reply.delayMs === 'bigint') {
      await sleep(Number(reply.delayMs));
    }
    const failure = this.failure(reply);
    if (failure !== undefined) {
      record.failed = true;
      callback(failure);
    } else {
      const messages = okMessages(rpc, output, call.request, reply.ok);
      callback(null, messages[0], this.trailers());
    }
    record.replied = this.now();
  }

  private async stream(rpc: string, output: DescMessage, call: grpc.ServerWritableStream<Message, Message>): Promise<void> {
    const record = this.record(rpc, call, call.request);
    const reply = this.next(rpc);
    if (typeof reply.delayMs === 'bigint') {
      await sleep(Number(reply.delayMs));
    }
    const failure = this.failure(reply);
    if (failure !== undefined) {
      record.failed = true;
      call.emit('error', failure);
    } else {
      for (const m of okMessages(rpc, output, call.request, reply.ok)) {
        call.write(m);
      }
      call.end(this.trailers());
    }
    record.replied = this.now();
  }

  private trailers(): grpc.Metadata {
    const md = new grpc.Metadata();
    if (this.causalityToken !== undefined) {
      md.set('rgn-causality-token', this.causalityToken);
    }
    return md;
  }

  /** A scripted Rustegon error (catalog gRPC status + packed ErrorDetail) or transport status. */
  private failure(reply: YamlMap): Partial<grpc.StatusObject> | undefined {
    if (typeof reply.transport === 'string') {
      const code = (grpc.status as unknown as Record<string, number>)[reply.transport];
      return { code: code ?? grpc.status.UNKNOWN, details: reply.transport, metadata: new grpc.Metadata() };
    }
    if (!isMap(reply.error)) {
      return undefined;
    }
    const e = reply.error;
    const code = Number(e.code);
    const entry = CODES.get(code);
    if (entry === undefined) {
      throw new Error(`unknown code ${code}`);
    }
    const detail = create(ErrorDetailSchema, {
      code,
      name: entry.name,
      retryable: e.retryable === true,
      traceId: randomBytes(16).toString('hex'),
      ...(typeof e.committed === 'boolean' ? { committed: e.committed } : {}),
      ...(typeof e.retryAfterMs === 'bigint' ? { retryAfterMs: Number(e.retryAfterMs) } : {}),
      details: isMap(e.details) ? Object.fromEntries(Object.entries(e.details).map(([k, v]) => [k, String(v)])) : {},
    });
    const grpcCode = (grpc.status as unknown as Record<string, number>)[entry.grpc] ?? grpc.status.UNKNOWN;
    // google.rpc.Status { code, message, details: [Any] }, encoded by hand (no googleapis protos).
    const any = new BinaryWriter().tag(1, 2).string('type.googleapis.com/rustegon.v1.ErrorDetail').tag(2, 2).bytes(toBinary(ErrorDetailSchema, detail)).finish();
    const status = new BinaryWriter().tag(1, 0).int32(grpcCode).tag(2, 2).string(entry.name).tag(3, 2).bytes(any).finish();
    const metadata = new grpc.Metadata();
    metadata.set('grpc-status-details-bin', Buffer.from(status));
    return { code: grpcCode, details: entry.name, metadata };
  }

  /** The SCRAM-SHA-256 server side (any salt, 4096 iterations) and X.509-less session tokens. */
  private async authenticate(rpc: string, call: grpc.ServerDuplexStream<Message, Message>): Promise<void> {
    const record = this.record(rpc, call, undefined);
    const it = call[Symbol.asyncIterator]() as AsyncIterator<{ payload: Uint8Array }>;
    const reply = (m: Message): boolean => call.write(m);
    try {
      const first = await it.next();
      if (first.done === true) {
        throw new Error('no client-first');
      }
      const clientFirst = new TextDecoder().decode(first.value.payload);
      const bare = clientFirst.slice('n,,'.length);
      const clientNonce = bare.slice(bare.indexOf(',r=') + 3);
      const salt = randomBytes(16);
      const iterations = 4096;
      const serverFirst = `r=${clientNonce}${randomBytes(18).toString('base64')},s=${salt.toString('base64')},i=${iterations}`;
      const output = AuthService.method.authenticate.output;
      reply(create(output, { step: { case: 'challenge', value: new TextEncoder().encode(serverFirst) } }));
      const final = await it.next();
      if (final.done === true) {
        throw new Error('no client-final');
      }
      const clientFinal = new TextDecoder().decode(final.value.payload);
      const proofAt = clientFinal.indexOf(',p=');
      const authMessage = `${bare},${serverFirst},${clientFinal.slice(0, proofAt)}`;
      const salted = pbkdf2Sync(SCRAM_PASSWORD, salt, iterations, 32, 'sha256');
      const clientKey = createHmac('sha256', salted).update('Client Key').digest();
      const signature = createHmac('sha256', createHash('sha256').update(clientKey).digest()).update(authMessage).digest();
      const proof = Buffer.from(clientFinal.slice(proofAt + 3), 'base64');
      for (let i = 0; i < proof.length; i++) {
        proof[i] = (proof[i] ?? 0) ^ (signature[i] ?? 0);
      }
      if (proof.length !== clientKey.length || !timingSafeEqual(proof, clientKey)) {
        throw new Error('wrong SCRAM proof');
      }
      const serverSignature = createHmac('sha256', createHmac('sha256', salted).update('Server Key').digest()).update(authMessage).digest();
      reply(
        create(output, {
          step: {
            case: 'success',
            value: {
              serverFinal: new TextEncoder().encode(`v=${serverSignature.toString('base64')}`),
              sessionToken: `fake-session-${++this.sessions}`,
              expiresAtUnixMs: BigInt(Date.now() + 3_600_000),
              user: SCRAM_USER,
            },
          },
        }),
      );
      call.end();
    } catch {
      record.failed = true;
      call.emit('error', { code: grpc.status.UNAUTHENTICATED, details: 'fake-authentication-failed', metadata: new grpc.Metadata() });
    }
    record.replied = this.now();
  }
}

/** The response messages of an `ok` reply, or README §8's default for the RPC. */
function okMessages(rpc: string, output: DescMessage, request: Message, ok: Yaml | undefined): Message[] {
  if (ok === undefined || ok === null) {
    return [defaultReply(rpc, output, request)];
  }
  if (rpc === 'QueryService.Execute') {
    const batches = asMap(ok).batches;
    return (Array.isArray(batches) ? batches : []).map((b) => create(output, { batch: build(QueryService.method.execute.output.field.batch.message!, b) }));
  }
  return [create(output, build(output, ok))];
}

function defaultReply(rpc: string, output: DescMessage, request: Message): Message {
  switch (rpc) {
    case 'SessionService.GetServerInfo':
      return create(output, { serverVersion: '0.0.0-fake', protocolVersion: '1.0' });
    case 'TransactionService.Begin':
      return create(output, { txnId: FAKE_TXN_ID, heartbeatIntervalMs: 1000 });
    case 'TransactionService.Status':
      return create(output, { state: 3 /* COMMITTED */ });
    case 'DocumentService.Insert': {
      const docs = (request as unknown as { documents: { rdoc: Uint8Array }[] }).documents;
      return create(output, {
        results: docs.map((d) => {
          const id = decodeDocument(d.rdoc)._id;
          return { id: { rdocValue: encodeValue(id === undefined ? ObjectId.generate() : id) } };
        }),
      });
    }
    case 'QueryService.Execute':
      return create(output, { batch: {} });
    default:
      return create(output);
  }
}

/**
 * A message init from retry.yaml's response JSON: the protobuf JSON mapping (lowerCamel names,
 * enum value names), except that Document and Value fields hold canonical extended JSON, which
 * is encoded to RDoc here.
 */
export function build(desc: DescMessage, json: Yaml): Record<string, unknown> {
  const init: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(asMap(json))) {
    const field = desc.fields.find((f) => f.jsonName === key || f.name === key || f.localName === key);
    if (field === undefined) {
      throw new Error(`${desc.name} has no field '${key}'`);
    }
    const v = fieldValue(field, value);
    if (field.oneof !== undefined) {
      init[field.oneof.localName] = { case: field.localName, value: v };
    } else {
      init[field.localName] = v;
    }
  }
  return init;
}

function fieldValue(field: DescField, value: Yaml): unknown {
  switch (field.fieldKind) {
    case 'list':
      return (Array.isArray(value) ? value : []).map((item) =>
        field.listKind === 'message' ? messageValue(field.message, item) : field.listKind === 'enum' ? enumValue(field.enum.values, item) : scalarValue(field.scalar, item),
      );
    case 'map':
      return Object.fromEntries(
        Object.entries(asMap(value)).map(([k, v]) => [k, field.mapKind === 'message' ? messageValue(field.message, v) : field.mapKind === 'enum' ? enumValue(field.enum.values, v) : scalarValue(field.scalar, v)]),
      );
    case 'message':
      return messageValue(field.message, value);
    case 'enum':
      return enumValue(field.enum.values, value);
    default:
      return scalarValue(field.scalar, value);
  }
}

function messageValue(desc: DescMessage, value: Yaml): unknown {
  if (desc.typeName === 'rustegon.v1.Document') {
    return { rdoc: encodeDocument(toDocument(asMap(value))) };
  }
  if (desc.typeName === 'rustegon.v1.Value') {
    return { rdocValue: encodeValue(toValue(value)) };
  }
  return build(desc, value);
}

function enumValue(values: readonly { name: string; number: number }[], value: Yaml): number {
  const found = values.find((v) => v.name === value);
  if (found === undefined) {
    throw new Error(`unknown enum value ${String(value)}`);
  }
  return found.number;
}

function scalarValue(scalar: number, value: Yaml): unknown {
  // ScalarType: 3 INT64, 4 UINT64, 6 FIXED64, 16 SFIXED64, 18 SINT64 are bigint; 9 STRING; 8 BOOL; 12 BYTES.
  if ([3, 4, 6, 16, 18].includes(scalar)) {
    return BigInt(value as bigint | number | string);
  }
  if (scalar === 9) {
    return String(value);
  }
  if (scalar === 8) {
    return value === true;
  }
  if (scalar === 12) {
    return new TextEncoder().encode(String(value));
  }
  return Number(value);
}
