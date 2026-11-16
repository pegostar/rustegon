// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

/**
 * Thin promise wrappers over @grpc/grpc-js generic calls with protobuf-es messages, and the
 * mapping of a failed call to the driver's error hierarchy (protocol.md §7, errors-map.yaml).
 */

import * as grpc from '@grpc/grpc-js';
import { fromBinary, toBinary, type DescMessage, type DescMethod, type MessageShape } from '@bufbuild/protobuf';
import { BinaryReader } from '@bufbuild/protobuf/wire';
import { ErrorDetailSchema } from '../generated/rustegon/v1/error_pb.js';
import { codeName, errorFromInfo, errorFromTransport, type RustegonError } from '../errors/errors.ts';

export const REQUEST_ID_HEADER = 'rgn-request-id';
export const CAUSALITY_TOKEN_HEADER = 'rgn-causality-token';
const STATUS_DETAILS_HEADER = 'grpc-status-details-bin';
const ERROR_DETAIL_TYPE = 'type.googleapis.com/rustegon.v1.ErrorDetail';

/** The gRPC path of a protobuf-es method descriptor. */
export function pathOf(method: DescMethod): string {
  return `/${method.parent.typeName}/${method.name}`;
}

function serializer<D extends DescMessage>(schema: D): (value: MessageShape<D>) => Buffer {
  return (value) => {
    const bytes = toBinary(schema, value);
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  };
}

function deserializer<D extends DescMessage>(schema: D): (value: Buffer) => MessageShape<D> {
  return (value) => fromBinary(schema, value);
}

export interface CallResult<T> {
  readonly value: T;
  readonly trailers: grpc.Metadata;
}

/** A unary call; resolves with the response and the trailers once the status is OK. */
export function unaryCall<I extends DescMessage, O extends DescMessage>(
  client: grpc.Client,
  method: DescMethod & { input: I; output: O },
  request: MessageShape<I>,
  metadata: grpc.Metadata,
  options: grpc.CallOptions,
  signal?: AbortSignal,
): Promise<CallResult<MessageShape<O>>> {
  return new Promise((resolve, reject) => {
    let value: MessageShape<O> | undefined;
    const call = client.makeUnaryRequest(
      pathOf(method),
      serializer(method.input),
      deserializer(method.output),
      request,
      metadata,
      options,
      (err, response) => {
        signal?.removeEventListener('abort', onAbort);
        if (err !== null) {
          reject(err);
        } else {
          value = response;
        }
      },
    );
    // grpc-js reports the trailers (causality token) on 'status', after the callback.
    call.on('status', (status: grpc.StatusObject) => {
      if (status.code === grpc.status.OK && value !== undefined) {
        resolve({ value, trailers: status.metadata });
      }
    });
    const onAbort = (): void => call.cancel();
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** A server-streaming call, read to the end (the Execute stream of a query is small: one batch). */
export function serverStreamCall<I extends DescMessage, O extends DescMessage>(
  client: grpc.Client,
  method: DescMethod & { input: I; output: O },
  request: MessageShape<I>,
  metadata: grpc.Metadata,
  options: grpc.CallOptions,
  received: MessageShape<O>[],
  signal?: AbortSignal,
): Promise<grpc.Metadata> {
  return new Promise((resolve, reject) => {
    const call = client.makeServerStreamRequest(pathOf(method), serializer(method.input), deserializer(method.output), request, metadata, options);
    const onAbort = (): void => call.cancel();
    signal?.addEventListener('abort', onAbort, { once: true });
    // `received` is filled in place: a stream that delivered a batch before failing must not be
    // retried (retry.yaml R3), so the caller needs to know even when the promise rejects.
    call.on('data', (m: MessageShape<O>) => received.push(m));
    call.on('error', (e: Error) => {
      signal?.removeEventListener('abort', onAbort);
      reject(e);
    });
    call.on('status', (status: grpc.StatusObject) => {
      if (status.code === grpc.status.OK) {
        signal?.removeEventListener('abort', onAbort);
        resolve(status.metadata);
      }
    });
  });
}

/** True for an error object raised by grpc-js for a call. */
export function isServiceError(e: unknown): e is grpc.ServiceError {
  return e instanceof Error && typeof (e as Partial<grpc.ServiceError>).code === 'number' && 'metadata' in e;
}

const STATUS_NAMES = new Map<number, string>(
  Object.entries(grpc.status)
    .filter((entry): entry is [string, number] => typeof entry[1] === 'number')
    .map(([name, code]) => [code, name]),
);

/** The gRPC status name of a code (`UNAVAILABLE`, …). */
export function statusName(code: number): string {
  return STATUS_NAMES.get(code) ?? 'UNKNOWN';
}

/**
 * The driver error of a failed call: the class from `ErrorDetail.code` when the server packed
 * one into `grpc-status-details-bin`, else the transport fallback of the status (errors-map.yaml).
 */
export function errorFromServiceError(e: grpc.ServiceError): RustegonError {
  const message = e.details.length > 0 ? e.details : statusName(e.code);
  const detail = errorDetailOf(e.metadata);
  if (detail !== undefined) {
    return errorFromInfo(
      {
        code: detail.code,
        name: detail.name.length > 0 ? detail.name : codeName(detail.code),
        retryable: detail.retryable,
        committed: detail.committed,
        details: Object.keys(detail.details).length === 0 ? undefined : { ...detail.details },
        traceId: detail.traceId.length > 0 ? detail.traceId : undefined,
        retryAfterMs: detail.retryAfterMs,
      },
      message,
      e,
    );
  }
  return errorFromTransport(statusName(e.code), message, e);
}

/** The packed ErrorDetail of a `google.rpc.Status` trailer, or undefined (absent or corrupt). */
export function errorDetailOf(metadata: grpc.Metadata | undefined) {
  const raw = metadata?.get(STATUS_DETAILS_HEADER)[0];
  if (raw === undefined) {
    return undefined;
  }
  const bytes = typeof raw === 'string' ? Buffer.from(raw, 'base64') : raw;
  try {
    // google.rpc.Status: 1 code, 2 message, 3 repeated Any {1 type_url, 2 value}. Decoded by hand
    // so the driver needs no googleapis protos for one message.
    const reader = new BinaryReader(bytes);
    while (reader.pos < reader.len) {
      const [field, wire] = reader.tag();
      if (field === 3) {
        const any = new BinaryReader(reader.bytes());
        let typeUrl = '';
        let value: Uint8Array | undefined;
        while (any.pos < any.len) {
          const [f, w] = any.tag();
          if (f === 1) {
            typeUrl = any.string();
          } else if (f === 2) {
            value = any.bytes();
          } else {
            any.skip(w);
          }
        }
        if (typeUrl === ERROR_DETAIL_TYPE && value !== undefined) {
          return fromBinary(ErrorDetailSchema, value);
        }
      } else {
        reader.skip(wire);
      }
    }
  } catch {
    // A corrupt trailer must not hide the original failure: fall back to the status code.
  }
  return undefined;
}

/** A UUIDv7 (RFC 9562) for `rgn-request-id`: time-ordered, so server logs sort by arrival. */
export function newRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const ms = Date.now();
  // 48-bit big-endian millisecond timestamp.
  bytes[0] = Math.floor(ms / 2 ** 40) & 0xff;
  bytes[1] = Math.floor(ms / 2 ** 32) & 0xff;
  bytes[2] = (ms >>> 24) & 0xff;
  bytes[3] = (ms >>> 16) & 0xff;
  bytes[4] = (ms >>> 8) & 0xff;
  bytes[5] = ms & 0xff;
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
