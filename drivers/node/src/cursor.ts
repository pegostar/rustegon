// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

import { create } from '@bufbuild/protobuf';
import { QueryService, ExecOptionsSchema, GetMoreRequestSchema, KillCursorRequestSchema, type ExecuteRequest, type ResultBatch } from './generated/rustegon/v1/query_pb.js';
import type { Document } from './generated/rustegon/v1/common_pb.js';
import type { Context } from './context.ts';
import type { CallSpec } from './transport/executor.ts';
import { decodeDocument } from './codec/index.ts';
import type { DocumentCodec } from './mapping/index.ts';
import { InvalidStateError, RustegonError } from './errors/errors.ts';

/**
 * A server cursor over the results of a find or an RGQL query (model.yaml `Cursor.*`). Iterate
 * it with `for await`, or call `next()`; `close()` (also run when a `for await` loop exits early)
 * kills the server cursor.
 */
export class Cursor<T> implements AsyncIterable<T>, AsyncDisposable {
  private readonly context: Context;
  private readonly codec: DocumentCodec<T>;
  private readonly spec: CallSpec;
  private readonly batchSize: number | undefined;
  private readonly buffer: Document[] = [];
  private cursorId: string | undefined;
  private closed = false;

  private constructor(context: Context, codec: DocumentCodec<T>, spec: CallSpec, batchSize: number | undefined) {
    this.context = context;
    this.codec = codec;
    this.spec = spec;
    this.batchSize = batchSize;
  }

  /** @internal Runs the request (first batch only, `max_batches = 1`) and opens the cursor. */
  static async open<T>(context: Context, codec: DocumentCodec<T>, request: ExecuteRequest, spec: CallSpec): Promise<Cursor<T>> {
    request.options ??= create(ExecOptionsSchema);
    request.options.maxBatches = 1;
    const cursor = new Cursor(context, codec, spec, request.options.batchSize);
    for (const batch of await context.execute(request, spec)) {
      cursor.take(batch);
    }
    return cursor;
  }

  /** The next document, or null at the end. */
  async next(): Promise<T | null> {
    if (this.closed) {
      throw new InvalidStateError('The cursor is closed.');
    }
    while (this.buffer.length === 0) {
      if (this.cursorId === undefined) {
        return null;
      }
      const request = create(GetMoreRequestSchema, { cursorId: this.cursorId });
      if (this.batchSize !== undefined) {
        request.batchSize = this.batchSize;
      }
      // The cursor is spent whatever happens: a failed GetMore is not retried (R3), and the
      // server closes an exhausted cursor itself.
      this.cursorId = undefined;
      const response = await this.context.executor.unary(QueryService.method.getMore, request, {
        kind: 'none',
        session: this.spec.session,
        signal: this.spec.signal,
      });
      if (response.batch !== undefined) {
        this.take(response.batch);
      }
    }
    const doc = this.buffer.shift();
    return doc === undefined ? null : this.codec.decode(decodeDocument(doc.rdoc));
  }

  /** Reads every remaining document and closes the cursor. */
  async toArray(): Promise<T[]> {
    const all: T[] = [];
    try {
      for (let d = await this.next(); d !== null; d = await this.next()) {
        all.push(d);
      }
    } finally {
      await this.close();
    }
    return all;
  }

  /** Closes the cursor (idempotent); kills the server cursor when one is open (best effort). */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.buffer.length = 0;
    const id = this.cursorId;
    this.cursorId = undefined;
    if (id === undefined || this.context.executor.isClosed) {
      return;
    }
    try {
      await this.context.executor.unary(QueryService.method.killCursor, create(KillCursorRequestSchema, { cursorId: id }), { kind: 'none', timeoutMs: 5_000 });
    } catch (e) {
      // Best effort: an unreachable server expires the cursor on its own.
      if (!(e instanceof RustegonError) && !(e instanceof InvalidStateError)) {
        throw e;
      }
    }
  }

  async *[Symbol.asyncIterator](): AsyncIterator<T> {
    try {
      for (let d = await this.next(); d !== null; d = await this.next()) {
        yield d;
      }
    } finally {
      await this.close();
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  private take(batch: ResultBatch): void {
    this.buffer.push(...batch.docs);
    if (batch.cursorId !== undefined && batch.cursorId.length > 0) {
      this.cursorId = batch.cursorId;
    }
  }
}
