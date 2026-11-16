// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"iter"
	"time"

	"google.golang.org/grpc"

	pb "github.com/pegostar/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/pegostar/rustegon/drivers/go/rdoc"
)

// Cursor iterates over query results, fetching further batches with GetMore. Use it from one
// goroutine; always Close it (Close kills the server-side cursor when it is not exhausted).
//
//	for cur.Next(ctx) { use(cur.Document()) }
//	if err := cur.Err(); err != nil { … }
type Cursor struct {
	ctx       dataContext
	session   *Session
	batchSize *uint32
	buffer    []*pb.Document
	cursorID  string
	current   rdoc.Document
	err       error
	closed    bool
}

func openCursor(ctx context.Context, d dataContext, req *pb.ExecuteRequest, spec callSpec) (*Cursor, error) {
	if req.Options == nil {
		req.Options = &pb.ExecOptions{}
	}
	// One batch per Execute; the rest comes through GetMore, so a large result is never
	// buffered whole.
	one := uint32(1)
	req.Options.MaxBatches = &one
	c := &Cursor{ctx: d, session: spec.session, batchSize: req.Options.BatchSize}
	batches, err := d.execute(ctx, req, spec)
	if err != nil {
		return nil, err
	}
	for _, b := range batches {
		c.take(b)
	}
	return c, nil
}

func (c *Cursor) take(b *pb.ResultBatch) {
	c.buffer = append(c.buffer, b.GetDocs()...)
	if b.CursorId != nil && b.GetCursorId() != "" {
		c.cursorID = b.GetCursorId()
	}
}

// Next advances to the next document; false at the end or on error (see Err).
func (c *Cursor) Next(ctx context.Context) bool {
	if c.closed {
		c.err = closedError("the cursor is closed")
		return false
	}
	for len(c.buffer) == 0 {
		if c.cursorID == "" || c.err != nil {
			c.current = nil
			return false
		}
		req := &pb.GetMoreRequest{CursorId: c.cursorID, BatchSize: c.batchSize}
		// The cursor is spent whatever happens: a failed GetMore is not retried (R3), and the
		// server closes an exhausted cursor itself.
		c.cursorID = ""
		var r *pb.GetMoreResponse
		err := c.ctx.exec.unary(ctx, callSpec{kind: opNoRetry, session: c.session}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) (err error) {
			r, err = pb.NewQueryServiceClient(cc).GetMore(ctx, req, o...)
			return err
		})
		if err != nil {
			c.err = err
			return false
		}
		c.take(r.GetBatch())
	}
	d, err := decodeDoc(c.buffer[0])
	c.buffer = c.buffer[1:]
	if err != nil {
		c.err = err
		return false
	}
	c.current = d
	return true
}

// Document returns the current document (after Next returned true).
func (c *Cursor) Document() rdoc.Document { return c.current }

// Err returns the error that stopped the iteration, if any.
func (c *Cursor) Err() error { return c.err }

// All iterates the remaining documents; iteration stops at the first error, yielded last.
func (c *Cursor) All(ctx context.Context) iter.Seq2[rdoc.Document, error] {
	return func(yield func(rdoc.Document, error) bool) {
		for c.Next(ctx) {
			if !yield(c.Document(), nil) {
				return
			}
		}
		if c.err != nil {
			yield(nil, c.err)
		}
	}
}

// Close releases the cursor (idempotent); killing the server cursor is best effort.
func (c *Cursor) Close(ctx context.Context) error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.buffer = nil
	id := c.cursorID
	c.cursorID = ""
	if id == "" {
		return nil
	}
	// An unreachable server expires the cursor on its own; a closed client killed it already.
	_ = c.ctx.exec.unary(ctx, callSpec{kind: opNoRetry, timeout: 5 * time.Second}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) error {
		_, err := pb.NewQueryServiceClient(cc).KillCursor(ctx, &pb.KillCursorRequest{CursorId: id}, o...)
		return err
	})
	return nil
}
