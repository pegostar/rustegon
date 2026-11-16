// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	pb "github.com/pegostar/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/pegostar/rustegon/drivers/go/rdoc"
)

// TransactionOutcome is the result of resolving a commit whose outcome was unknown (RGN-2006).
type TransactionOutcome string

// Transaction outcomes.
const (
	OutcomeCommitted TransactionOutcome = "committed"
	OutcomeAborted   TransactionOutcome = "aborted"
	OutcomeUnknown   TransactionOutcome = "unknown"
)

const (
	txActive int32 = iota
	txCommitted
	txUnknown
	txEnded
)

// Transaction is an interactive transaction (transactions.md). Operations on its handles carry
// its id and are never retried alone; the transaction is the unit of retry (WithTransaction).
type Transaction struct {
	exec      *executor
	defaultDB string
	id        string
	state     atomic.Int32
	closed    atomic.Bool
	stopBeat  context.CancelFunc
	beatDone  sync.WaitGroup
}

// ID returns the server transaction id.
func (t *Transaction) ID() string { return t.id }

func (t *Transaction) checkActive() error {
	if t.closed.Load() {
		return closedError("the transaction is closed")
	}
	return nil
}

func beginTransaction(ctx context.Context, x *executor, defaultDB string, o opOptions) (*Transaction, error) {
	req := &pb.BeginRequest{ReadOnly: o.readOnly, WriteConcern: x.concern(o.writeConcern)}
	switch o.isolation {
	case Serializable:
		req.Isolation = pb.AstIsolation_AST_ISOLATION_SERIALIZABLE
	case Snapshot:
		req.Isolation = pb.AstIsolation_AST_ISOLATION_SNAPSHOT
	case ReadCommitted:
		req.Isolation = pb.AstIsolation_AST_ISOLATION_READ_COMMITTED
	}
	// Follower and bounded-staleness reads exist only for read-only transactions (the server
	// refuses them otherwise, consistency.md): the consistency is sent for those only.
	if req.ReadOnly {
		c, err := x.consistency(o.consistency, o.maxStaleness)
		if err != nil {
			return nil, err
		}
		req.Consistency = c
	}
	var r *pb.BeginResponse
	err := x.unary(ctx, callSpec{kind: opNoRetry}, func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewTransactionServiceClient(cc).Begin(ctx, req, co...)
		return err
	})
	if err != nil {
		return nil, err
	}
	t := &Transaction{exec: x, defaultDB: defaultDB, id: r.GetTxnId()}
	if iv := time.Duration(r.GetHeartbeatIntervalMs()) * time.Millisecond; iv > 0 {
		hctx, cancel := context.WithCancel(context.Background())
		t.stopBeat = cancel
		t.beatDone.Add(1)
		go t.heartbeat(hctx, iv)
	}
	return t, nil
}

// heartbeat keeps the transaction alive while the application works; failures are ignored (the
// next operation reports a lost transaction).
func (t *Transaction) heartbeat(ctx context.Context, every time.Duration) {
	defer t.beatDone.Done()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = t.call(ctx, func(ctx context.Context, c pb.TransactionServiceClient, o ...grpc.CallOption) error {
				_, err := c.Heartbeat(ctx, &pb.HeartbeatRequest{TxnId: t.id}, o...)
				return err
			})
		}
	}
}

func (t *Transaction) stopHeartbeat() {
	if t.stopBeat != nil {
		t.stopBeat()
	}
}

// leave moves an active transaction to state and stops the heartbeat.
func (t *Transaction) leave(state int32) {
	if t.state.CompareAndSwap(txActive, state) {
		t.stopHeartbeat()
	}
}

func (t *Transaction) call(ctx context.Context, f func(context.Context, pb.TransactionServiceClient, ...grpc.CallOption) error) error {
	return t.exec.unary(ctx, callSpec{kind: opNoRetry}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) error {
		return f(ctx, pb.NewTransactionServiceClient(cc), o...)
	})
}

// Database returns a handle on a database inside the transaction.
func (t *Transaction) Database(name string) *Database {
	return &Database{ctx: dataContext{exec: t.exec, database: name, txn: t}}
}

// Collection returns a handle on "db.collection", or on a collection of the default database.
func (t *Transaction) Collection(name string) *Collection {
	if db, coll, ok := strings.Cut(name, "."); ok && db != "" {
		return t.Database(db).Collection(coll)
	}
	return t.Database(t.defaultDB).Collection(name)
}

// Query runs RGQL text in the default database inside the transaction.
func (t *Transaction) Query(ctx context.Context, rgql string, params rdoc.Document, opts ...OpOption) (*Cursor, error) {
	return t.Database(t.defaultDB).Query(ctx, rgql, params, opts...)
}

// Commit commits. A commit whose reply was lost after it was sent fails with
// ClassCommitOutcomeUnknown (RGN-2006): resolve it with Resolve, never by re-running blindly.
func (t *Transaction) Commit(ctx context.Context) error {
	if err := t.checkActive(); err != nil {
		return err
	}
	err := t.call(ctx, func(ctx context.Context, c pb.TransactionServiceClient, o ...grpc.CallOption) error {
		_, err := c.Commit(ctx, &pb.CommitRequest{TxnId: t.id}, o...)
		return err
	})
	if err == nil {
		t.leave(txCommitted)
		return nil
	}
	var e *Error
	if errors.As(err, &e) && e.Class == ClassCommitOutcomeUnknown {
		t.leave(txUnknown)
		return err
	}
	if reachedServer(err) {
		// A commit lost after it was sent (connection reset, node killed, deadline without an
		// answer) may have committed: never report it as retryable, or WithTransaction would run
		// the callback again (PD-119, PD-122).
		u := newError(CodeCommitOutcomeUnknown, false, "the commit reply was lost ("+err.Error()+"); the outcome is unknown")
		if e != nil {
			u.TraceID = e.TraceID
		}
		u.cause = err
		t.leave(txUnknown)
		return u
	}
	return err
}

// Rollback aborts the transaction.
func (t *Transaction) Rollback(ctx context.Context) error {
	if err := t.checkActive(); err != nil {
		return err
	}
	// Ended before the call: a failed rollback is not repeated by Close; the server aborts an
	// abandoned transaction on its own anyway.
	t.leave(txEnded)
	return t.call(ctx, func(ctx context.Context, c pb.TransactionServiceClient, o ...grpc.CallOption) error {
		_, err := c.Rollback(ctx, &pb.RollbackRequest{TxnId: t.id}, o...)
		return err
	})
}

// Resolve asks the server whether the transaction committed (after RGN-2006).
func (t *Transaction) Resolve(ctx context.Context) (TransactionOutcome, error) {
	var r *pb.StatusResponse
	err := t.call(ctx, func(ctx context.Context, c pb.TransactionServiceClient, o ...grpc.CallOption) (err error) {
		r, err = c.Status(ctx, &pb.StatusRequest{TxnId: t.id}, o...)
		return err
	})
	if err != nil {
		return OutcomeUnknown, err
	}
	switch r.GetState() {
	case pb.TransactionState_TRANSACTION_STATE_COMMITTED:
		return OutcomeCommitted, nil
	case pb.TransactionState_TRANSACTION_STATE_ABORTED:
		return OutcomeAborted, nil
	}
	// ACTIVE, COMMITTING and states unknown to this driver: never "aborted" by guess.
	return OutcomeUnknown, nil
}

func (t *Transaction) rollbackBestEffort() {
	if t.state.Load() != txActive {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.exec.settings.OperationTimeout)
	defer cancel()
	_ = t.Rollback(ctx)
}

// Close rolls back an active transaction (best effort) and releases it; idempotent.
func (t *Transaction) Close(ctx context.Context) error {
	if t.closed.Load() {
		return nil
	}
	if t.state.Load() == txActive {
		t.leave(txEnded)
		_ = t.call(context.WithoutCancel(ctx), func(ctx context.Context, c pb.TransactionServiceClient, o ...grpc.CallOption) error {
			_, err := c.Rollback(ctx, &pb.RollbackRequest{TxnId: t.id}, o...)
			return err
		})
	}
	t.closed.Store(true)
	t.stopHeartbeat()
	t.beatDone.Wait()
	return nil
}

// BeginTransaction starts a transaction in manual mode; Close it (it rolls back if not committed).
func (c *Client) BeginTransaction(ctx context.Context, opts ...OpOption) (*Transaction, error) {
	if err := c.exec.checkOpen(); err != nil {
		return nil, err
	}
	return beginTransaction(ctx, c.exec, c.settings.DefaultDatabase, collect(opts))
}

// WithTransaction runs fn in a transaction and commits it, retrying per transactions.md §5:
// retryable errors of fn or of the commit roll back, back off and re-run fn until MaxRetryTime
// (default 2 minutes); an unknown commit outcome (RGN-2006) is resolved with Status and never
// re-run blindly; any other error rolls back and is returned unchanged.
func (c *Client) WithTransaction(ctx context.Context, fn func(ctx context.Context, tx *Transaction) error, opts ...OpOption) error {
	if fn == nil {
		return argumentError("nil transaction callback")
	}
	if err := c.exec.checkOpen(); err != nil {
		return err
	}
	o := collect(opts)
	maxTime := 2 * time.Minute
	if o.maxRetryTime != nil {
		maxTime = *o.maxRetryTime
	}
	deadline := time.Now().Add(maxTime)
	attempt := 0
	for {
		retryable, err := c.attempt(ctx, fn, o, deadline)
		if retryable == nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return retryable
		}
		attempt++
		if err := sleepCtx(ctx, clamp(backoffDelay(attempt), deadline)); err != nil {
			return err
		}
	}
}

// attempt runs one transaction; it returns a retryable error to re-run, or (nil, final result).
func (c *Client) attempt(ctx context.Context, fn func(context.Context, *Transaction) error, o opOptions, deadline time.Time) (*Error, error) {
	tx, err := beginTransaction(ctx, c.exec, c.settings.DefaultDatabase, o)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Close(ctx) }()
	if err := fn(ctx, tx); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Retryable && e.Class != ClassCommitOutcomeUnknown && time.Now().Before(deadline) {
			tx.rollbackBestEffort()
			return e, nil
		}
		// Non-retryable errors, errors at the deadline and the callback's own errors: roll back
		// and return unchanged.
		tx.rollbackBestEffort()
		return nil, err
	}
	err = tx.Commit(ctx)
	if err == nil {
		return nil, nil
	}
	var e *Error
	if !errors.As(err, &e) {
		tx.rollbackBestEffort()
		return nil, err
	}
	if e.Class == ClassCommitOutcomeUnknown {
		committed, rerr := resolve(ctx, tx, e, deadline)
		if rerr != nil {
			return nil, rerr
		}
		if committed {
			return nil, nil
		}
		// Resolved as ABORTED: it definitely did not commit, so it is handled like a retryable error.
		a := newError(CodeTransactionAborted, true, "the commit outcome was unknown and the transaction status reports it aborted")
		f := false
		a.Committed, a.TraceID, a.cause = &f, e.TraceID, e
		return a, nil
	}
	tx.rollbackBestEffort()
	if e.Retryable && time.Now().Before(deadline) {
		return e, nil
	}
	return nil, err
}

// resolve polls Status until COMMITTED/ABORTED or the deadline; a failed Status call says
// nothing about the commit and must never lead to a re-run (the transaction could apply twice).
func resolve(ctx context.Context, tx *Transaction, unknown *Error, deadline time.Time) (bool, error) {
	attempt := 0
	for {
		outcome, err := tx.Resolve(ctx)
		if err != nil && ctx.Err() != nil {
			return false, err
		}
		switch outcome {
		case OutcomeCommitted:
			return true, nil
		case OutcomeAborted:
			return false, nil
		}
		if !time.Now().Before(deadline) {
			return false, unknown
		}
		attempt++
		if err := sleepCtx(ctx, clamp(backoffDelay(attempt), deadline)); err != nil {
			return false, err
		}
	}
}

func clamp(d time.Duration, deadline time.Time) time.Duration {
	left := time.Until(deadline)
	if left <= 0 {
		return 0
	}
	return min(d, left)
}
