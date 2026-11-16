// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"sort"

	"google.golang.org/grpc"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/rustegon/rustegon/drivers/go/rdoc"
)

// dataContext is what a database or collection handle needs: the executor, the database and,
// inside a transaction, the transaction.
type dataContext struct {
	exec     *executor
	database string
	txn      *Transaction
}

func (d dataContext) check() error {
	if d.database == "" {
		return argumentError("no database name and no default database in the settings")
	}
	if d.txn != nil {
		return d.txn.checkActive()
	}
	return nil
}

func (d dataContext) txnID() *string {
	if d.txn == nil {
		return nil
	}
	id := d.txn.id
	return &id
}

// spec: operations inside a transaction are never retried alone (R2); the transaction is the unit.
func (d dataContext) spec(kind opKind, o opOptions) callSpec {
	if d.txn != nil {
		return callSpec{kind: opNoRetry, timeout: o.timeout}
	}
	return callSpec{kind: kind, timeout: o.timeout, session: o.session}
}

func (d dataContext) consistency(o opOptions) (*pb.ReadConsistency, error) {
	if d.txn != nil {
		return nil, nil
	}
	return d.exec.consistency(o.consistency, o.maxStaleness)
}

func (d dataContext) writeOptions(o opOptions) *pb.WriteOptions {
	if d.txn != nil {
		return nil
	}
	return &pb.WriteOptions{WriteConcern: d.exec.concern(o.writeConcern)}
}

func (d dataContext) notTransactional(what string) error {
	if d.txn != nil {
		return argumentError("%s is not transactional; run it on a handle of Client.Database", what)
	}
	return nil
}

// execute runs QueryService.Execute and collects its batches. A stream that delivered a batch
// is not retried (R3).
func (d dataContext) execute(ctx context.Context, req *pb.ExecuteRequest, spec callSpec) ([]*pb.ResultBatch, error) {
	req.TxnId = d.txnID()
	var batches []*pb.ResultBatch
	err := d.exec.run(ctx, spec, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) (bool, error) {
		batches = nil
		stream, err := pb.NewQueryServiceClient(cc).Execute(ctx, req, o...)
		if err != nil {
			return false, err
		}
		msgs, err := drain[pb.ExecuteResponse](stream)
		for _, m := range msgs {
			b := m.GetBatch()
			if b == nil {
				b = &pb.ResultBatch{}
			}
			batches = append(batches, b)
		}
		return len(msgs) > 0, err
	})
	return batches, err
}

// executeWrite runs a statement write and returns docs_affected.
func (d dataContext) executeWrite(ctx context.Context, st *pb.AstStatement, s *paramSink, o opOptions) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	req := &pb.ExecuteRequest{Database: d.database, Query: &pb.ExecuteRequest_Ast{Ast: st}, Params: s.params, Options: &pb.ExecOptions{}}
	if d.txn == nil {
		req.Options.WriteConcern = d.exec.concern(o.writeConcern)
	}
	batches, err := d.execute(ctx, req, d.spec(opWrite, o))
	if err != nil {
		return 0, err
	}
	var n int64
	for _, b := range batches {
		if b.GetStats() != nil {
			n = int64(b.GetStats().GetDocsAffected())
		}
	}
	return n, nil
}

// Database is a handle on one database (cheap; create as many as needed).
type Database struct{ ctx dataContext }

// Name returns the database name.
func (db *Database) Name() string { return db.ctx.database }

// Collection returns a handle on a collection of the database.
func (db *Database) Collection(name string) *Collection {
	return &Collection{ctx: db.ctx, name: name}
}

// Query runs RGQL text with named parameters ($name) and returns a cursor over its rows. RGQL
// text may write, so it is retried as a write (RetryWrites; the request id deduplicates, PD-097).
func (db *Database) Query(ctx context.Context, rgql string, params rdoc.Document, opts ...OpOption) (*Cursor, error) {
	if rgql == "" {
		return nil, argumentError("empty RGQL text")
	}
	if err := db.ctx.check(); err != nil {
		return nil, err
	}
	o := collect(opts)
	cons, err := db.ctx.consistency(o)
	if err != nil {
		return nil, err
	}
	req := &pb.ExecuteRequest{Database: db.ctx.database, Query: &pb.ExecuteRequest_Rgql{Rgql: rgql}, Options: &pb.ExecOptions{Consistency: cons}, Params: map[string]*pb.Value{}}
	for _, p := range params {
		v, err := valueProto(p.Value)
		if err != nil {
			return nil, err
		}
		req.Params[p.Name] = v
	}
	if o.batchSize < 0 {
		return nil, argumentError("BatchSize must be positive")
	}
	if o.batchSize > 0 {
		b := uint32(o.batchSize)
		req.Options.BatchSize = &b
	}
	if db.ctx.txn == nil {
		req.Options.WriteConcern = db.ctx.exec.concern(o.writeConcern)
	}
	return openCursor(ctx, db.ctx, req, db.ctx.spec(opWrite, o))
}

// CreateCollection creates a collection (IfNotExists, WithValidator).
func (db *Database) CreateCollection(ctx context.Context, name string, opts ...OpOption) (bool, error) {
	if name == "" {
		return false, argumentError("empty collection name")
	}
	if err := db.ctx.notTransactional("CreateCollection"); err != nil {
		return false, err
	}
	if err := db.ctx.check(); err != nil {
		return false, err
	}
	o := collect(opts)
	req := &pb.CreateCollectionRequest{Database: db.ctx.database, Name: name, IfNotExists: o.ifNotExists}
	if v := o.validator; v != nil {
		req.Validator = &pb.Validator{DefinitionJson: `{"$jsonSchema":` + v.JSONSchema + `}`}
		switch v.Level {
		case ValidationOff:
			req.Validator.Level = pb.ValidationLevel_VALIDATION_LEVEL_OFF
		case ValidationModerate:
			req.Validator.Level = pb.ValidationLevel_VALIDATION_LEVEL_MODERATE
		case ValidationStrict:
			req.Validator.Level = pb.ValidationLevel_VALIDATION_LEVEL_STRICT
		}
		switch v.Action {
		case ValidationError:
			req.Validator.Action = pb.ValidationAction_VALIDATION_ACTION_ERROR
		case ValidationWarn:
			req.Validator.Action = pb.ValidationAction_VALIDATION_ACTION_WARN
		}
	}
	var r *pb.CreateCollectionResponse
	err := db.ctx.exec.unary(ctx, db.ctx.spec(opNoRetry, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).CreateCollection(ctx, req, co...)
		return err
	})
	return r.GetCreated(), err
}

// DropCollection drops a collection (IfExists).
func (db *Database) DropCollection(ctx context.Context, name string, opts ...OpOption) (bool, error) {
	if name == "" {
		return false, argumentError("empty collection name")
	}
	if err := db.ctx.notTransactional("DropCollection"); err != nil {
		return false, err
	}
	if err := db.ctx.check(); err != nil {
		return false, err
	}
	o := collect(opts)
	req := &pb.DropCollectionRequest{Database: db.ctx.database, Name: name, IfExists: o.ifExists}
	var r *pb.DropCollectionResponse
	err := db.ctx.exec.unary(ctx, db.ctx.spec(opNoRetry, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).DropCollection(ctx, req, co...)
		return err
	})
	return r.GetDropped(), err
}

// ListCollectionNames returns the collection names, sorted.
func (db *Database) ListCollectionNames(ctx context.Context) ([]string, error) {
	if err := db.ctx.notTransactional("ListCollections"); err != nil {
		return nil, err
	}
	if err := db.ctx.check(); err != nil {
		return nil, err
	}
	var r *pb.ListCollectionsResponse
	err := db.ctx.exec.unary(ctx, db.ctx.spec(opRead, opOptions{}), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).ListCollections(ctx, &pb.ListCollectionsRequest{Database: db.ctx.database}, co...)
		return err
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(r.GetCollections()))
	for _, c := range r.GetCollections() {
		names = append(names, c.GetName())
	}
	sort.Strings(names)
	return names, nil
}
