// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/pegostar/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/pegostar/rustegon/drivers/go/rdoc"
)

// Collection is a handle on a collection; documents are rdoc.Document values.
type Collection struct {
	ctx  dataContext
	name string
}

// Name returns the collection name.
func (c *Collection) Name() string { return c.name }

// Database returns the database name.
func (c *Collection) Database() string { return c.ctx.database }

func (c *Collection) check() error {
	if c.name == "" {
		return argumentError("empty collection name")
	}
	return c.ctx.check()
}

func encodeDoc(d rdoc.Document) (*pb.Document, error) {
	if d == nil {
		return nil, argumentError("nil document")
	}
	n, err := rdoc.Normalize(d)
	if err != nil {
		return nil, argumentError("invalid document: %v", err)
	}
	b, err := rdoc.EncodeDocument(n.(rdoc.Document))
	if err != nil {
		return nil, codecError(err)
	}
	return &pb.Document{Rdoc: b}, nil
}

// codecError maps a codec error to its catalog code (1001…1004, 1040) as a client error.
func codecError(err error) error {
	if e, ok := err.(*rdoc.Error); ok {
		return newError(e.Code, false, e.Message)
	}
	return argumentError("%v", err)
}

func decodeDoc(d *pb.Document) (rdoc.Document, error) {
	doc, err := rdoc.DecodeDocument(d.GetRdoc())
	if err != nil {
		return nil, codecError(err)
	}
	return doc, nil
}

// InsertOneResult reports the id of the inserted document.
type InsertOneResult struct{ InsertedID any }

// InsertManyResult reports the ids of the inserted documents, in order.
type InsertManyResult struct{ InsertedIDs []any }

// UpdateResult reports the matched and modified documents (statement writes report docs_affected
// as both, conformance README §5) and the id of an upserted document.
type UpdateResult struct {
	MatchedCount  int64
	ModifiedCount int64
	UpsertedID    any
}

// DeleteResult reports the deleted documents.
type DeleteResult struct{ DeletedCount int64 }

// InsertOne inserts a document (the server generates an objectId _id when absent).
func (c *Collection) InsertOne(ctx context.Context, doc rdoc.Document, opts ...OpOption) (InsertOneResult, error) {
	r, err := c.insert(ctx, []rdoc.Document{doc}, opts)
	if err != nil {
		return InsertOneResult{}, err
	}
	return InsertOneResult{InsertedID: r.InsertedIDs[0]}, nil
}

// InsertMany inserts documents atomically in one request.
func (c *Collection) InsertMany(ctx context.Context, docs []rdoc.Document, opts ...OpOption) (InsertManyResult, error) {
	if len(docs) == 0 {
		return InsertManyResult{}, argumentError("InsertMany needs at least one document")
	}
	return c.insert(ctx, docs, opts)
}

func (c *Collection) insert(ctx context.Context, docs []rdoc.Document, opts []OpOption) (InsertManyResult, error) {
	if err := c.check(); err != nil {
		return InsertManyResult{}, err
	}
	o := collect(opts)
	req := &pb.InsertRequest{Database: c.ctx.database, Collection: c.name, Options: c.ctx.writeOptions(o), TxnId: c.ctx.txnID()}
	for _, d := range docs {
		p, err := encodeDoc(d)
		if err != nil {
			return InsertManyResult{}, err
		}
		req.Documents = append(req.Documents, p)
	}
	var r *pb.InsertResponse
	err := c.ctx.exec.unary(ctx, c.ctx.spec(opWrite, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewDocumentServiceClient(cc).Insert(ctx, req, co...)
		return err
	})
	if err != nil {
		return InsertManyResult{}, err
	}
	out := InsertManyResult{InsertedIDs: make([]any, 0, len(r.GetResults()))}
	for _, w := range r.GetResults() {
		id, err := valueOf(w.GetId())
		if err != nil {
			return InsertManyResult{}, codecError(err)
		}
		out.InsertedIDs = append(out.InsertedIDs, id)
	}
	return out, nil
}

// FindByID returns the document with _id = id; found is false when there is none.
func (c *Collection) FindByID(ctx context.Context, id any, opts ...OpOption) (doc rdoc.Document, found bool, err error) {
	if err := c.check(); err != nil {
		return nil, false, err
	}
	o := collect(opts)
	idv, err := valueProto(id)
	if err != nil {
		return nil, false, err
	}
	cons, err := c.ctx.consistency(o)
	if err != nil {
		return nil, false, err
	}
	req := &pb.GetRequest{Database: c.ctx.database, Collection: c.name, Id: idv, Consistency: cons, TxnId: c.ctx.txnID()}
	var r *pb.GetResponse
	err = c.ctx.exec.unary(ctx, c.ctx.spec(opRead, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewDocumentServiceClient(cc).Get(ctx, req, co...)
		return err
	})
	if err != nil || r.GetDocument() == nil {
		return nil, false, err
	}
	doc, err = decodeDoc(r.GetDocument())
	return doc, err == nil, err
}

// Find starts a query; chain Sort/Limit/Skip/Project/BatchSize, then All, First or Cursor.
func (c *Collection) Find(filter Filter, opts ...OpOption) *FindQuery {
	return &FindQuery{coll: c, filter: filter, opts: collect(opts)}
}

// UpdateOne updates the first matching document: by id with DocumentService.Update when the
// filter is exactly ID(v), otherwise UPDATE … WHERE … LIMIT 1 (lowest _id, README §4 rule 4).
func (c *Collection) UpdateOne(ctx context.Context, filter Filter, update Update, opts ...OpOption) (UpdateResult, error) {
	return c.update(ctx, filter, update, true, opts)
}

// UpdateMany updates every matching document.
func (c *Collection) UpdateMany(ctx context.Context, filter Filter, update Update, opts ...OpOption) (UpdateResult, error) {
	return c.update(ctx, filter, update, false, opts)
}

func (c *Collection) update(ctx context.Context, filter Filter, update Update, one bool, opts []OpOption) (UpdateResult, error) {
	if err := c.check(); err != nil {
		return UpdateResult{}, err
	}
	if err := filter.check(); err != nil {
		return UpdateResult{}, err
	}
	o := collect(opts)
	s := newSink()
	if id, ok := filter.idValue(); ok && one {
		ops, err := update.toAST(s)
		if err != nil {
			return UpdateResult{}, err
		}
		if s.err != nil {
			return UpdateResult{}, s.err
		}
		idv, err := valueProto(id)
		if err != nil {
			return UpdateResult{}, err
		}
		req := &pb.UpdateRequest{Database: c.ctx.database, Collection: c.name, Id: idv, Operations: ops, Params: s.params, IfRev: o.ifRev, TxnId: c.ctx.txnID(), Options: c.ctx.writeOptions(o)}
		var r *pb.UpdateResponse
		err = c.ctx.exec.unary(ctx, c.ctx.spec(opWrite, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
			r, err = pb.NewDocumentServiceClient(cc).Update(ctx, req, co...)
			return err
		})
		if err != nil {
			return UpdateResult{}, err
		}
		return UpdateResult{MatchedCount: b2i(r.GetMatched()), ModifiedCount: b2i(r.GetModified())}, nil
	}
	if o.ifRev != nil {
		return UpdateResult{}, argumentError("IfRev applies to ID filters only")
	}
	st, err := updateStatement(c.name, filter, update, one, s)
	if err != nil {
		return UpdateResult{}, err
	}
	n, err := c.ctx.executeWrite(ctx, st, s, o)
	return UpdateResult{MatchedCount: n, ModifiedCount: n}, err
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ReplaceOne replaces the first matching document (Upsert requires an ID filter).
func (c *Collection) ReplaceOne(ctx context.Context, filter Filter, replacement rdoc.Document, opts ...OpOption) (UpdateResult, error) {
	if err := c.check(); err != nil {
		return UpdateResult{}, err
	}
	if err := filter.check(); err != nil {
		return UpdateResult{}, err
	}
	o := collect(opts)
	nd, err := rdoc.Normalize(replacement)
	if err != nil || replacement == nil {
		return UpdateResult{}, argumentError("invalid replacement document")
	}
	doc := nd.(rdoc.Document)
	id, byID := filter.idValue()
	if !byID {
		if o.upsert {
			return UpdateResult{}, argumentError("an upserting ReplaceOne needs an ID filter")
		}
		if o.ifRev != nil {
			return UpdateResult{}, argumentError("IfRev applies to ID filters only")
		}
		s := newSink()
		st, err := updateStatement(c.name, filter, replaceUpdate(doc), true, s)
		if err != nil {
			return UpdateResult{}, err
		}
		n, err := c.ctx.executeWrite(ctx, st, s, o)
		return UpdateResult{MatchedCount: n, ModifiedCount: n}, err
	}
	if o.upsert {
		withID, err := withID(doc, id)
		if err != nil {
			return UpdateResult{}, err
		}
		p, err := encodeDoc(withID)
		if err != nil {
			return UpdateResult{}, err
		}
		req := &pb.UpsertRequest{Database: c.ctx.database, Collection: c.name, Document: p, IfRev: o.ifRev, TxnId: c.ctx.txnID(), Options: c.ctx.writeOptions(o)}
		var r *pb.UpsertResponse
		err = c.ctx.exec.unary(ctx, c.ctx.spec(opWrite, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
			r, err = pb.NewDocumentServiceClient(cc).Upsert(ctx, req, co...)
			return err
		})
		if err != nil {
			return UpdateResult{}, err
		}
		if r.GetInserted() {
			return UpdateResult{UpsertedID: id}, nil
		}
		return UpdateResult{MatchedCount: 1, ModifiedCount: 1}, nil
	}
	p, err := encodeDoc(doc)
	if err != nil {
		return UpdateResult{}, err
	}
	idv, err := valueProto(id)
	if err != nil {
		return UpdateResult{}, err
	}
	req := &pb.ReplaceRequest{Database: c.ctx.database, Collection: c.name, Id: idv, Document: p, IfRev: o.ifRev, TxnId: c.ctx.txnID(), Options: c.ctx.writeOptions(o)}
	var r *pb.ReplaceResponse
	err = c.ctx.exec.unary(ctx, c.ctx.spec(opWrite, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewDocumentServiceClient(cc).Replace(ctx, req, co...)
		return err
	})
	if err != nil {
		return UpdateResult{}, err
	}
	m := b2i(r.GetMatched())
	return UpdateResult{MatchedCount: m, ModifiedCount: m}, nil
}

// withID puts _id first unless the document already has the same _id.
func withID(d rdoc.Document, id any) (rdoc.Document, error) {
	if v, ok := d.Get("_id"); ok {
		if !rdoc.Equal(v, id, true) {
			return nil, argumentError("the replacement's _id differs from the id of the ID filter")
		}
		return d, nil
	}
	return append(rdoc.Document{{Name: "_id", Value: id}}, d...), nil
}

// DeleteOne deletes the first matching document (by id with an ID filter).
func (c *Collection) DeleteOne(ctx context.Context, filter Filter, opts ...OpOption) (DeleteResult, error) {
	return c.delete(ctx, filter, true, opts)
}

// DeleteMany deletes every matching document.
func (c *Collection) DeleteMany(ctx context.Context, filter Filter, opts ...OpOption) (DeleteResult, error) {
	return c.delete(ctx, filter, false, opts)
}

func (c *Collection) delete(ctx context.Context, filter Filter, one bool, opts []OpOption) (DeleteResult, error) {
	if err := c.check(); err != nil {
		return DeleteResult{}, err
	}
	if err := filter.check(); err != nil {
		return DeleteResult{}, err
	}
	o := collect(opts)
	if id, ok := filter.idValue(); ok && one {
		idv, err := valueProto(id)
		if err != nil {
			return DeleteResult{}, err
		}
		req := &pb.DeleteRequest{Database: c.ctx.database, Collection: c.name, Id: idv, IfRev: o.ifRev, TxnId: c.ctx.txnID(), Options: c.ctx.writeOptions(o)}
		var r *pb.DeleteResponse
		err = c.ctx.exec.unary(ctx, c.ctx.spec(opWrite, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
			r, err = pb.NewDocumentServiceClient(cc).Delete(ctx, req, co...)
			return err
		})
		if err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{DeletedCount: b2i(r.GetDeleted())}, nil
	}
	if o.ifRev != nil {
		return DeleteResult{}, argumentError("IfRev applies to ID filters only")
	}
	s := newSink()
	n, err := c.ctx.executeWrite(ctx, deleteStatement(c.name, filter, one, s), s, o)
	return DeleteResult{DeletedCount: n}, err
}

// BulkOperation is one operation of BulkWrite (by id; constructors BulkInsert, BulkReplace, …).
type BulkOperation struct {
	kind   int
	doc    rdoc.Document
	id     any
	update Update
	ifRev  string
}

const (
	bulkInsert = iota
	bulkReplace
	bulkUpdate
	bulkUpsert
	bulkDelete
)

// BulkInsert inserts doc.
func BulkInsert(doc rdoc.Document) BulkOperation { return BulkOperation{kind: bulkInsert, doc: doc} }

// BulkUpsert inserts or replaces doc by its _id.
func BulkUpsert(doc rdoc.Document) BulkOperation { return BulkOperation{kind: bulkUpsert, doc: doc} }

// BulkReplace replaces the document id ("" ifRev = unconditional).
func BulkReplace(id any, doc rdoc.Document, ifRev string) BulkOperation {
	return BulkOperation{kind: bulkReplace, id: id, doc: doc, ifRev: ifRev}
}

// BulkUpdate updates the document id.
func BulkUpdate(id any, update Update, ifRev string) BulkOperation {
	return BulkOperation{kind: bulkUpdate, id: id, update: update, ifRev: ifRev}
}

// BulkDelete deletes the document id.
func BulkDelete(id any, ifRev string) BulkOperation {
	return BulkOperation{kind: bulkDelete, id: id, ifRev: ifRev}
}

// BulkWriteError is the failure of one operation of a bulk write.
type BulkWriteError struct {
	Index int
	Err   *Error
}

// BulkWriteResult counts the effects of a bulk write; per-operation failures are in Errors.
type BulkWriteResult struct {
	InsertedCount, MatchedCount, ModifiedCount, DeletedCount int64
	Errors                                                   []BulkWriteError
}

func optRev(r string) *string {
	if r == "" {
		return nil
	}
	return &r
}

// BulkWrite runs operations in one request (ordered unless Unordered()). Failures of single
// operations are reported in the result; the call fails only when the request itself fails.
func (c *Collection) BulkWrite(ctx context.Context, ops []BulkOperation, opts ...OpOption) (BulkWriteResult, error) {
	if err := c.check(); err != nil {
		return BulkWriteResult{}, err
	}
	if len(ops) == 0 {
		return BulkWriteResult{}, argumentError("a bulk write needs at least one operation")
	}
	o := collect(opts)
	req := &pb.BulkWriteRequest{Database: c.ctx.database, Collection: c.name, Ordered: !o.unordered, Options: c.ctx.writeOptions(o), TxnId: c.ctx.txnID()}
	// One sink: BulkWriteRequest.params is shared by every update, numbered u0, u1, … across them.
	s := newSink()
	for _, op := range ops {
		p := &pb.BulkOperation{}
		var err error
		switch op.kind {
		case bulkInsert, bulkUpsert:
			var d *pb.Document
			if d, err = encodeDoc(op.doc); err == nil {
				if op.kind == bulkInsert {
					p.Op = &pb.BulkOperation_Insert{Insert: &pb.BulkInsert{Document: d}}
				} else {
					p.Op = &pb.BulkOperation_Upsert{Upsert: &pb.BulkUpsert{Document: d}}
				}
			}
		case bulkReplace:
			var d *pb.Document
			var id *pb.Value
			if d, err = encodeDoc(op.doc); err == nil {
				if id, err = valueProto(op.id); err == nil {
					p.Op = &pb.BulkOperation_Replace{Replace: &pb.BulkReplace{Id: id, Document: d, IfRev: optRev(op.ifRev)}}
				}
			}
		case bulkUpdate:
			var id *pb.Value
			var u []*pb.AstUpdateOp
			if id, err = valueProto(op.id); err == nil {
				if u, err = op.update.toAST(s); err == nil {
					p.Op = &pb.BulkOperation_Update{Update: &pb.BulkUpdate{Id: id, Operations: u, IfRev: optRev(op.ifRev)}}
				}
			}
		default:
			var id *pb.Value
			if id, err = valueProto(op.id); err == nil {
				p.Op = &pb.BulkOperation_Delete{Delete: &pb.BulkDelete{Id: id, IfRev: optRev(op.ifRev)}}
			}
		}
		if err != nil {
			return BulkWriteResult{}, err
		}
		req.Operations = append(req.Operations, p)
	}
	if s.err != nil {
		return BulkWriteResult{}, s.err
	}
	req.Params = s.params
	var r *pb.BulkWriteResponse
	err := c.ctx.exec.unary(ctx, c.ctx.spec(opWrite, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewDocumentServiceClient(cc).BulkWrite(ctx, req, co...)
		return err
	})
	if err != nil {
		return BulkWriteResult{}, err
	}
	out := BulkWriteResult{
		InsertedCount: int64(r.GetInserted()), MatchedCount: int64(r.GetMatched()),
		ModifiedCount: int64(r.GetModified()), DeletedCount: int64(r.GetDeleted()), Errors: []BulkWriteError{},
	}
	for _, e := range r.GetErrors() {
		var re *Error
		if e.GetError() != nil {
			re = fromDetail(e.GetError(), e.GetMessage(), nil)
		} else {
			re = fromTransport(codes.Unknown, e.GetMessage(), nil)
		}
		out.Errors = append(out.Errors, BulkWriteError{Index: int(e.GetIndex()), Err: re})
	}
	return out, nil
}

// IndexState is the build state of an index.
type IndexState string

// Index states.
const (
	IndexBuilding IndexState = "building"
	IndexReady    IndexState = "ready"
	IndexFailed   IndexState = "failed"
	IndexHidden   IndexState = "hidden"
)

// IndexDescription describes an index.
type IndexDescription struct {
	Name   string
	Keys   []IndexKey
	Unique bool
	State  IndexState
	Error  string
}

func indexState(s pb.IndexState) IndexState {
	switch s {
	case pb.IndexState_INDEX_STATE_READY:
		return IndexReady
	case pb.IndexState_INDEX_STATE_FAILED:
		return IndexFailed
	case pb.IndexState_INDEX_STATE_HIDDEN:
		return IndexHidden
	}
	return IndexBuilding
}

func describe(d *pb.AstCreateIndex, s pb.IndexState, errText string) IndexDescription {
	out := IndexDescription{Name: d.GetName(), Unique: d.GetIndexType() == pb.AstIndexType_AST_INDEX_TYPE_UNIQUE, State: indexState(s), Error: errText, Keys: []IndexKey{}}
	for _, k := range d.GetKeys() {
		out.Keys = append(out.Keys, IndexKey{Path: pathText(k.GetPath()), Descending: k.GetDescending()})
	}
	return out
}

// CreateIndex creates an index and waits until its build has finished (README §5: createIndex
// returns the final state), polling with a doubling interval capped at 500 ms.
func (c *Collection) CreateIndex(ctx context.Context, name string, keys IndexKeys, opts ...OpOption) (IndexDescription, error) {
	if name == "" {
		return IndexDescription{}, argumentError("empty index name")
	}
	if keys.err != nil || len(keys.keys) == 0 {
		if keys.err != nil {
			return IndexDescription{}, keys.err
		}
		return IndexDescription{}, argumentError("an index needs at least one key")
	}
	if err := c.ctx.notTransactional("CreateIndex"); err != nil {
		return IndexDescription{}, err
	}
	if err := c.check(); err != nil {
		return IndexDescription{}, err
	}
	o := collect(opts)
	def := &pb.AstCreateIndex{IndexType: pb.AstIndexType_AST_INDEX_TYPE_STANDARD, Name: name, On: &pb.AstQualifiedName{Name: c.name}}
	if o.unique {
		def.IndexType = pb.AstIndexType_AST_INDEX_TYPE_UNIQUE
	}
	for _, k := range keys.keys {
		p, _ := astPath(k.Path)
		def.Keys = append(def.Keys, &pb.AstIndexKey{Path: p, Descending: k.Descending})
	}
	req := &pb.CreateIndexRequest{Database: c.ctx.database, Definition: def}
	var r *pb.CreateIndexResponse
	err := c.ctx.exec.unary(ctx, c.ctx.spec(opNoRetry, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).CreateIndex(ctx, req, co...)
		return err
	})
	if err != nil {
		return IndexDescription{}, err
	}
	state := pb.IndexState_INDEX_STATE_BUILDING
	if r.GetIndex() != nil {
		state = r.GetIndex().GetState()
	}
	delay := 10 * time.Millisecond
	for state == pb.IndexState_INDEX_STATE_BUILDING {
		if err := sleepCtx(ctx, delay); err != nil {
			return IndexDescription{}, err
		}
		delay = min(500*time.Millisecond, delay*2)
		preq := &pb.IndexBuildProgressRequest{Database: c.ctx.database, Collection: c.name, Name: name}
		var p *pb.IndexBuildProgressResponse
		err := c.ctx.exec.unary(ctx, c.ctx.spec(opRead, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
			p, err = pb.NewSchemaServiceClient(cc).IndexBuildProgress(ctx, preq, co...)
			return err
		})
		if err != nil {
			return IndexDescription{}, err
		}
		state = p.GetState()
	}
	d := def
	if r.GetIndex().GetDefinition() != nil {
		d = r.GetIndex().GetDefinition()
	}
	return describe(d, state, r.GetIndex().GetError()), nil
}

// DropIndex drops an index (IfExists).
func (c *Collection) DropIndex(ctx context.Context, name string, opts ...OpOption) (bool, error) {
	if name == "" {
		return false, argumentError("empty index name")
	}
	if err := c.ctx.notTransactional("DropIndex"); err != nil {
		return false, err
	}
	if err := c.check(); err != nil {
		return false, err
	}
	o := collect(opts)
	req := &pb.DropIndexRequest{Database: c.ctx.database, Collection: c.name, Name: name, IfExists: o.ifExists}
	var r *pb.DropIndexResponse
	err := c.ctx.exec.unary(ctx, c.ctx.spec(opNoRetry, o), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).DropIndex(ctx, req, co...)
		return err
	})
	return r.GetDropped(), err
}

// ListIndexes lists the indexes, sorted by name.
func (c *Collection) ListIndexes(ctx context.Context) ([]IndexDescription, error) {
	if err := c.ctx.notTransactional("ListIndexes"); err != nil {
		return nil, err
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	req := &pb.ListIndexesRequest{Database: c.ctx.database, Collection: c.name}
	var r *pb.ListIndexesResponse
	err := c.ctx.exec.unary(ctx, c.ctx.spec(opRead, opOptions{}), func(ctx context.Context, cc grpc.ClientConnInterface, co ...grpc.CallOption) (err error) {
		r, err = pb.NewSchemaServiceClient(cc).ListIndexes(ctx, req, co...)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]IndexDescription, 0, len(r.GetIndexes()))
	for _, i := range r.GetIndexes() {
		out = append(out, describe(i.GetDefinition(), i.GetState(), i.GetError()))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// FindQuery is a find being built; it is not safe for concurrent modification.
type FindQuery struct {
	coll       *Collection
	filter     Filter
	opts       opOptions
	sort       *Sort
	projection *Projection
	limit      *int64
	skip       *int64
	err        error
}

// Sort orders the results.
func (q *FindQuery) Sort(s Sort) *FindQuery {
	q.sort = &s
	if s.err != nil {
		q.err = s.err
	}
	return q
}

// Limit returns at most n documents.
func (q *FindQuery) Limit(n int64) *FindQuery {
	if n < 0 {
		q.err = argumentError("Limit must not be negative")
	}
	q.limit = &n
	return q
}

// Skip skips the first n documents.
func (q *FindQuery) Skip(n int64) *FindQuery {
	if n < 0 {
		q.err = argumentError("Skip must not be negative")
	}
	q.skip = &n
	return q
}

// Project selects the fields of the results.
func (q *FindQuery) Project(p Projection) *FindQuery {
	q.projection = &p
	if p.err != nil {
		q.err = p.err
	}
	return q
}

// BatchSize sets the documents per batch.
func (q *FindQuery) BatchSize(n int) *FindQuery {
	if n <= 0 {
		q.err = argumentError("BatchSize must be positive")
	}
	q.opts.batchSize = n
	return q
}

func (q *FindQuery) request(limit *int64) (*pb.ExecuteRequest, error) {
	if q.err != nil {
		return nil, q.err
	}
	if err := q.filter.check(); err != nil {
		return nil, err
	}
	if err := q.coll.check(); err != nil {
		return nil, err
	}
	cons, err := q.coll.ctx.consistency(q.opts)
	if err != nil {
		return nil, err
	}
	s := newSink()
	st := findStatement(q.coll.name, q.filter, q.sort, q.projection, limit, q.skip, s)
	if s.err != nil {
		return nil, s.err
	}
	req := &pb.ExecuteRequest{Database: q.coll.ctx.database, Query: &pb.ExecuteRequest_Ast{Ast: st}, Params: s.params, Options: &pb.ExecOptions{Consistency: cons}}
	if q.opts.batchSize > 0 {
		b := uint32(q.opts.batchSize)
		req.Options.BatchSize = &b
	}
	return req, nil
}

// Cursor runs the query and returns a cursor over the results.
func (q *FindQuery) Cursor(ctx context.Context) (*Cursor, error) {
	req, err := q.request(q.limit)
	if err != nil {
		return nil, err
	}
	return openCursor(ctx, q.coll.ctx, req, q.coll.ctx.spec(opRead, q.opts))
}

// All runs the query and returns every result.
func (q *FindQuery) All(ctx context.Context) ([]rdoc.Document, error) {
	cur, err := q.Cursor(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(context.WithoutCancel(ctx)) }()
	var out []rdoc.Document
	for cur.Next(ctx) {
		out = append(out, cur.Document())
	}
	return out, cur.Err()
}

// First returns the first result; found is false when there is none.
func (q *FindQuery) First(ctx context.Context) (doc rdoc.Document, found bool, err error) {
	one := int64(1)
	if q.limit != nil && *q.limit < 1 {
		one = *q.limit
	}
	req, err := q.request(&one)
	if err != nil {
		return nil, false, err
	}
	cur, err := openCursor(ctx, q.coll.ctx, req, q.coll.ctx.spec(opRead, q.opts))
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = cur.Close(context.WithoutCancel(ctx)) }()
	if cur.Next(ctx) {
		return cur.Document(), true, nil
	}
	return nil, false, cur.Err()
}
