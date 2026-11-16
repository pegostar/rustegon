// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pegostar/rustegon/drivers/go/rdoc"
)

// Conformance runner (drivers/conformance/README.md §5–§7), a port of the .NET ConformanceRun so
// that the observations are identical (AC-DRV-003).

// errApplication is the error of runner.throwApplicationError.
var errApplication = errors.New("application error raised by the conformance callback")

// conformanceFailure is a failed expectation (never an observed error).
type conformanceFailure struct{ msg string }

func (f *conformanceFailure) Error() string { return f.msg }

func failf(format string, a ...any) error { return &conformanceFailure{fmt.Sprintf(format, a...)} }

type run struct {
	ctx           context.Context
	client        *Client
	database      string
	defaultColl   string
	substitute    func(string) string
	normalizer    *normalizer
	saved         map[string]any
	opened        []*Client
	txn           *Transaction
	lastErr       error
	observations  []string
	openClient    func(args *ymap) (*Client, error)
	runnerExt     func(name string, args *ymap) (bool, error)
	cursorsOpened []*Cursor
}

func newRun(ctx context.Context, c *Client, database, defaultColl string, substitute func(string) string, testText string) *run {
	return &run{ctx: ctx, client: c, database: database, defaultColl: defaultColl, substitute: substitute,
		normalizer: newNormalizer(testText), saved: map[string]any{}}
}

func (r *run) close() {
	for _, v := range r.saved {
		switch h := v.(type) {
		case *Cursor:
			_ = h.Close(r.ctx)
		case *Transaction:
			_ = h.Close(r.ctx)
		}
	}
	for _, c := range r.opened {
		_ = c.Close(r.ctx)
	}
}

func isHandle(v any) bool {
	switch v.(type) {
	case *Client, *Session, *Cursor, *Transaction:
		return true
	}
	return false
}

func (r *run) runOps(ops []any, topLevel bool) error {
	for i, o := range ops {
		idx := -1
		if topLevel {
			idx = i
		}
		if err := r.runOne(o.(*ymap), idx); err != nil {
			return err
		}
	}
	return nil
}

func (r *run) runOne(op *ymap, index int) error {
	name, target := op.str("name"), op.str("object")
	expect := op.mp("expect")
	result, err := r.dispatch(target, name, op)
	var cf *conformanceFailure
	if errors.As(err, &cf) {
		return err
	}
	label := target + "." + name
	if err != nil {
		r.lastErr = err
		if index >= 0 {
			r.observations = append(r.observations, fmt.Sprintf(`{"error":%s,"op":%d}`, errorJSON(err), index))
		}
		expected := expect.mp("error")
		if expected == nil {
			if index < 0 {
				// Inside a callback or a step: the error belongs to the enclosing operation.
				return err
			}
			return failf("%s failed: %v", label, err)
		}
		return checkError(label, expected, err)
	}
	if index >= 0 {
		observed := "null"
		if isHandle(result) {
			observed = `"<handle>"`
		} else {
			observed = r.normalizer.json(r.volatile(name, result))
		}
		r.observations = append(r.observations, fmt.Sprintf(`{"op":%d,"result":%s}`, index, observed))
	}
	if s := op.str("saveAs"); s != "" {
		r.saved[s] = result
	}
	if expect == nil {
		return nil
	}
	if expect.has("error") {
		return failf("%s succeeded but an error was expected", label)
	}
	if expect.has("result") {
		mode := matchMode{subset: op.str("match") == "subset", ordered: op.get("ordered") != false, fieldOrder: op.get("fieldOrder") == true}
		if why := r.matcher().result(expect.get("result"), result, mode); why != "" {
			return failf("%s: %s", label, why)
		}
	}
	return nil
}

func (r *run) volatile(name string, v any) any {
	if name == "causalityToken" {
		if _, ok := v.(string); ok {
			return "<volatile>"
		}
	}
	if name == "listDatabaseNames" {
		if arr, ok := v.([]any); ok {
			own := []any{}
			for _, n := range arr {
				if s, ok := n.(string); ok && strings.HasPrefix(s, r.database) {
					own = append(own, "<database>"+s[len(r.database):])
				}
			}
			return own
		}
	}
	return v
}

// classID is the errors-map.yaml id of an error, or Argument / InvalidState.
func classID(err error) string {
	var e *Error
	switch {
	case errors.Is(err, errApplication):
		return "ApplicationError"
	case errors.As(err, &e):
		return e.Class.String()
	case errors.Is(err, ErrArgument):
		return "Argument"
	case errors.Is(err, ErrClosed):
		return "InvalidState"
	}
	return fmt.Sprintf("%T", err)
}

func errorJSON(err error) string {
	var e *Error
	switch {
	case errors.Is(err, errApplication):
		return `{"applicationError":true}`
	case errors.As(err, &e):
		return fmt.Sprintf(`{"code":%d,"exception":"%s","retryable":%t}`, e.Code, e.Class.String(), e.Retryable)
	}
	return fmt.Sprintf(`{"exception":"%s"}`, classID(err))
}

var classByID = func() map[string]ErrorClass {
	m := map[string]ErrorClass{}
	for _, c := range allClasses {
		m[c.String()] = c
	}
	return m
}()

func checkError(label string, expected *ymap, err error) error {
	var e *Error
	isR := errors.As(err, &e)
	require := func(ok bool, what string) error {
		if ok {
			return nil
		}
		return failf("%s: %s; got %v", label, what, err)
	}
	if expected.isTrue("applicationError") {
		return require(errors.Is(err, errApplication), "expected the application's error unchanged")
	}
	if cls := expected.str("exception"); cls != "" {
		var ok bool
		switch cls {
		case "Argument":
			ok = errors.Is(err, ErrArgument)
		case "InvalidState":
			ok = errors.Is(err, ErrClosed)
		default:
			c, known := classByID[cls]
			if !known {
				return failf("unknown exception class id %q", cls)
			}
			ok = errors.Is(err, c)
		}
		if e := require(ok, "expected an instance of "+cls); e != nil {
			return e
		}
	}
	if code, ok := expected.get("code").(int64); ok {
		if e2 := require(isR && int64(e.Code) == code, fmt.Sprintf("expected code %d", code)); e2 != nil {
			return e2
		}
	}
	if n := expected.str("name"); n != "" {
		if e2 := require(isR && e.Name == n, "expected name "+n); e2 != nil {
			return e2
		}
	}
	if b, ok := expected.get("retryable").(bool); ok {
		if e2 := require(isR && e.Retryable == b, fmt.Sprintf("expected retryable %t", b)); e2 != nil {
			return e2
		}
	}
	if b, ok := expected.get("committed").(bool); ok {
		if e2 := require(isR && e.Committed != nil && *e.Committed == b, fmt.Sprintf("expected committed %t", b)); e2 != nil {
			return e2
		}
	}
	return nil
}

// ------------------------------------------------------------------ dispatch

func (r *run) dispatch(target, name string, op *ymap) (any, error) {
	args := op.mp("args")
	if args == nil {
		args = &ymap{vals: map[string]any{}}
	}
	switch target {
	case "runner":
		return nil, r.runner(name, args)
	case "client":
		return r.clientOp(r.client, name, op, args)
	case "database":
		return r.databaseOp(r.client.Database(r.database), name, args)
	case "collection":
		coll, err := r.collName(op)
		if err != nil {
			return nil, err
		}
		return r.collectionOp(r.client.Database(r.database).Collection(coll), name, op, args)
	case "transaction":
		if r.txn == nil {
			return nil, failf("object: transaction outside a callback")
		}
		return r.transactionOp(r.txn, name, op, args)
	}
	switch h := r.saved[target].(type) {
	case *Client:
		return r.clientOp(h, name, op, args)
	case *Transaction:
		return r.transactionOp(h, name, op, args)
	case *Session:
		switch name {
		case "causalityToken":
			if t := h.CausalityToken(); t != "" {
				return t, nil
			}
			return nil, nil
		case "close":
			h.Close()
			return nil, nil
		}
		return nil, failf("unknown session operation %q", name)
	case *Cursor:
		switch name {
		case "next":
			if h.Next(r.ctx) {
				return h.Document(), nil
			}
			return nil, h.Err()
		case "close":
			return nil, h.Close(r.ctx)
		}
		return nil, failf("unknown cursor operation %q", name)
	}
	return nil, failf("unknown object %q", target)
}

func (r *run) collName(op *ymap) (string, error) {
	if c := op.str("collection"); c != "" {
		return c, nil
	}
	if r.defaultColl != "" {
		return r.defaultColl, nil
	}
	return "", failf("no collection")
}

func doc(fields ...any) rdoc.Document {
	d := rdoc.Document{}
	for i := 0; i+1 < len(fields); i += 2 {
		d = append(d, rdoc.Field{Name: fields[i].(string), Value: fields[i+1]})
	}
	return d
}

func strs(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func (r *run) connect(c *Client) (*Client, error) {
	if err := c.connect(r.ctx); err != nil {
		_ = c.Close(r.ctx)
		return nil, err
	}
	r.opened = append(r.opened, c)
	return c, nil
}

func (r *run) clientOp(c *Client, name string, op, args *ymap) (any, error) {
	switch name {
	case "open":
		if r.openClient == nil {
			return nil, failf("client.open is not available here")
		}
		nc, err := r.openClient(args)
		if err != nil {
			return nil, err
		}
		return r.connect(nc)
	case "openFromConnectionString":
		nc, err := New(WithConnectionString(r.substitute(args.str("uri"))))
		if err != nil {
			return nil, err
		}
		return r.connect(nc)
	case "getServerInfo":
		info, err := c.ServerInfo(r.ctx)
		if err != nil {
			return nil, err
		}
		return doc("serverVersion", info.ServerVersion, "protocolVersion", info.ProtocolVersion, "features", strs(info.Features)), nil
	case "listDatabaseNames":
		names, err := c.ListDatabaseNames(r.ctx)
		if err != nil {
			return nil, err
		}
		return strs(names), nil
	case "createDatabase":
		var o []OpOption
		if args.isTrue("ifNotExists") {
			o = append(o, IfNotExists())
		}
		ok, err := c.CreateDatabase(r.ctx, r.substitute(args.str("name")), o...)
		if err != nil {
			return nil, err
		}
		return doc("created", ok), nil
	case "dropDatabase":
		var o []OpOption
		if args.isTrue("ifExists") {
			o = append(o, IfExists())
		}
		ok, err := c.DropDatabase(r.ctx, r.substitute(args.str("name")), o...)
		if err != nil {
			return nil, err
		}
		return doc("dropped", ok), nil
	case "startSession":
		return c.StartSession(CausalConsistency(args.get("causalConsistency") != false))
	case "beginTransaction":
		return c.BeginTransaction(r.ctx, txnOptions(args)...)
	case "withTransaction":
		callback := args.list("callback")
		err := c.WithTransaction(r.ctx, func(_ context.Context, tx *Transaction) error {
			return r.inTransaction(tx, callback)
		}, txnOptions(args)...)
		return nil, err
	case "manualTransaction":
		tx, err := c.BeginTransaction(r.ctx, txnOptions(args)...)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Close(r.ctx) }()
		return nil, r.inTransaction(tx, args.list("steps"))
	case "changePassword":
		return nil, c.ChangePassword(r.ctx, args.str("currentPassword"), args.str("newPassword"))
	case "close":
		return nil, c.Close(r.ctx)
	}
	// README §5: collection operations are also available on a saved client.
	coll, err := r.collName(op)
	if err != nil {
		return nil, err
	}
	return r.collectionOp(c.Database(r.database).Collection(coll), name, op, args)
}

func (r *run) inTransaction(tx *Transaction, ops []any) error {
	outer := r.txn
	r.txn = tx
	defer func() { r.txn = outer }()
	return r.runOps(ops, false)
}

func txnOptions(args *ymap) []OpOption {
	o := args.mp("options")
	if o == nil {
		return nil
	}
	var out []OpOption
	if o.isTrue("readOnly") {
		out = append(out, ReadOnly())
	}
	switch o.str("isolation") {
	case "serializable":
		out = append(out, Isolation(Serializable))
	case "snapshot":
		out = append(out, Isolation(Snapshot))
	case "read_committed":
		out = append(out, Isolation(ReadCommitted))
	}
	if ms, ok := o.get("maxRetryTimeMs").(int64); ok {
		out = append(out, MaxRetryTime(time.Duration(ms)*time.Millisecond))
	}
	return out
}

func (r *run) transactionOp(tx *Transaction, name string, op, args *ymap) (any, error) {
	switch name {
	case "query":
		cur, err := tx.Query(r.ctx, args.str("rgql"), r.params(args), batchOpt(args)...)
		return r.drainCursor(cur, err)
	case "commit":
		return nil, tx.Commit(r.ctx)
	case "rollback":
		return nil, tx.Rollback(r.ctx)
	case "close":
		return nil, tx.Close(r.ctx)
	case "resolve":
		// Manual mode resolves through the transaction (the .NET/Java exception-attached
		// resolver calls the same Status, PD-190).
		out, err := tx.Resolve(r.ctx)
		if err != nil {
			return nil, err
		}
		return string(out), nil
	}
	coll, err := r.collName(op)
	if err != nil {
		return nil, err
	}
	return r.collectionOp(tx.Collection(coll), name, op, args)
}

func (r *run) drainCursor(cur *Cursor, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(r.ctx) }()
	rows := []any{}
	for cur.Next(r.ctx) {
		rows = append(rows, cur.Document())
	}
	if cur.Err() != nil {
		return nil, cur.Err()
	}
	return rows, nil
}

func batchOpt(args *ymap) []OpOption {
	if b, ok := args.get("batchSize").(int64); ok {
		return []OpOption{BatchSize(int(b))}
	}
	return nil
}

func (r *run) params(args *ymap) rdoc.Document {
	if p := args.mp("params"); p != nil {
		return r.document(p)
	}
	return nil
}

func validatorOf(v *ymap) Validator {
	out := Validator{JSONSchema: toJSON(v.get("jsonSchema"))}
	switch v.str("level") {
	case "off":
		out.Level = ValidationOff
	case "strict":
		out.Level = ValidationStrict
	case "moderate":
		out.Level = ValidationModerate
	}
	switch v.str("action") {
	case "error":
		out.Action = ValidationError
	case "warn":
		out.Action = ValidationWarn
	}
	return out
}

func (r *run) databaseOp(db *Database, name string, args *ymap) (any, error) {
	switch name {
	case "query":
		cur, err := db.Query(r.ctx, args.str("rgql"), r.params(args), batchOpt(args)...)
		return r.drainCursor(cur, err)
	case "createCollection":
		var o []OpOption
		if args.isTrue("ifNotExists") {
			o = append(o, IfNotExists())
		}
		if v := args.mp("validator"); v != nil {
			o = append(o, WithValidator(validatorOf(v)))
		}
		ok, err := db.CreateCollection(r.ctx, args.str("name"), o...)
		if err != nil {
			return nil, err
		}
		return doc("created", ok), nil
	case "dropCollection":
		var o []OpOption
		if args.isTrue("ifExists") {
			o = append(o, IfExists())
		}
		ok, err := db.DropCollection(r.ctx, args.str("name"), o...)
		if err != nil {
			return nil, err
		}
		return doc("dropped", ok), nil
	case "listCollectionNames":
		names, err := db.ListCollectionNames(r.ctx)
		if err != nil {
			return nil, err
		}
		return strs(names), nil
	}
	return nil, failf("unknown database operation %q", name)
}

func counts(u UpdateResult) rdoc.Document {
	d := doc("matchedCount", u.MatchedCount, "modifiedCount", u.ModifiedCount)
	if u.UpsertedID != nil {
		d = append(d, rdoc.Field{Name: "upsertedId", Value: u.UpsertedID})
	}
	return d
}

func (r *run) collectionOp(c *Collection, name string, op, args *ymap) (any, error) {
	var o []OpOption
	if s := op.str("session"); s != "" {
		sess, _ := r.saved[s].(*Session)
		o = append(o, InSession(sess))
	}
	opts := args.mp("options")
	if rev, ok := opts.get("ifRev").(string); ok {
		v, _ := r.value(rev).(string)
		o = append(o, IfRev(v))
	}
	switch name {
	case "insertOne":
		res, err := c.InsertOne(r.ctx, r.document(args.get("document")), o...)
		if err != nil {
			return nil, err
		}
		return doc("insertedId", res.InsertedID), nil
	case "insertMany":
		var docs []rdoc.Document
		for _, d := range args.list("documents") {
			docs = append(docs, r.document(d))
		}
		res, err := c.InsertMany(r.ctx, docs, o...)
		if err != nil {
			return nil, err
		}
		return doc("insertedIds", res.InsertedIDs), nil
	case "findById":
		d, found, err := c.FindByID(r.ctx, r.value(args.get("id")), o...)
		if err != nil || !found {
			return nil, err
		}
		return d, nil
	case "find":
		f, err := r.filter(args.get("filter"))
		if err != nil {
			return nil, err
		}
		q := c.Find(f, o...)
		if s := args.list("sort"); s != nil {
			q.Sort(sortOf(s))
		}
		if n, ok := args.get("limit").(int64); ok {
			q.Limit(n)
		}
		if n, ok := args.get("skip").(int64); ok {
			q.Skip(n)
		}
		if p := args.mp("projection"); p != nil {
			q.Project(projectionOf(p))
		}
		if n, ok := args.get("batchSize").(int64); ok {
			q.BatchSize(int(n))
		}
		switch op.str("then") {
		case "first":
			d, found, err := q.First(r.ctx)
			if err != nil || !found {
				return nil, err
			}
			return d, nil
		case "cursor":
			return q.Cursor(r.ctx)
		}
		docs, err := q.All(r.ctx)
		if err != nil {
			return nil, err
		}
		out := []any{}
		for _, d := range docs {
			out = append(out, d)
		}
		return out, nil
	case "updateOne", "updateMany":
		f, err := r.filter(args.get("filter"))
		if err != nil {
			return nil, err
		}
		u, err := r.updateOf(args.list("update"))
		if err != nil {
			return nil, err
		}
		var res UpdateResult
		if name == "updateOne" {
			res, err = c.UpdateOne(r.ctx, f, u, o...)
		} else {
			res, err = c.UpdateMany(r.ctx, f, u, o...)
		}
		if err != nil {
			return nil, err
		}
		return counts(res), nil
	case "replaceOne":
		f, err := r.filter(args.get("filter"))
		if err != nil {
			return nil, err
		}
		if opts.isTrue("upsert") {
			o = append(o, Upsert())
		}
		res, err := c.ReplaceOne(r.ctx, f, r.document(args.get("replacement")), o...)
		if err != nil {
			return nil, err
		}
		return counts(res), nil
	case "deleteOne", "deleteMany":
		f, err := r.filter(args.get("filter"))
		if err != nil {
			return nil, err
		}
		var res DeleteResult
		if name == "deleteOne" {
			res, err = c.DeleteOne(r.ctx, f, o...)
		} else {
			res, err = c.DeleteMany(r.ctx, f, o...)
		}
		if err != nil {
			return nil, err
		}
		return doc("deletedCount", res.DeletedCount), nil
	case "bulkWrite":
		var ops []BulkOperation
		for _, b := range args.list("operations") {
			bo, err := r.bulkOf(b.(*ymap))
			if err != nil {
				return nil, err
			}
			ops = append(ops, bo)
		}
		if args.get("ordered") == false {
			o = append(o, Unordered())
		}
		res, err := c.BulkWrite(r.ctx, ops, o...)
		if err != nil {
			return nil, err
		}
		errs := []any{}
		for _, e := range res.Errors {
			errs = append(errs, doc("index", int64(e.Index), "code", int64(e.Err.Code)))
		}
		return doc("insertedCount", res.InsertedCount, "matchedCount", res.MatchedCount, "modifiedCount", res.ModifiedCount,
			"deletedCount", res.DeletedCount, "errors", errs), nil
	case "createIndex":
		if args.isTrue("unique") {
			o = append(o, Unique())
		}
		d, err := c.CreateIndex(r.ctx, args.str("name"), keysOf(args.list("keys")), o...)
		if err != nil {
			return nil, err
		}
		return doc("name", d.Name, "state", string(d.State)), nil
	case "dropIndex":
		if args.isTrue("ifExists") {
			o = append(o, IfExists())
		}
		ok, err := c.DropIndex(r.ctx, args.str("name"), o...)
		if err != nil {
			return nil, err
		}
		return doc("dropped", ok), nil
	case "listIndexes":
		idx, err := c.ListIndexes(r.ctx)
		if err != nil {
			return nil, err
		}
		out := []any{}
		for _, i := range idx {
			ks := []any{}
			for _, k := range i.Keys {
				ks = append(ks, doc("path", k.Path, "descending", k.Descending))
			}
			out = append(out, doc("name", i.Name, "keys", ks, "unique", i.Unique, "state", string(i.State)))
		}
		return out, nil
	}
	return nil, failf("unknown collection operation %q", name)
}

func (r *run) runner(name string, args *ymap) error {
	switch name {
	case "sleep":
		ms, _ := args.get("ms").(int64)
		return sleepCtx(r.ctx, time.Duration(ms)*time.Millisecond)
	case "throwApplicationError":
		return errApplication
	case "assertLastErrorHasTraceId":
		var e *Error
		if !errors.As(r.lastErr, &e) || e.TraceID == "" {
			return failf("the last error has no trace id")
		}
		return nil
	}
	if r.runnerExt != nil {
		ok, err := r.runnerExt(name, args)
		if err != nil {
			return failf("runner %s: %v", name, err)
		}
		if ok {
			return nil
		}
	}
	return failf("unknown runner operation %q", name)
}

// ------------------------------------------------------------------ values and DSL

func (r *run) resolveString(s string) any {
	if strings.HasPrefix(s, "$$ref:") {
		return r.resolveRef(s)
	}
	return r.substitute(s)
}

func (r *run) resolveRef(ref string) any {
	parts := strings.Split(strings.TrimPrefix(ref, "$$ref:"), ".")
	v, ok := r.saved[parts[0]]
	if !ok || isHandle(v) {
		return missing{}
	}
	for _, p := range parts[1:] {
		d, ok := v.(rdoc.Document)
		if !ok {
			return missing{}
		}
		if v, ok = d.Get(p); !ok {
			return missing{}
		}
	}
	return v
}

// missing stands for an absent value (never equal to anything).
type missing struct{}

func (r *run) value(v any) any { return toValue(v, r.resolveString) }

func (r *run) document(v any) rdoc.Document {
	m, _ := v.(*ymap)
	if m == nil {
		return nil
	}
	return toDocument(m, r.resolveString)
}

func (r *run) bulkOf(m *ymap) (BulkOperation, error) {
	kind, a := m.single()
	args := a.(*ymap)
	rev := ""
	if s, ok := args.get("ifRev").(string); ok {
		rev, _ = r.value(s).(string)
	}
	switch kind {
	case "insert":
		return BulkInsert(r.document(args.get("document"))), nil
	case "replace":
		return BulkReplace(r.value(args.get("id")), r.document(args.get("document")), rev), nil
	case "update":
		u, err := r.updateOf(args.list("update"))
		return BulkUpdate(r.value(args.get("id")), u, rev), err
	case "upsert":
		return BulkUpsert(r.document(args.get("document"))), nil
	case "delete":
		return BulkDelete(r.value(args.get("id")), rev), nil
	}
	return BulkOperation{}, failf("unknown bulk operation %q", kind)
}

func (r *run) filter(v any) (Filter, error) { return dslFilter(v, r.value) }

func (r *run) updateOf(ops []any) (Update, error) { return dslUpdate(ops, r.value) }

func dslFilter(v any, value func(any) any) (Filter, error) {
	m, ok := v.(*ymap)
	if !ok {
		return Filter{}, failf("filter must be a mapping")
	}
	if len(m.keys) == 0 {
		return EmptyFilter(), nil
	}
	op, a := m.single()
	l, _ := a.([]any)
	p := func() string { s, _ := l[0].(string); return s }
	vals := func() []any {
		var out []any
		for _, e := range l[1].([]any) {
			out = append(out, value(e))
		}
		return out
	}
	sub := func(x any) Filter { f, _ := dslFilter(x, value); return f }
	switch op {
	case "eq":
		return Eq(p(), value(l[1])), nil
	case "ne":
		return Ne(p(), value(l[1])), nil
	case "gt":
		return Gt(p(), value(l[1])), nil
	case "gte":
		return Gte(p(), value(l[1])), nil
	case "lt":
		return Lt(p(), value(l[1])), nil
	case "lte":
		return Lte(p(), value(l[1])), nil
	case "in":
		return In(p(), vals()...), nil
	case "nin":
		return Nin(p(), vals()...), nil
	case "exists":
		return Exists(p(), l[1].(bool)), nil
	case "isNull":
		return IsNull(a.(string)), nil
	case "contains":
		return Contains(p(), value(l[1])), nil
	case "containsAny":
		return ContainsAny(p(), vals()...), nil
	case "containsAll":
		return ContainsAll(p(), vals()...), nil
	case "elemMatch":
		return ElemMatch(p(), sub(l[1])), nil
	case "like":
		return Like(p(), l[1].(string)), nil
	case "regex":
		return Regex(p(), l[1].(string)), nil
	case "and", "or":
		var fs []Filter
		for _, x := range l {
			fs = append(fs, sub(x))
		}
		if op == "and" {
			return And(fs...), nil
		}
		return Or(fs...), nil
	case "not":
		return Not(sub(a)), nil
	case "id":
		return ID(value(a)), nil
	}
	return Filter{}, failf("unknown filter operator %q", op)
}

func dslUpdate(ops []any, value func(any) any) (Update, error) {
	if len(ops) == 0 {
		return Update{}, failf("empty update")
	}
	var u Update
	for _, item := range ops {
		op, a := item.(*ymap).single()
		l, _ := a.([]any)
		p := func() string { s, _ := l[0].(string); return s }
		switch op {
		case "set":
			u = u.Set(p(), value(l[1]))
		case "unset":
			u = u.Unset(a.(string))
		case "inc":
			u = u.Inc(p(), value(l[1]))
		case "mul":
			u = u.Mul(p(), value(l[1]))
		case "min":
			u = u.Min(p(), value(l[1]))
		case "max":
			u = u.Max(p(), value(l[1]))
		case "push":
			u = u.Push(p(), value(l[1]))
		case "addToSet":
			u = u.AddToSet(p(), value(l[1]))
		case "pull":
			u = u.Pull(p(), value(l[1]))
		case "pop":
			if l[1].(string) == "first" {
				u = u.PopFirst(p())
			} else {
				u = u.PopLast(p())
			}
		case "rename":
			u = u.Rename(p(), l[1].(string))
		case "currentDate":
			u = u.CurrentDate(a.(string))
		default:
			return Update{}, failf("unknown update operator %q", op)
		}
	}
	return u, nil
}

func sortOf(keys []any) Sort {
	var s Sort
	for i, k := range keys {
		path := k.(string)
		desc := strings.HasPrefix(path, "-")
		path = strings.TrimPrefix(path, "-")
		switch {
		case i == 0 && desc:
			s = Desc(path)
		case i == 0:
			s = Asc(path)
		case desc:
			s = s.ThenDesc(path)
		default:
			s = s.ThenAsc(path)
		}
	}
	return s
}

func projectionOf(p *ymap) Projection {
	var paths []string
	if p.has("include") {
		for _, x := range p.list("include") {
			paths = append(paths, x.(string))
		}
		return Include(paths...)
	}
	for _, x := range p.list("exclude") {
		paths = append(paths, x.(string))
	}
	return Exclude(paths...)
}

func keysOf(keys []any) IndexKeys {
	var s Sort
	for i, k := range keys {
		m := k.(*ymap)
		path, desc := m.str("path"), m.isTrue("descending")
		switch {
		case i == 0 && desc:
			s = Desc(path)
		case i == 0:
			s = Asc(path)
		case desc:
			s = s.ThenDesc(path)
		default:
			s = s.ThenAsc(path)
		}
	}
	return s
}

// ------------------------------------------------------------------ matching

type matchMode struct{ subset, ordered, fieldOrder bool }

type matcher struct {
	substitute func(string) string
	resolveRef func(string) any
}

func (r *run) matcher() matcher { return matcher{r.substitute, r.resolveRef} }

func (m matcher) result(expected, actual any, mode matchMode) string {
	if list, ok := expected.([]any); ok && !mode.ordered {
		items, ok := actual.([]any)
		if !ok {
			return "expected an array, got " + valueJSON(actual)
		}
		if (mode.subset && len(items) < len(list)) || (!mode.subset && len(items) != len(list)) {
			return fmt.Sprintf("expected %d rows, got %d: %s", len(list), len(items), valueJSON(actual))
		}
		left := append([]any(nil), items...)
		for _, e := range list {
			found := -1
			for i, a := range left {
				if m.why(e, a, mode, "") == "" {
					found = i
					break
				}
			}
			if found < 0 {
				return fmt.Sprintf("no row matches %s in %s", toJSON(e), valueJSON(actual))
			}
			left = append(left[:found], left[found+1:]...)
		}
		return ""
	}
	return m.why(expected, actual, mode, "$")
}

func (m matcher) why(e, a any, mode matchMode, at string) string {
	fail := func(what string) string {
		if _, ok := a.(missing); ok {
			return at + ": " + what + " (actual missing)"
		}
		return at + ": " + what + " (actual " + valueJSON(a) + ")"
	}
	switch x := e.(type) {
	case string:
		if x == "$$any" {
			return ""
		}
		if strings.HasPrefix(x, "$$ref:") {
			want := m.resolveRef(x)
			if _, isMissing := want.(missing); !isMissing && rdoc.Equal(a, want, false) {
				return ""
			}
			return fail("expected " + valueJSON(want))
		}
		want := m.substitute(x)
		if s, ok := a.(string); ok && s == want {
			return ""
		}
		return fail(fmt.Sprintf("expected %q", want))
	case nil:
		if a == nil {
			return ""
		}
		return fail("expected null")
	case bool:
		if b, ok := a.(bool); ok && b == x {
			return ""
		}
		return fail(fmt.Sprintf("expected %t", x))
	case int64:
		if n, ok := a.(int64); ok && n == x {
			return ""
		}
		return fail(fmt.Sprintf("expected int64 %d", x))
	case float64:
		if f, ok := a.(float64); ok && (f == x && math.Signbit(f) == math.Signbit(x) || math.IsNaN(f) && math.IsNaN(x)) {
			return ""
		}
		return fail(fmt.Sprintf("expected float64 %v", x))
	case []any:
		arr, ok := a.([]any)
		if !ok || len(arr) != len(x) {
			return fail(fmt.Sprintf("expected an array of %d", len(x)))
		}
		for i := range x {
			if w := m.why(x[i], arr[i], mode, fmt.Sprintf("%s[%d]", at, i)); w != "" {
				return w
			}
		}
		return ""
	case *ymap:
		if len(x.keys) == 1 && x.keys[0] == "$$type" {
			if typeName(a) == x.str("$$type") {
				return ""
			}
			return fail("expected type " + x.str("$$type"))
		}
		if isWrapper(x) {
			want := toValue(x, nil)
			if rdoc.Equal(a, want, false) {
				return ""
			}
			return fail("expected " + valueJSON(want))
		}
		d, ok := a.(rdoc.Document)
		if !ok {
			return fail("expected a document")
		}
		var names []string
		for _, f := range d {
			if !systemFields[f.Name] || x.has(f.Name) {
				names = append(names, f.Name)
			}
		}
		for _, k := range x.keys {
			av, ok := d.Get(k)
			if !ok {
				return fail("missing field '" + k + "'")
			}
			if w := m.why(x.vals[k], av, mode, at+"."+k); w != "" {
				return w
			}
		}
		if !mode.subset && len(names) != len(x.keys) {
			return fail("unexpected fields")
		}
		if mode.fieldOrder && !mode.subset && strings.Join(names, ",") != strings.Join(x.keys, ",") {
			return fail("field order " + strings.Join(names, ",") + " instead of " + strings.Join(x.keys, ","))
		}
		return ""
	}
	return fmt.Sprintf("%s: unsupported expectation %T", at, e)
}

// ------------------------------------------------------------------ normalisation (README §6)

type normalizer struct {
	testText string
	oids     map[string]string
}

func newNormalizer(text string) *normalizer {
	return &normalizer{testText: strings.ToLower(text), oids: map[string]string{}}
}

func (n *normalizer) json(v any) string { return valueJSON(n.normalize(v)) }

func (n *normalizer) normalize(v any) any {
	switch x := v.(type) {
	case rdoc.ObjectID:
		hex := x.Hex()
		if strings.Contains(n.testText, strings.ToLower(hex)) {
			return x
		}
		tok, ok := n.oids[hex]
		if !ok {
			tok = "<oid:" + strconv.Itoa(len(n.oids)+1) + ">"
			n.oids[hex] = tok
		}
		return tok
	case rdoc.DateTime:
		text := valueJSON(x)
		iso := text[strings.IndexByte(text, ':')+2 : len(text)-2]
		if strings.Contains(n.testText, strings.ToLower(iso)) {
			return x
		}
		return "<datetime>"
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = n.normalize(e)
		}
		return out
	case rdoc.Document:
		fields := append(rdoc.Document(nil), x...)
		sort.SliceStable(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		out := rdoc.Document{}
		for _, f := range fields {
			// System fields are always removed from observations (README §6).
			if !systemFields[f.Name] {
				out = append(out, rdoc.Field{Name: f.Name, Value: n.normalize(f.Value)})
			}
		}
		return out
	}
	return v
}
