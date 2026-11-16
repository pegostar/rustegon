// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"strconv"
	"strings"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/rustegon/rustegon/drivers/go/rdoc"
)

// The builders produce the structured AST of query_ast.proto, never RGQL text (PD-070); the
// exact output is pinned by drivers/conformance/ast/*.json. Every value becomes a named
// parameter (f0, f1, … for filters, u0, u1, … for updates) in depth-first, left-to-right order.

// paramSink numbers the parameters of one request.
type paramSink struct {
	filters, updates int
	params           map[string]*pb.Value
	// err is the first value that failed to encode; builders check values when they are made,
	// so only a document passed unchecked (a replacement) can set it.
	err error
}

func newSink() *paramSink { return &paramSink{params: map[string]*pb.Value{}} }

func (s *paramSink) add(prefix string, n *int, v any) *pb.AstExpr {
	name := prefix + strconv.Itoa(*n)
	*n++
	b, err := rdoc.EncodeValue(v)
	if err != nil && s.err == nil {
		s.err = argumentError("invalid value: %v", err)
	}
	s.params[name] = &pb.Value{RdocValue: b}
	return &pb.AstExpr{Kind: &pb.AstExpr_Param{Param: &pb.AstParam{Name: name}}}
}

func (s *paramSink) filter(v any) *pb.AstExpr { return s.add("f", &s.filters, v) }
func (s *paramSink) update(v any) *pb.AstExpr { return s.add("u", &s.updates, v) }

// checkedValue normalizes a builder value and verifies it encodes; errors surface when the
// operation runs (builders return values, not errors, to stay composable).
func checkedValue(v any) (any, error) {
	n, err := rdoc.Normalize(v)
	if err != nil {
		return nil, argumentError("invalid value: %v", err)
	}
	if _, err := rdoc.EncodeValue(n); err != nil {
		return nil, argumentError("invalid value: %v", err)
	}
	return n, nil
}

func valueProto(v any) (*pb.Value, error) {
	n, err := checkedValue(v)
	if err != nil {
		return nil, err
	}
	b, err := rdoc.EncodeValue(n)
	if err != nil {
		return nil, argumentError("invalid value: %v", err)
	}
	return &pb.Value{RdocValue: b}, nil
}

func valueOf(p *pb.Value) (any, error) {
	if p == nil {
		return nil, nil
	}
	return rdoc.DecodeValue(p.GetRdocValue())
}

// astPath splits a dotted path; an all-digit segment after the first is an array position.
func astPath(path string) (*pb.AstPath, error) {
	if path == "" {
		return nil, argumentError("empty path")
	}
	out := &pb.AstPath{}
	for i, p := range strings.Split(path, ".") {
		if p == "" {
			return nil, argumentError("the path %q has an empty segment", path)
		}
		if i > 0 && isDigits(p) {
			if n, err := strconv.ParseUint(p, 10, 32); err == nil {
				out.Segments = append(out.Segments, &pb.AstSegment{Segment: &pb.AstSegment_Position{Position: uint32(n)}})
				continue
			}
		}
		out.Segments = append(out.Segments, &pb.AstSegment{Segment: &pb.AstSegment_Field{Field: p}})
	}
	return out, nil
}

func pathText(p *pb.AstPath) string {
	parts := make([]string, 0, len(p.GetSegments()))
	for _, s := range p.GetSegments() {
		if pos, ok := s.GetSegment().(*pb.AstSegment_Position); ok {
			parts = append(parts, strconv.FormatUint(uint64(pos.Position), 10))
		} else {
			parts = append(parts, s.GetField())
		}
	}
	return strings.Join(parts, ".")
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func pathExpr(p *pb.AstPath) *pb.AstExpr {
	return &pb.AstExpr{Kind: &pb.AstExpr_Path{Path: &pb.AstPathExpr{Path: p}}}
}

func intLit(v int64) *pb.AstExpr {
	return &pb.AstExpr{Kind: &pb.AstExpr_Literal{Literal: &pb.AstLiteral{Value: &pb.AstLiteral_IntValue{IntValue: v}}}}
}

func allowFullScanWrite() *pb.AstOptionItem {
	return &pb.AstOptionItem{Name: "allow_full_scan_write", Value: &pb.AstExpr{Kind: &pb.AstExpr_Literal{Literal: &pb.AstLiteral{Value: &pb.AstLiteral_BoolValue{BoolValue: true}}}}}
}

// ---------------------------------------------------------------- filters

type filterKind int

const (
	fEmpty filterKind = iota
	fID
	fBinary
	fExists
	fIsNull
	fElemMatch
	fAnd
	fOr
	fNot
)

// Filter is a query condition. Construct it with Eq, And, ID, … ; EmptyFilter matches every
// document. An invalid argument is reported when the operation using the filter runs.
type Filter struct {
	kind     filterKind
	path     *pb.AstPath
	op       pb.AstBinaryOp
	value    any
	flag     bool
	children []Filter
	err      error
}

// EmptyFilter matches every document.
func EmptyFilter() Filter { return Filter{kind: fEmpty} }

// ID matches the document with _id = id; UpdateOne/ReplaceOne/DeleteOne with it use the by-id RPCs.
func ID(id any) Filter {
	f := binary("_id", pb.AstBinaryOp_AST_BINARY_OP_EQ, id)
	f.kind = fID
	return f
}

// Eq matches path = value.
func Eq(path string, value any) Filter { return binary(path, pb.AstBinaryOp_AST_BINARY_OP_EQ, value) }

// Ne matches path != value.
func Ne(path string, value any) Filter { return binary(path, pb.AstBinaryOp_AST_BINARY_OP_NE, value) }

// Gt matches path > value.
func Gt(path string, value any) Filter { return binary(path, pb.AstBinaryOp_AST_BINARY_OP_GT, value) }

// Gte matches path >= value.
func Gte(path string, value any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_GE, value)
}

// Lt matches path < value.
func Lt(path string, value any) Filter { return binary(path, pb.AstBinaryOp_AST_BINARY_OP_LT, value) }

// Lte matches path <= value.
func Lte(path string, value any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_LE, value)
}

// In matches path IN values.
func In(path string, values ...any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_IN, list(values))
}

// Nin matches path NOT IN values.
func Nin(path string, values ...any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_NOT_IN, list(values))
}

// Contains matches arrays at path containing value.
func Contains(path string, value any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_CONTAINS, value)
}

// ContainsAny matches arrays at path containing any of values.
func ContainsAny(path string, values ...any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_CONTAINS_ANY, list(values))
}

// ContainsAll matches arrays at path containing all of values.
func ContainsAll(path string, values ...any) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_CONTAINS_ALL, list(values))
}

// Like matches path LIKE pattern.
func Like(path, pattern string) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_LIKE, pattern)
}

// Regex matches path MATCHES re.
func Regex(path, re string) Filter {
	return binary(path, pb.AstBinaryOp_AST_BINARY_OP_MATCHES, re)
}

// Exists matches documents where path is present (exists) or missing (!exists).
func Exists(path string, exists bool) Filter {
	p, err := astPath(path)
	return Filter{kind: fExists, path: p, flag: exists, err: err}
}

// IsNull matches documents where path is null or missing.
func IsNull(path string) Filter {
	p, err := astPath(path)
	return Filter{kind: fIsNull, path: p, err: err}
}

// ElemMatch matches arrays at path with an element satisfying filter.
func ElemMatch(path string, filter Filter) Filter {
	p, err := astPath(path)
	if err == nil && filter.kind == fEmpty {
		err = argumentError("ElemMatch needs a non-empty element filter")
	}
	return Filter{kind: fElemMatch, path: p, children: []Filter{filter}, err: err}
}

// And matches documents satisfying every filter (empty filters are dropped, nested And flattened).
func And(filters ...Filter) Filter { return nary(fAnd, filters) }

// Or matches documents satisfying any filter.
func Or(filters ...Filter) Filter { return nary(fOr, filters) }

// Not negates a non-empty filter.
func Not(filter Filter) Filter {
	var err error
	if filter.kind == fEmpty {
		err = argumentError("Not of the empty filter matches nothing; use a real condition")
	}
	return Filter{kind: fNot, children: []Filter{filter}, err: err}
}

func binary(path string, op pb.AstBinaryOp, value any) Filter {
	p, err := astPath(path)
	var v any
	if err == nil {
		v, err = checkedValue(value)
	}
	return Filter{kind: fBinary, path: p, op: op, value: v, err: err}
}

func list(values []any) []any {
	if values == nil {
		return []any{}
	}
	return values
}

func nary(kind filterKind, filters []Filter) Filter {
	flat := make([]Filter, 0, len(filters))
	for _, f := range filters {
		if f.kind == fEmpty && f.err == nil {
			continue
		}
		// The server accepts only canonical ASTs: an `and` inside an `and` must be flat already
		// (PD-070 rule 2; otherwise RGN-1010).
		if f.kind == kind {
			flat = append(flat, f.children...)
		} else {
			flat = append(flat, f)
		}
	}
	switch len(flat) {
	case 0:
		return EmptyFilter()
	case 1:
		return flat[0]
	}
	return Filter{kind: kind, children: flat}
}

func (f Filter) check() error {
	if f.err != nil {
		return f.err
	}
	for _, c := range f.children {
		if err := c.check(); err != nil {
			return err
		}
	}
	return nil
}

func (f Filter) idValue() (any, bool) {
	if f.kind == fID {
		return f.value, true
	}
	return nil, false
}

func (f Filter) toAST(s *paramSink) *pb.AstExpr {
	switch f.kind {
	case fEmpty:
		return nil
	case fID, fBinary:
		return &pb.AstExpr{Kind: &pb.AstExpr_Binary{Binary: &pb.AstBinary{Op: f.op, Left: pathExpr(f.path), Right: s.filter(f.value)}}}
	case fExists:
		// exists = true is `IS NOT MISSING`: the canonical AST of a negated IS test.
		return &pb.AstExpr{Kind: &pb.AstExpr_Is{Is: &pb.AstIs{Expr: pathExpr(f.path), Test: pb.AstIsTest_AST_IS_TEST_MISSING, Negated: f.flag}}}
	case fIsNull:
		return &pb.AstExpr{Kind: &pb.AstExpr_Is{Is: &pb.AstIs{Expr: pathExpr(f.path), Test: pb.AstIsTest_AST_IS_TEST_NULL}}}
	case fElemMatch:
		return &pb.AstExpr{Kind: &pb.AstExpr_ElemMatch{ElemMatch: &pb.AstElemMatch{Path: f.path, Predicate: f.children[0].toAST(s)}}}
	case fNot:
		return &pb.AstExpr{Kind: &pb.AstExpr_Not{Not: &pb.AstUnary{Expr: f.children[0].toAST(s)}}}
	}
	n := &pb.AstNary{}
	for _, c := range f.children {
		n.Args = append(n.Args, c.toAST(s))
	}
	if f.kind == fAnd {
		return &pb.AstExpr{Kind: &pb.AstExpr_And{And: n}}
	}
	return &pb.AstExpr{Kind: &pb.AstExpr_Or{Or: n}}
}

// ---------------------------------------------------------------- updates

type updateOp func(*paramSink) *pb.AstUpdateOp

// Update is an ordered list of update operators; chain them (Set("a", 1).Inc("n", 1)).
type Update struct {
	ops []updateOp
	err error
}

func (u Update) then(op updateOp, err error) Update {
	ops := append(append([]updateOp(nil), u.ops...), op)
	if u.err != nil {
		err = u.err
	}
	return Update{ops: ops, err: err}
}

func pathValueOp(u Update, path string, value any, make func(*pb.AstPath, *pb.AstExpr) *pb.AstUpdateOp) Update {
	p, err := astPath(path)
	var v any
	if err == nil {
		v, err = checkedValue(value)
	}
	return u.then(func(s *paramSink) *pb.AstUpdateOp { return make(p, s.update(v)) }, err)
}

func pathOnly(u Update, path string, make func(*pb.AstPath) *pb.AstUpdateOp) Update {
	p, err := astPath(path)
	return u.then(func(*paramSink) *pb.AstUpdateOp { return make(p) }, err)
}

// Set sets path to value.
func Set(path string, value any) Update { return Update{}.Set(path, value) }

// Unset removes path.
func Unset(path string) Update { return Update{}.Unset(path) }

// Inc adds amount to the number at path.
func Inc(path string, amount any) Update { return Update{}.Inc(path, amount) }

// Mul multiplies the number at path by factor.
func Mul(path string, factor any) Update { return Update{}.Mul(path, factor) }

// Min sets path to value when value is smaller.
func Min(path string, value any) Update { return Update{}.Min(path, value) }

// Max sets path to value when value is larger.
func Max(path string, value any) Update { return Update{}.Max(path, value) }

// Push appends value to the array at path.
func Push(path string, value any) Update { return Update{}.Push(path, value) }

// AddToSet appends value to the array at path unless present.
func AddToSet(path string, value any) Update { return Update{}.AddToSet(path, value) }

// Pull removes the elements equal to value from the array at path.
func Pull(path string, value any) Update { return Update{}.Pull(path, value) }

// PopFirst removes the first element of the array at path.
func PopFirst(path string) Update { return Update{}.PopFirst(path) }

// PopLast removes the last element of the array at path.
func PopLast(path string) Update { return Update{}.PopLast(path) }

// Rename moves the field at from to to.
func Rename(from, to string) Update { return Update{}.Rename(from, to) }

// CurrentDate sets path to the server's current datetime.
func CurrentDate(path string) Update { return Update{}.CurrentDate(path) }

// Set chains a Set.
func (u Update) Set(path string, value any) Update {
	return pathValueOp(u, path, value, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Set{Set: &pb.AstSetStage{Items: []*pb.AstSetItem{{Path: p, Value: v}}}}}
	})
}

// Unset chains an Unset.
func (u Update) Unset(path string) Update {
	return pathOnly(u, path, func(p *pb.AstPath) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Unset{Unset: &pb.AstUnsetStage{Paths: []*pb.AstPath{p}}}}
	})
}

// Inc chains an Inc.
func (u Update) Inc(path string, amount any) Update {
	return pathValueOp(u, path, amount, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Inc{Inc: &pb.AstPathBy{Path: p, By: v}}}
	})
}

// Mul chains a Mul.
func (u Update) Mul(path string, factor any) Update {
	return pathValueOp(u, path, factor, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Mul{Mul: &pb.AstPathBy{Path: p, By: v}}}
	})
}

// Min chains a Min.
func (u Update) Min(path string, value any) Update {
	return pathValueOp(u, path, value, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Min{Min: &pb.AstPathValue{Path: p, Value: v}}}
	})
}

// Max chains a Max.
func (u Update) Max(path string, value any) Update {
	return pathValueOp(u, path, value, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Max{Max: &pb.AstPathValue{Path: p, Value: v}}}
	})
}

// Push chains a Push.
func (u Update) Push(path string, value any) Update {
	return pathValueOp(u, path, value, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Push{Push: &pb.AstPushOp{Path: p, Value: v}}}
	})
}

// AddToSet chains an AddToSet.
func (u Update) AddToSet(path string, value any) Update {
	return pathValueOp(u, path, value, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_AddToSet{AddToSet: &pb.AstPathValue{Path: p, Value: v}}}
	})
}

// Pull chains a Pull: PULL p WHERE <last field of p> = value (conformance README §4).
func (u Update) Pull(path string, value any) Update {
	return pathValueOp(u, path, value, func(p *pb.AstPath, v *pb.AstExpr) *pb.AstUpdateOp {
		last := p.GetSegments()[len(p.GetSegments())-1].GetField()
		elem := &pb.AstPath{Segments: []*pb.AstSegment{{Segment: &pb.AstSegment_Field{Field: last}}}}
		where := &pb.AstExpr{Kind: &pb.AstExpr_Binary{Binary: &pb.AstBinary{Op: pb.AstBinaryOp_AST_BINARY_OP_EQ, Left: pathExpr(elem), Right: v}}}
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Pull{Pull: &pb.AstPullOp{Path: p, Where: where}}}
	})
}

// PopFirst chains a PopFirst.
func (u Update) PopFirst(path string) Update { return u.pop(path, pb.AstPopEnd_AST_POP_END_FIRST) }

// PopLast chains a PopLast.
func (u Update) PopLast(path string) Update { return u.pop(path, pb.AstPopEnd_AST_POP_END_LAST) }

func (u Update) pop(path string, end pb.AstPopEnd) Update {
	return pathOnly(u, path, func(p *pb.AstPath) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Pop{Pop: &pb.AstPopOp{Path: p, End: end}}}
	})
}

// Rename chains a Rename.
func (u Update) Rename(from, to string) Update {
	f, err := astPath(from)
	t, err2 := astPath(to)
	if err == nil {
		err = err2
	}
	return u.then(func(*paramSink) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Rename{Rename: &pb.AstRenameOp{From: f, To: t}}}
	}, err)
}

// CurrentDate chains a CurrentDate.
func (u Update) CurrentDate(path string) Update {
	return pathOnly(u, path, func(p *pb.AstPath) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_CurrentDate{CurrentDate: &pb.AstPathOnly{Path: p}}}
	})
}

// Combine concatenates updates in order.
func Combine(updates ...Update) Update {
	var out Update
	for _, u := range updates {
		out.ops = append(out.ops, u.ops...)
		if out.err == nil {
			out.err = u.err
		}
	}
	return out
}

func replaceUpdate(d rdoc.Document) Update {
	return Update{ops: []updateOp{func(s *paramSink) *pb.AstUpdateOp {
		return &pb.AstUpdateOp{Kind: &pb.AstUpdateOp_Replace{Replace: &pb.AstReplaceOp{Value: s.update(d)}}}
	}}}
}

func (u Update) toAST(s *paramSink) ([]*pb.AstUpdateOp, error) {
	if u.err != nil {
		return nil, u.err
	}
	if len(u.ops) == 0 {
		return nil, argumentError("an update needs at least one operator")
	}
	out := make([]*pb.AstUpdateOp, len(u.ops))
	for i, op := range u.ops {
		out[i] = op(s)
	}
	return out, nil
}

// ---------------------------------------------------------------- sort, projection, keys

// Sort is an ordered list of sort keys.
type Sort struct {
	keys []IndexKey
	err  error
}

// IndexKey is one key of a sort or an index.
type IndexKey struct {
	Path       string
	Descending bool
}

func keys(prev []IndexKey, prevErr error, paths []string, desc bool) ([]IndexKey, error) {
	out := append([]IndexKey(nil), prev...)
	err := prevErr
	if len(paths) == 0 && err == nil {
		err = argumentError("at least one path is required")
	}
	for _, p := range paths {
		if _, e := astPath(p); e != nil && err == nil {
			err = e
		}
		out = append(out, IndexKey{Path: p, Descending: desc})
	}
	return out, err
}

// Asc sorts by paths ascending.
func Asc(paths ...string) Sort { k, err := keys(nil, nil, paths, false); return Sort{k, err} }

// Desc sorts by paths descending.
func Desc(paths ...string) Sort { k, err := keys(nil, nil, paths, true); return Sort{k, err} }

// ThenAsc appends ascending keys.
func (s Sort) ThenAsc(paths ...string) Sort {
	k, err := keys(s.keys, s.err, paths, false)
	return Sort{k, err}
}

// ThenDesc appends descending keys.
func (s Sort) ThenDesc(paths ...string) Sort {
	k, err := keys(s.keys, s.err, paths, true)
	return Sort{k, err}
}

func (s Sort) toAST() []*pb.AstOrderItem {
	out := make([]*pb.AstOrderItem, 0, len(s.keys))
	for _, k := range s.keys {
		p, _ := astPath(k.Path)
		out = append(out, &pb.AstOrderItem{Expr: pathExpr(p), Descending: k.Descending})
	}
	return out
}

// IndexKeys are the keys of an index.
type IndexKeys = Sort

// Projection selects (Include) or removes (Exclude) fields of the results.
type Projection struct {
	paths   []string
	exclude bool
	err     error
}

// Include returns only paths (and _id as the server decides).
func Include(paths ...string) Projection { return projection(paths, false) }

// Exclude returns everything but paths.
func Exclude(paths ...string) Projection { return projection(paths, true) }

func projection(paths []string, exclude bool) Projection {
	var err error
	if len(paths) == 0 {
		err = argumentError("a projection needs at least one path")
	}
	for _, p := range paths {
		if _, e := astPath(p); e != nil && err == nil {
			err = e
		}
	}
	return Projection{paths: append([]string(nil), paths...), exclude: exclude, err: err}
}

func (p Projection) toAST() *pb.AstSelect {
	items := &pb.AstSelectItems{}
	for _, s := range p.paths {
		ap, _ := astPath(s)
		if p.exclude {
			items.Items = append(items.Items, &pb.AstProjection{Kind: &pb.AstProjection_Exclude{Exclude: &pb.AstPathProjection{Path: ap}}})
		} else {
			items.Items = append(items.Items, &pb.AstProjection{Kind: &pb.AstProjection_Expr{Expr: &pb.AstExprProjection{Expr: pathExpr(ap)}}})
		}
	}
	return &pb.AstSelect{Kind: &pb.AstSelect_Items{Items: items}}
}

// ---------------------------------------------------------------- statements

func collectionSource(c string) *pb.AstFromClause {
	return &pb.AstFromClause{Source: &pb.AstSource{Kind: &pb.AstSource_Collection{Collection: &pb.AstQualifiedName{Name: c}}}}
}

// findStatement = FROM `c` [WHERE f] [SELECT projection] [ORDER BY sort] [LIMIT n] [OFFSET m].
func findStatement(c string, f Filter, sort *Sort, proj *Projection, limit, skip *int64, s *paramSink) *pb.AstStatement {
	q := &pb.AstQuery{From: collectionSource(c), Where: f.toAST(s)}
	if proj != nil {
		q.Select = proj.toAST()
	}
	if sort != nil {
		q.OrderBy = sort.toAST()
	}
	if limit != nil {
		q.Limit = intLit(*limit)
	}
	if skip != nil {
		q.Offset = intLit(*skip)
	}
	return &pb.AstStatement{Kind: &pb.AstStatement_Query{Query: q}}
}

// updateStatement: filter parameters first (f*), then update parameters (u*).
func updateStatement(c string, f Filter, u Update, one bool, s *paramSink) (*pb.AstStatement, error) {
	where := f.toAST(s)
	ops, err := u.toAST(s)
	if err != nil {
		return nil, err
	}
	st := &pb.AstUpdate{Target: &pb.AstQualifiedName{Name: c}, Where: where, Ops: ops}
	if one {
		st.Limit = intLit(1)
	}
	if f.kind == fEmpty {
		// Without WHERE the server refuses a write unless asked explicitly (RGN-1013); the empty
		// filter is that explicit request (README §4 rule 5).
		st.Options = append(st.Options, allowFullScanWrite())
	}
	return &pb.AstStatement{Kind: &pb.AstStatement_Update{Update: st}}, nil
}

func deleteStatement(c string, f Filter, one bool, s *paramSink) *pb.AstStatement {
	d := &pb.AstDelete{Target: &pb.AstQualifiedName{Name: c}, Where: f.toAST(s)}
	if one {
		d.Limit = intLit(1)
	}
	if f.kind == fEmpty {
		d.Options = append(d.Options, allowFullScanWrite())
	}
	return &pb.AstStatement{Kind: &pb.AstStatement_Delete{Delete: d}}
}
