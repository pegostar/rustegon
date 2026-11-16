// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/rustegon/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/rustegon/rustegon/drivers/go/internal/scram"
	"github.com/rustegon/rustegon/drivers/go/rdoc"
)

// runnerChecks implements the runner operations of README §7 that need no server.
func runnerChecks(name string, args *ymap) (bool, error) {
	file := args.str("file")
	switch name {
	case "checkErrorMapping":
		return true, checkErrorMapping(file)
	case "checkValueVectors", "checkDocumentVectors", "checkInvalidVectors":
		dir := filepath.Join(conformanceDir(), filepath.Dir(file))
		return true, rdoc.CheckVectors(dir, filepath.Base(file))
	case "checkAstVectors":
		return true, checkAstVectors(file)
	case "checkConnectionStrings":
		return true, checkConnectionStrings(file)
	case "runRetryScenarios":
		return true, runRetryScenarios(file, "")
	case "checkScramVectors":
		return true, scram.CheckVectors(filepath.Join(conformanceDir(), file))
	}
	return false, nil
}

// ---------------------------------------------------------------- error mapping (TC-DRV-GO-004)

func checkErrorMapping(file string) error {
	text, err := os.ReadFile(filepath.Join(conformanceDir(), file))
	if err != nil {
		return err
	}
	var t struct {
		Codes []struct {
			Code      int
			Name      string
			Exception struct{ ID string }
		}
		Transport []struct {
			Code      int
			Grpc      string
			Retryable bool
			Exception struct{ ID string }
		}
		Unknown struct{ ID string }
	}
	if err := json.Unmarshal(text, &t); err != nil {
		return err
	}
	for _, c := range t.Codes {
		e := fromDetail(&pb.ErrorDetail{Code: uint32(c.Code), Name: c.Name, Retryable: true}, "x", nil)
		if e.Class.String() != c.Exception.ID || e.Code != c.Code || !e.Retryable {
			return fmt.Errorf("code %d maps to %s, expected %s", c.Code, e.Class, c.Exception.ID)
		}
		if nameOfCode(c.Code) != c.Name {
			return fmt.Errorf("code %d is named %s, expected %s", c.Code, nameOfCode(c.Code), c.Name)
		}
	}
	if e := fromDetail(&pb.ErrorDetail{Code: 9999}, "x", nil); e.Class.String() != t.Unknown.ID || e.Code != 9999 {
		return fmt.Errorf("unknown code maps to %s", e.Class)
	}
	for _, tr := range t.Transport {
		code := codes.Code(9999)
		if tr.Grpc != "default" {
			found := false
			for c := codes.OK; c <= codes.Unauthenticated; c++ {
				if strings.EqualFold(strings.ReplaceAll(tr.Grpc, "_", ""), strings.ReplaceAll(strings.ToLower(c.String()), "_", "")) ||
					(tr.Grpc == "CANCELLED" && c == codes.Canceled) {
					code, found = c, true
				}
			}
			if !found {
				return fmt.Errorf("unknown gRPC status %s", tr.Grpc)
			}
		}
		e := fromTransport(code, "x", nil)
		if e.Code != tr.Code || e.Retryable != tr.Retryable || e.Class.String() != tr.Exception.ID {
			return fmt.Errorf("transport %s maps to %d/%t/%s", tr.Grpc, e.Code, e.Retryable, e.Class)
		}
	}
	return nil
}

func TestTCDrvGo004ErrorMapping(t *testing.T) {
	if err := checkErrorMapping("generated/errors.json"); err != nil {
		t.Fatal(err)
	}
	e := newError(CodeQuerySyntaxError, false, "x")
	var target *Error
	if !errors.Is(e, ClassQuerySyntax) || !errors.Is(e, ClassClient) || errors.Is(e, ClassServer) || !errors.As(fmt.Errorf("wrap: %w", e), &target) {
		t.Fatal("class matching")
	}
	p := newError(CodePermissionDenied, false, "x")
	p.Class = ClassPasswordChangeRequired
	if !errors.Is(p, ClassAuthentication) {
		t.Fatal("PasswordChangeRequired must be an Authentication error (PD-076)")
	}
}

// ---------------------------------------------------------------- connection strings (TC-DRV-GO-005)

func endpointsModel(eps []string) []any {
	out := []any{}
	for _, e := range eps {
		h, p, _ := strings.Cut(e[strings.LastIndex(e, "]")+1:], ":")
		_ = h
		host := e[:len(e)-len(p)-1]
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		var port int64
		_, _ = fmt.Sscan(p, &port)
		out = append(out, map[string]any{"host": host, "port": port})
	}
	return out
}

func settingsModel(s Settings) map[string]any {
	str := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	m := map[string]any{
		"hosts": endpointsModel(s.Endpoints), "user": nil, "password": nil, "database": str(s.DefaultDatabase),
		"tls": s.TLSEnabled(), "tlsCaFile": str(s.TLS.CAFile), "tlsServerName": str(s.TLS.ServerName),
		"tlsCertificateFile": str(s.TLS.CertificateFile), "tlsKeyFile": str(s.TLS.KeyFile), "authMechanism": nil,
		"applicationName": str(s.ApplicationName), "connectTimeoutMs": s.ConnectTimeout.Milliseconds(),
		"operationTimeoutMs": s.OperationTimeout.Milliseconds(), "readConsistency": nil, "maxStalenessMs": nil,
		"writeConcern": nil, "retryReads": s.RetryReads, "retryWrites": s.RetryWrites, "maxRetries": int64(s.MaxRetries),
		"connectionsPerEndpoint": int64(s.ConnectionsPerEndpoint),
	}
	if s.mechanism != "" {
		m["authMechanism"] = s.mechanism
	}
	if c := s.Credential; c != nil {
		m["authMechanism"] = c.mechanism.String()
		m["user"] = str(c.user)
		if c.mechanism == MechanismScramSHA256 && c.hasSecret {
			m["password"] = c.secret
		}
	}
	switch s.ReadConsistency {
	case Linearizable:
		m["readConsistency"] = "linearizable"
	case BoundedStaleness:
		m["readConsistency"] = "bounded_staleness"
	case Follower:
		m["readConsistency"] = "follower"
	}
	if s.MaxStaleness > 0 {
		m["maxStalenessMs"] = s.MaxStaleness.Milliseconds()
	}
	switch s.WriteConcern {
	case Majority:
		m["writeConcern"] = "majority"
	case All:
		m["writeConcern"] = "all"
	}
	return m
}

// plain converts a model value to plain Go maps for comparison.
func plain(v any) any {
	switch x := v.(type) {
	case *ymap:
		m := map[string]any{}
		for _, k := range x.keys {
			m[k] = plain(x.vals[k])
		}
		return m
	case []any:
		out := []any{}
		for _, e := range x {
			out = append(out, plain(e))
		}
		return out
	}
	return v
}

func checkConnectionStrings(file string) error {
	rootAny, err := loadYAML(filepath.Join(conformanceDir(), file))
	if err != nil {
		return err
	}
	root := rootAny.(*ymap)
	defaults := root.mp("defaults")
	for _, cAny := range root.list("cases") {
		c := cAny.(*ymap)
		name, uri := c.str("name"), c.str("uri")
		s, err := ParseConnectionString(uri)
		if !c.isTrue("valid") {
			if err == nil {
				return fmt.Errorf("%s: accepted an invalid string", name)
			}
			if !errors.Is(err, ErrArgument) {
				return fmt.Errorf("%s: not an argument error: %v", name, err)
			}
			if u, after, ok := strings.Cut(uri, "://"); ok && u != "" {
				if at := strings.LastIndex(after, "@"); at >= 0 {
					info := after[:at]
					if _, pw, ok := strings.Cut(info, ":"); ok && len(pw) >= 4 && strings.Contains(err.Error(), pw) {
						return fmt.Errorf("%s: the message quotes the password", name)
					}
				}
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %v", name, err)
		}
		got := settingsModel(s)
		want := plain(defaults).(map[string]any)
		for k, v := range plain(c.get("expect")).(map[string]any) {
			want[k] = v
		}
		// An unset mechanism with a user is SCRAM-SHA-256 (connstring.yaml defaults note).
		for k, w := range want {
			gj, _ := json.Marshal(got[k])
			wj, _ := json.Marshal(w)
			if string(gj) != string(wj) {
				return fmt.Errorf("%s: %s = %s, expected %s", name, k, gj, wj)
			}
		}
	}
	return nil
}

func TestTCDrvGo005ConnectionStrings(t *testing.T) {
	if err := checkConnectionStrings("connstring.yaml"); err != nil {
		t.Fatal(err)
	}
	// ADR-034: the programmatic settings follow the same implication rules.
	s := DefaultSettings()
	s.TLS.CAFile = "ca.crt"
	if !s.TLSEnabled() || DefaultSettings().TLSEnabled() {
		t.Fatal("TLS implication")
	}
	if _, err := New(WithCredential(ScramCredential("u", "secret-pw")), WithMaxRetries(11)); !errors.Is(err, ErrArgument) {
		t.Fatal("MaxRetries range")
	}
	if c := ScramCredential("u", "secret-pw"); strings.Contains(c.String(), "secret-pw") {
		t.Fatal("credential string leaks the password")
	}
}

// ---------------------------------------------------------------- AST vectors (TC-DRV-GO-006)

func checkAstVectors(file string) error {
	rootAny, err := loadYAML(filepath.Join(conformanceDir(), file))
	if err != nil {
		return err
	}
	root := rootAny.(*ymap)
	coll := root.str("collection")
	plainValue := func(v any) any { return toValue(v, nil) }
	parse := func(v any, m proto.Message) error {
		return protojson.Unmarshal([]byte(toJSON(v)), m)
	}
	for _, cAny := range root.list("cases") {
		c := cAny.(*ymap)
		name := c.str("name")
		s := newSink()
		switch filepath.Base(file) {
		case "filters.json":
			f, err := dslFilter(c.get("filter"), plainValue)
			if err == nil {
				err = f.check()
			}
			if err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			where := f.toAST(s)
			if c.has("where") {
				want := &pb.AstExpr{}
				if err := parse(c.get("where"), want); err != nil {
					return fmt.Errorf("%s: %v", name, err)
				}
				if !proto.Equal(want, where) {
					return fmt.Errorf("%s: where %v, expected %v", name, where, want)
				}
			} else if where != nil {
				return fmt.Errorf("%s: expected no where", name)
			}
			if err := checkParams(c, s); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			s2 := newSink()
			if err := compareStatement(c, findStatement(coll, f, nil, nil, nil, nil, s2), parse); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			if err := checkParams(c, s2); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
		case "updates.json":
			ops := c.list("update")
			var u Update
			if len(ops) == 1 && ops[0].(*ymap).has("replace") {
				u = replaceUpdate(toDocument(ops[0].(*ymap).mp("replace"), nil))
			} else if u, err = dslUpdate(ops, plainValue); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			actual, err := u.toAST(s)
			if err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			want := c.list("operations")
			if len(want) != len(actual) {
				return fmt.Errorf("%s: %d operations, expected %d", name, len(actual), len(want))
			}
			for i, w := range want {
				op := &pb.AstUpdateOp{}
				if err := parse(w, op); err != nil {
					return fmt.Errorf("%s: %v", name, err)
				}
				if !proto.Equal(op, actual[i]) {
					return fmt.Errorf("%s: op %d = %v, expected %v", name, i, actual[i], op)
				}
			}
			if err := checkParams(c, s); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
		case "statements.json":
			args := c.mp("args")
			f, err := dslFilter(args.get("filter"), plainValue)
			if err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			var st *pb.AstStatement
			switch c.str("op") {
			case "find":
				var srt *Sort
				var proj *Projection
				var limit, skip *int64
				if l := args.list("sort"); l != nil {
					x := sortOf(l)
					srt = &x
				}
				if p := args.mp("projection"); p != nil {
					x := projectionOf(p)
					proj = &x
				}
				if n, ok := args.get("limit").(int64); ok {
					limit = &n
				}
				if n, ok := args.get("skip").(int64); ok {
					skip = &n
				}
				st = findStatement(coll, f, srt, proj, limit, skip, s)
			case "updateOne", "updateMany":
				u, err := dslUpdate(args.list("update"), plainValue)
				if err == nil {
					st, err = updateStatement(coll, f, u, c.str("op") == "updateOne", s)
				}
				if err != nil {
					return fmt.Errorf("%s: %v", name, err)
				}
			case "replaceOne":
				st, err = updateStatement(coll, f, replaceUpdate(toDocument(args.mp("replacement"), nil)), true, s)
				if err != nil {
					return fmt.Errorf("%s: %v", name, err)
				}
			case "deleteOne", "deleteMany":
				st = deleteStatement(coll, f, c.str("op") == "deleteOne", s)
			default:
				return fmt.Errorf("%s: unknown op %s", name, c.str("op"))
			}
			if err := compareStatement(c, st, parse); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			if err := checkParams(c, s); err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
		default:
			return fmt.Errorf("no AST check for %s", file)
		}
	}
	return nil
}

func compareStatement(c *ymap, st *pb.AstStatement, parse func(any, proto.Message) error) error {
	want := &pb.AstStatement{}
	if err := parse(c.get("statement"), want); err != nil {
		return err
	}
	if !proto.Equal(want, st) {
		return fmt.Errorf("statement %v, expected %v", st, want)
	}
	return nil
}

func checkParams(c *ymap, s *paramSink) error {
	if s.err != nil {
		return s.err
	}
	want := c.mp("params")
	var gotKeys, wantKeys []string
	for k := range s.params {
		gotKeys = append(gotKeys, k)
	}
	wantKeys = append(wantKeys, want.keys...)
	sort.Strings(gotKeys)
	sort.Strings(wantKeys)
	if strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
		return fmt.Errorf("params %v, expected %v", gotKeys, wantKeys)
	}
	for _, k := range want.keys {
		if h := hex.EncodeToString(s.params[k].GetRdocValue()); h != want.mp(k).str("hex") {
			return fmt.Errorf("param %s = %s, expected %s", k, h, want.mp(k).str("hex"))
		}
	}
	return nil
}

func TestTCDrvGo006AstVectors(t *testing.T) {
	for _, f := range []string{"ast/filters.json", "ast/updates.json", "ast/statements.json"} {
		if err := checkAstVectors(f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if err := And(Eq("a", 1), Gt("b", 2)).check(); err != nil {
		t.Fatal(err)
	}
	if err := Eq("a..b", 1).check(); !errors.Is(err, ErrArgument) {
		t.Fatal("empty path segment must be refused")
	}
	if _, err := (Update{}).toAST(newSink()); !errors.Is(err, ErrArgument) {
		t.Fatal("empty update must be refused")
	}
}

func TestTCDrvGo003ScramConformanceVectors(t *testing.T) {
	if err := scram.CheckVectors(filepath.Join(conformanceDir(), "scram", "vectors.yaml")); err != nil {
		t.Fatal(err)
	}
}

var _ = time.Second
