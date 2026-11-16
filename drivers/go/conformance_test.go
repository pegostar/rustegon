// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/pegostar/rustegon/drivers/go/internal/pb/rustegon/v1"
	"github.com/pegostar/rustegon/drivers/go/internal/testserver"
	"github.com/pegostar/rustegon/drivers/go/rdoc"
)

// TC-DRV-GO-020: the shared conformance suite (FR-DRV-007, FR-DRV-003, AC-DRV-007). Every test
// of drivers/conformance/<category>/*.yaml runs as a subtest; the results are written to
// RUSTEGON_CONFORMANCE_RESULTS (default conformance-results.json here) for the AC-DRV-003
// cross-driver comparison.

var categories = []string{"crud", "query", "cursor", "bulk", "txn", "errors", "schema", "auth", "client"}

var capabilities = map[string]bool{"admin": true, "api-key": true, "x509-client-cert": true, "slow": true, "fixture-connection-string": true}

// ---------------------------------------------------------------- shared server fixture

var fixture struct {
	once    sync.Once
	server  *testserver.Server
	reason  string
	mu      sync.Mutex
	files   map[string]*fileContext
	apiKey  string
	cleanup []func()
}

type fileContext struct {
	database string
	client   *Client
}

func TestMain(m *testing.M) {
	code := m.Run()
	for i := len(fixture.cleanup) - 1; i >= 0; i-- {
		fixture.cleanup[i]()
	}
	if fixture.server != nil {
		_ = fixture.server.Stop()
	}
	os.Exit(code)
}

// requireServer returns the shared TLS node, skipping (failing under CI=true) without binaries.
func requireServer(t *testing.T) *testserver.Server {
	t.Helper()
	fixture.once.Do(func() {
		dir, reason := testserver.FindBinaries()
		if dir == "" {
			fixture.reason = reason
			return
		}
		s, err := testserver.Start(dir, false)
		if err != nil {
			fixture.reason = err.Error()
			return
		}
		fixture.server = s
	})
	if fixture.server == nil {
		if os.Getenv("CI") == "true" {
			t.Fatalf("no server: %s", fixture.reason)
		}
		t.Skipf("no server: %s", fixture.reason)
	}
	return fixture.server
}

func serverOptions(s *testserver.Server, cred *Credential) []Option {
	opts := []Option{WithEndpoints(s.GRPC), WithCredential(cred), WithApplicationName("rustegon-go-tests")}
	if s.TLS() {
		opts = append(opts, WithTLS(TLSSettings{Enabled: true, CAFile: s.CAFile()}))
	}
	return opts
}

func adminClient(t *testing.T, s *testserver.Server, extra ...Option) *Client {
	t.Helper()
	c, err := New(append(serverOptions(s, ScramCredential(testserver.AdminUser, s.AdminPassword)), extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fileContextFor(t *testing.T, s *testserver.Server, relative string) *fileContext {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.files == nil {
		fixture.files = map[string]*fileContext{}
	}
	if f, ok := fixture.files[relative]; ok {
		return f
	}
	category, file, _ := strings.Cut(relative, "/")
	stem := strings.ReplaceAll(strings.TrimSuffix(file, filepath.Ext(file)), "-", "_")
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	database := fmt.Sprintf("conf_%s_%s_%s", category, stem, hex.EncodeToString(rnd[:]))
	c := adminClient(t, s, WithDefaultDatabase(database))
	if _, err := c.CreateDatabase(context.Background(), database); err != nil {
		t.Fatalf("create database: %v", err)
	}
	f := &fileContext{database: database, client: c}
	fixture.files[relative] = f
	fixture.cleanup = append(fixture.cleanup, func() {
		_, _ = c.DropDatabase(context.Background(), database, IfExists())
		_ = c.Close(context.Background())
	})
	return f
}

func admin[T any](ctx context.Context, c *Client, f func(context.Context, pb.AdminServiceClient, ...grpc.CallOption) (T, error)) (T, error) {
	var out T
	err := c.exec.unary(ctx, callSpec{kind: opNoRetry}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) (err error) {
		out, err = f(ctx, pb.NewAdminServiceClient(cc), o...)
		return err
	})
	return out, err
}

func fixtureAPIKey(t *testing.T, s *testserver.Server) string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.apiKey != "" {
		return fixture.apiKey
	}
	ctx := context.Background()
	c := adminClient(t, s)
	defer func() { _ = c.Close(ctx) }()
	var who *pb.WhoAmIResponse
	err := c.exec.unary(ctx, callSpec{kind: opRead}, func(ctx context.Context, cc grpc.ClientConnInterface, o ...grpc.CallOption) (err error) {
		who, err = pb.NewAuthServiceClient(cc).WhoAmI(ctx, &pb.WhoAmIRequest{}, o...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := admin(ctx, c, func(ctx context.Context, a pb.AdminServiceClient, o ...grpc.CallOption) (*pb.CreateApiKeyResponse, error) {
		return a.CreateApiKey(ctx, &pb.CreateApiKeyRequest{Description: "go conformance runner", Roles: who.GetRoles()}, o...)
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.apiKey = created.GetSecret()
	return fixture.apiKey
}

// ---------------------------------------------------------------- results file

type resultEntry struct {
	ID           string            `json:"id"`
	Status       string            `json:"status"`
	Reason       string            `json:"reason,omitempty"`
	Observations []json.RawMessage `json:"observations"`
	Outcome      json.RawMessage   `json:"outcome,omitempty"`
}

var results struct {
	mu            sync.Mutex
	entries       map[string]resultEntry
	serverVersion string
}

func addResult(e resultEntry) {
	results.mu.Lock()
	defer results.mu.Unlock()
	if results.entries == nil {
		results.entries = map[string]resultEntry{}
	}
	if e.Observations == nil {
		e.Observations = []json.RawMessage{}
	}
	results.entries[e.ID] = e
	ids := make([]string, 0, len(results.entries))
	for id := range results.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	list := make([]resultEntry, 0, len(ids))
	for _, id := range ids {
		list = append(list, results.entries[id])
	}
	out := struct {
		Driver        string        `json:"driver"`
		DriverVersion string        `json:"driverVersion"`
		ServerVersion string        `json:"serverVersion"`
		Results       []resultEntry `json:"results"`
	}{"go", Version, results.serverVersion, list}
	text, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	path := os.Getenv("RUSTEGON_CONFORMANCE_RESULTS")
	if path == "" {
		path = "conformance-results.json"
	}
	_ = os.WriteFile(path, text, 0o644)
}

func raw(ss []string) []json.RawMessage {
	out := make([]json.RawMessage, len(ss))
	for i, s := range ss {
		out[i] = json.RawMessage(s)
	}
	return out
}

// ---------------------------------------------------------------- the suite

func TestTCDrvGo020ConformanceSuite(t *testing.T) {
	for _, category := range categories {
		files, err := filepath.Glob(filepath.Join(conformanceDir(), category, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(files)
		for _, file := range files {
			relative := category + "/" + filepath.Base(file)
			text, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			rootAny, err := parseYAML(text)
			if err != nil {
				t.Fatalf("%s: %v", relative, err)
			}
			root := rootAny.(*ymap)
			for _, tAny := range root.list("tests") {
				test := tAny.(*ymap)
				id := test.str("id")
				t.Run(id, func(t *testing.T) { runConformanceTest(t, relative, root, test, string(text)) })
			}
		}
	}
}

func runConformanceTest(t *testing.T, relative string, root, test *ymap, text string) {
	id := test.str("id")
	setup := test.mp("setup")
	if setup == nil {
		setup = root.mp("setup")
	}
	ops := test.list("operations")
	unitLevel := setup == nil
	for _, o := range ops {
		if o.(*ymap).str("object") != "runner" {
			unitLevel = false
		}
	}
	for _, r := range test.list("requires") {
		if !capabilities[r.(string)] {
			addResult(resultEntry{ID: id, Status: "skipped", Reason: "requires " + r.(string)})
			t.Skip("requires " + r.(string))
		}
	}
	var obs []string
	var outcome string
	var err error
	if unitLevel {
		obs, err = runUnitLevel(ops, text)
	} else {
		dir, _ := testserver.FindBinaries()
		if dir == "" && os.Getenv("CI") != "true" {
			addResult(resultEntry{ID: id, Status: "skipped", Reason: "no server binaries (RUSTEGON_BIN_DIR)"})
		}
		s := requireServer(t)
		obs, outcome, err = runWithServer(t, s, relative, test, setup, ops, text)
	}
	if err != nil {
		addResult(resultEntry{ID: id, Status: "failed", Reason: err.Error()})
		t.Fatal(err)
	}
	e := resultEntry{ID: id, Status: "passed", Observations: raw(obs)}
	if outcome != "" {
		e.Outcome = json.RawMessage(outcome)
	}
	addResult(e)
}

func testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

func runUnitLevel(ops []any, text string) ([]string, error) {
	// Runner operations need no server; the run still needs a client object, never used.
	c, err := New(WithEndpoints("unused.invalid:7700"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := testContext()
	defer cancel()
	defer func() { _ = c.Close(ctx) }()
	r := newRun(ctx, c, "unused", "", func(s string) string { return s }, text)
	r.runnerExt = runnerChecks
	defer r.close()
	if err := r.runOps(ops, true); err != nil {
		return nil, err
	}
	return r.observations, nil
}

func runWithServer(t *testing.T, s *testserver.Server, relative string, test, setup *ymap, ops []any, text string) ([]string, string, error) {
	ctx, cancel := testContext()
	defer cancel()
	f := fileContextFor(t, s, relative)
	results.mu.Lock()
	if results.serverVersion == "" {
		results.mu.Unlock()
		if info, err := f.client.ServerInfo(ctx); err == nil {
			results.mu.Lock()
			results.serverVersion = info.ServerVersion
			results.mu.Unlock()
		}
	} else {
		results.mu.Unlock()
	}
	requires := map[string]bool{}
	for _, r := range test.list("requires") {
		requires[r.(string)] = true
	}
	apiKey := ""
	if requires["api-key"] {
		apiKey = fixtureAPIKey(t, s)
	}
	host, port, _ := net.SplitHostPort(s.GRPC)
	subs := [][2]string{
		{"${database}", f.database}, {"${host}", host}, {"${port}", port},
		{"${adminUserEncoded}", escapeData(testserver.AdminUser)}, {"${adminPasswordEncoded}", escapeData(s.AdminPassword)},
		{"${adminUser}", testserver.AdminUser}, {"${adminPassword}", s.AdminPassword},
		{"${caFileEncoded}", escapeData(s.CAFile())}, {"${caFile}", s.CAFile()},
		{"${apiKey}", apiKey}, {"${clientCertFile}", s.ClientCertFile()}, {"${clientKeyFile}", s.ClientKeyFile()},
	}
	substitute := func(x string) string {
		for _, kv := range subs {
			x = strings.ReplaceAll(x, kv[0], kv[1])
		}
		return x
	}
	var users []string
	defer func() {
		for _, u := range users {
			_, _ = admin(ctx, f.client, func(ctx context.Context, a pb.AdminServiceClient, o ...grpc.CallOption) (*pb.DropUserResponse, error) {
				return a.DropUser(ctx, &pb.DropUserRequest{Name: u}, o...)
			})
		}
	}()
	first, err := setupTest(ctx, f, setup, &users, requires["x509-client-cert"], substitute)
	if err != nil {
		return nil, "", fmt.Errorf("setup: %w", err)
	}
	r := newRun(ctx, f.client, f.database, first, substitute, text)
	r.runnerExt = runnerChecks
	r.openClient = func(args *ymap) (*Client, error) { return openFixtureClient(s, f.database, args, substitute) }
	defer r.close()
	if err := r.runOps(ops, true); err != nil {
		return nil, "", err
	}
	outcome := ""
	if expected := test.mp("outcome"); expected != nil {
		outcome, err = checkOutcome(ctx, f, r, expected, text)
		if err != nil {
			return nil, "", err
		}
	}
	return r.observations, outcome, nil
}

func grant(ref string) *pb.RoleGrant {
	role, scope, ok := strings.Cut(ref, "@")
	if !ok {
		return &pb.RoleGrant{Role: ref}
	}
	kind := "database:"
	if strings.Contains(scope, ".") {
		kind = "collection:"
	}
	return &pb.RoleGrant{Role: role, Resource: kind + scope}
}

func setupTest(ctx context.Context, f *fileContext, setup *ymap, users *[]string, x509 bool, substitute func(string) string) (string, error) {
	db := f.client.Database(f.database)
	names, err := db.ListCollectionNames(ctx)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if _, err := db.DropCollection(ctx, n, IfExists()); err != nil {
			return "", err
		}
	}
	first := ""
	for _, cAny := range setup.list("collections") {
		c := cAny.(*ymap)
		if first == "" {
			first = c.str("name")
		}
		var o []OpOption
		if v := c.mp("validator"); v != nil {
			o = append(o, WithValidator(validatorOf(v)))
		}
		if _, err := db.CreateCollection(ctx, c.str("name"), o...); err != nil {
			return "", err
		}
	}
	for _, iAny := range setup.list("indexes") {
		i := iAny.(*ymap)
		var o []OpOption
		if i.isTrue("unique") {
			o = append(o, Unique())
		}
		d, err := db.Collection(i.str("collection")).CreateIndex(ctx, i.str("name"), keysOf(i.list("keys")), o...)
		if err != nil {
			return "", err
		}
		if d.State != IndexReady {
			return "", fmt.Errorf("index %s is %s", d.Name, d.State)
		}
	}
	if data := setup.mp("data"); data != nil {
		for _, coll := range data.keys {
			var docs []rdoc.Document
			for _, d := range data.list(coll) {
				docs = append(docs, toDocument(d.(*ymap), nil))
			}
			if len(docs) > 0 {
				if _, err := db.Collection(coll).InsertMany(ctx, docs); err != nil {
					return "", err
				}
			}
		}
	}
	create := func(req *pb.CreateUserRequest) error {
		_, err := admin(ctx, f.client, func(ctx context.Context, a pb.AdminServiceClient, o ...grpc.CallOption) (*pb.CreateUserResponse, error) {
			return a.CreateUser(ctx, req, o...)
		})
		if err == nil {
			*users = append(*users, req.GetName())
		}
		return err
	}
	for _, uAny := range setup.list("users") {
		u := uAny.(*ymap)
		pw := u.str("password")
		req := &pb.CreateUserRequest{Name: u.str("name"), Password: &pw, MustChangePassword: u.isTrue("mustChangePassword")}
		for _, r := range u.list("roles") {
			req.Roles = append(req.Roles, grant(substitute(r.(string))))
		}
		if err := create(req); err != nil {
			return "", err
		}
	}
	if x509 {
		// README §5: the init client certificate maps to a user with read-write on ${database}.
		req := &pb.CreateUserRequest{Name: "x509:CN=" + testserver.ClientCertificateUser, Roles: []*pb.RoleGrant{grant("read_write@" + f.database)}}
		if err := create(req); err != nil {
			return "", err
		}
	}
	return first, nil
}

func openFixtureClient(s *testserver.Server, database string, args *ymap, substitute func(string) string) (*Client, error) {
	cred := args.mp("credential")
	opts := []Option{WithEndpoints(s.GRPC), WithDefaultDatabase(database), WithApplicationName("rustegon-go-tests"),
		WithAllowPasswordChangeOnly(args.isTrue("allowPasswordChangeOnly"))}
	tlsSettings := TLSSettings{Enabled: s.TLS(), CAFile: s.CAFile()}
	switch {
	case cred.has("scram"):
		sc := cred.mp("scram")
		opts = append(opts, WithCredential(ScramCredential(substitute(sc.str("user")), substitute(sc.str("password")))))
	case cred.has("apiKey"):
		opts = append(opts, WithCredential(APIKeyCredential(substitute(cred.str("apiKey")))))
	default:
		x := cred.mp("x509")
		opts = append(opts, WithCredential(X509Credential()))
		tlsSettings.CertificateFile = substitute(x.str("certificateFile"))
		tlsSettings.KeyFile = substitute(x.str("keyFile"))
	}
	if s.TLS() {
		opts = append(opts, WithTLS(tlsSettings))
	}
	return New(opts...)
}

func checkOutcome(ctx context.Context, f *fileContext, r *run, expected *ymap, text string) (string, error) {
	n := newNormalizer(text)
	keys := append([]string(nil), expected.keys...)
	sort.Strings(keys)
	parts := map[string]string{}
	for _, coll := range expected.keys {
		docs, err := f.client.Database(f.database).Collection(coll).Find(EmptyFilter()).Sort(Asc("_id")).All(ctx)
		if err != nil {
			return "", err
		}
		arr := []any{}
		for _, d := range docs {
			arr = append(arr, d)
		}
		if why := r.matcher().result(expected.get(coll), arr, matchMode{ordered: true}); why != "" {
			return "", failf("outcome of %s: %s", coll, why)
		}
		parts[coll] = n.json(arr)
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kj, _ := json.Marshal(k)
		b.Write(kj)
		b.WriteByte(':')
		b.WriteString(parts[k])
	}
	b.WriteByte('}')
	return b.String(), nil
}

// escapeData percent-encodes everything but the RFC 3986 unreserved characters (as .NET
// Uri.EscapeDataString), so the result is valid in any part of a connection string.
func escapeData(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
