// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

package rustegon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rustegon/rustegon/drivers/go/internal/testserver"
	"github.com/rustegon/rustegon/drivers/go/rdoc"
)

// Driver-specific integration tests against a real node (the conformance suite covers the
// shared behaviour). Each starts its own node when it changes the node's state or mode.

func ownServer(t *testing.T, plainText bool) *testserver.Server {
	t.Helper()
	dir, reason := testserver.FindBinaries()
	if dir == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal(reason)
		}
		t.Skip(reason)
	}
	s, err := testserver.Start(dir, plainText)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

// TC-DRV-GO-009 (ADR-034): a connection string without tls* options is plain text and works
// against a plain-text node; a client with TLS settings fails against it.
func TestTCDrvGo009PlainTextDefault(t *testing.T) {
	s := ownServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	uri := fmt.Sprintf("rustegon://%s:%s@%s/plain", testserver.AdminUser, escapeData(s.AdminPassword), s.GRPC)
	c, err := New(WithConnectionString(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	if c.Settings().TLSEnabled() {
		t.Fatal("TLS must be off by default (ADR-034)")
	}
	if _, err := c.CreateDatabase(ctx, "plain"); err != nil {
		t.Fatal(err)
	}
	coll := c.Database("").Collection("items")
	if _, err := coll.InsertOne(ctx, rdoc.Document{{Name: "_id", Value: 1}, {Name: "n", Value: 7}}); err != nil {
		t.Fatal(err)
	}
	d, found, err := coll.FindByID(ctx, 1)
	if err != nil || !found {
		t.Fatalf("findById: %v %v", found, err)
	}
	if v, _ := d.Get("n"); v != int64(7) {
		t.Fatalf("n = %v", v)
	}
	tlsClient, err := New(WithEndpoints(s.GRPC), WithCredential(ScramCredential(testserver.AdminUser, s.AdminPassword)),
		WithTLS(TLSSettings{Enabled: true}), WithMaxRetries(0), WithOperationTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tlsClient.Close(ctx) }()
	if err := tlsClient.Ping(ctx); !errors.Is(err, ClassUnavailable) {
		t.Fatalf("TLS against a plain-text node: %v", err)
	}
}

// TC-DRV-GO-011…015: client API round trip (id 4: total 40 → 41 by UpdateMany → 46 in the transaction) — CRUD, cursor batches, RGQL, bulk, transactions.
func TestTCDrvGo011ClientAPI(t *testing.T) {
	s := requireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := adminClient(t, s, WithDefaultDatabase("go_api"))
	defer func() { _ = c.Close(ctx) }()
	if _, err := c.CreateDatabase(ctx, "go_api", IfNotExists()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = c.DropDatabase(context.Background(), "go_api", IfExists()) }()
	db := c.Database("")
	if _, err := db.CreateCollection(ctx, "orders", IfNotExists()); err != nil {
		t.Fatal(err)
	}
	orders := db.Collection("orders")
	var docs []rdoc.Document
	for i := 1; i <= 25; i++ {
		docs = append(docs, rdoc.Document{{Name: "_id", Value: i}, {Name: "status", Value: map[bool]string{true: "paid", false: "open"}[i%2 == 0]}, {Name: "total", Value: i * 10}})
	}
	if _, err := orders.InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	cur, err := orders.Find(Eq("status", "paid")).Sort(Desc("total")).BatchSize(4).Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for d, err := range cur.All(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			if v, _ := d.Get("_id"); v != int64(24) {
				t.Fatalf("first = %v", v)
			}
		}
		n++
	}
	_ = cur.Close(ctx)
	if n != 12 {
		t.Fatalf("paid = %d", n)
	}
	u, err := orders.UpdateMany(ctx, Lt("total", 50), Set("status", "small").Inc("total", 1))
	if err != nil || u.MatchedCount != 4 {
		t.Fatalf("updateMany %+v %v", u, err)
	}
	rows, err := db.Query(ctx, "FROM orders WHERE status = $s", rdoc.Document{{Name: "s", Value: "small"}})
	if err != nil {
		t.Fatal(err)
	}
	all, err := (&run{ctx: ctx}).drainCursor(rows, nil)
	if err != nil || len(all.([]any)) != 4 {
		t.Fatalf("query: %v %v", all, err)
	}
	b, err := orders.BulkWrite(ctx, []BulkOperation{BulkInsert(rdoc.Document{{Name: "_id", Value: 100}}), BulkInsert(rdoc.Document{{Name: "_id", Value: 1}}), BulkDelete(2, "")}, Unordered())
	if err != nil || b.InsertedCount != 1 || b.DeletedCount != 1 || len(b.Errors) != 1 || b.Errors[0].Err.Code != CodeDuplicateKey {
		t.Fatalf("bulk %+v %v", b, err)
	}
	err = c.WithTransaction(ctx, func(ctx context.Context, tx *Transaction) error {
		if _, err := tx.Collection("orders").UpdateOne(ctx, ID(3), Inc("total", -5)); err != nil {
			return err
		}
		_, err := tx.Collection("go_api.orders").UpdateOne(ctx, ID(4), Inc("total", 5))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := orders.FindByID(ctx, 4)
	if v, _ := d.Get("total"); err != nil || v != int64(46) {
		t.Fatalf("after txn total = %v %v", v, err)
	}
	if _, err := orders.InsertOne(ctx, rdoc.Document{{Name: "_id", Value: 1}}); !errors.Is(err, ClassDuplicateKey) {
		t.Fatalf("duplicate: %v", err)
	}
}

// TC-DRV-GO-026: concurrency stress — many goroutines share one client and its pool.
func TestTCDrvGo026ConcurrencyStress(t *testing.T) {
	s := requireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := adminClient(t, s, WithDefaultDatabase("go_stress"), WithConnectionsPerEndpoint(4))
	defer func() { _ = c.Close(ctx) }()
	if _, err := c.CreateDatabase(ctx, "go_stress", IfNotExists()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = c.DropDatabase(context.Background(), "go_stress", IfExists()) }()
	if _, err := c.Database("").CreateCollection(ctx, "s", IfNotExists()); err != nil {
		t.Fatal(err)
	}
	coll := c.Database("").Collection("s")
	const workers, each = 50, 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				id := w*each + i
				if _, err := coll.InsertOne(ctx, rdoc.Document{{Name: "_id", Value: id}}); err != nil {
					errs <- err
					return
				}
				if _, found, err := coll.FindByID(ctx, id); err != nil || !found {
					errs <- fmt.Errorf("find %d: %v %v", id, found, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	all, err := coll.Find(EmptyFilter()).All(ctx)
	if err != nil || len(all) != workers*each {
		t.Fatalf("%d documents, %v", len(all), err)
	}
	for _, sl := range c.pool.slots {
		if sl.inFlight.Load() != 0 {
			t.Fatal("in-flight counter leaked")
		}
	}
}

// TC-DRV-GO-027: the client survives a node crash and restart on the same data directory.
func TestTCDrvGo027Reconnect(t *testing.T) {
	s := ownServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := adminClient(t, s, WithDefaultDatabase("go_reconnect"))
	defer func() { _ = c.Close(ctx) }()
	if _, err := c.CreateDatabase(ctx, "go_reconnect"); err != nil {
		t.Fatal(err)
	}
	coll := c.Database("").Collection("r")
	if _, err := c.Database("").CreateCollection(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := coll.InsertOne(ctx, rdoc.Document{{Name: "_id", Value: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Crash(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx); !errors.Is(err, ClassUnavailable) {
		t.Fatalf("ping of a dead node: %v", err)
	}
	if err := s.Restart(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, found, err := coll.FindByID(ctx, 1)
		if err == nil && found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reconnect: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
