# Rustegon Go driver

Go client for Rustegon (FR-DRV-007, DEC-014). Specification: [`docs/specifications/go-driver.md`](../../docs/specifications/go-driver.md).
Same Driver Conceptual Model, error mapping, retry policy and conformance results as the .NET and Java drivers.

```go
import (
    rustegon "github.com/pegostar/rustegon/drivers/go"
    "github.com/pegostar/rustegon/drivers/go/rdoc"
)

client, err := rustegon.New(rustegon.WithConnectionString("rustegon://app_user:pwd@localhost:7700/shop"))
if err != nil { return err }
defer client.Close(ctx)

orders := client.Database("").Collection("orders")
_, err = orders.InsertOne(ctx, rdoc.Document{{Name: "_id", Value: 1}, {Name: "status", Value: "paid"}})
docs, err := orders.Find(rustegon.Eq("status", "paid")).Sort(rustegon.Desc("_id")).Limit(10).All(ctx)

err = client.WithTransaction(ctx, func(ctx context.Context, tx *rustegon.Transaction) error {
    _, err := tx.Collection("orders").UpdateOne(ctx, rustegon.ID(1), rustegon.Set("status", "shipped"))
    return err
})
var e *rustegon.Error
if errors.As(err, &e) && errors.Is(err, rustegon.ClassTransactionConflict) { /* … */ }
```

- **TLS (ADR-034):** plain text by default; `tlsCaFile`, `tlsServerName`, `tlsCertificateFile`/`tlsKeyFile`, `tls=true`
  or `authMechanism=X509` turn TLS on (`rustegon.WithTLS(rustegon.TLSSettings{CAFile: …})` in code).
- **Credentials:** `ScramCredential(user, password)`, `APIKeyCredential(key)`, `X509Credential()` (with a client
  certificate in `TLSSettings`). Secrets are never logged or printed.
- **Certificates:** `rustegon init --tls` certificates work with Go since ADR-035 (node role as a URI SAN, PD-193 closed).

## Layout

| Path | Content |
|---|---|
| `*.go` (package `rustegon`) | client, settings, connection strings, auth, transport/retry, builders, CRUD, cursors, transactions |
| `rdoc/` | RDoc v1 codec, value model, canonical/extended JSON |
| `internal/pb/` | generated gRPC stubs (`scripts/generate.sh`, do not edit) |
| `errorcodes_gen.go` | generated error table from `drivers/conformance/generated/errors.json` |
| `internal/scram/` | SCRAM-SHA-256 and SASLprep |
| `internal/testserver/` | `rustegond` process fixture (PD-072, PD-191) |

## Build and test

```bash
cd drivers/go
gofmt -l . && go vet ./...
RUSTEGON_BIN_DIR=<dir with rustegon and rustegond> go test ./...      # -race where cgo is available (PD-192)
scripts/generate.sh                                                   # regenerate stubs and error table
```

Without `RUSTEGON_BIN_DIR` (or `<repo>/target/debug`) the server tests skip (they fail under `CI=true`). The
conformance runner (TC-DRV-GO-020) writes `conformance-results.json` (or `RUSTEGON_CONFORMANCE_RESULTS`), compared
with the .NET and Java results by `scripts/ci-local.sh` (AC-DRV-003). Test ids: TC-DRV-GO-001…030 (go-driver.md §11).
No module is published yet.
