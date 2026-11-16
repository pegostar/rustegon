# Driver divergences

java-driver.md §11: both drivers expose the same Driver Conceptual Model (dotnet-driver.md §1)
with the same method names modulo language conventions, defaults, retry parameters, connection
string grammar, exception names and error mapping, and pass the same conformance suite
(`drivers/conformance/`). Every exception to that rule — between the drivers, or between the
drivers and their specifications — is listed here with its justification. Operation ids refer
to `drivers/conformance/model.yaml`.

## 1. R1 scope (both drivers, versus the specifications)

| Item | Divergence | Justification | Until |
|---|---|---|---|
| Deferred features (PD-069) | Not exposed in R1: tables (`Database.GetTable`), time series (`Database.GetTimeSeries`), change streams (`Collection.Watch`), subscriptions, document counters (`Collection.Counters`), vector search (`Collection.VectorSearch`), the typed pipeline builder (`Collection.Query` / `Rgql.Query`), LINQ (`Collection.AsQueryable`), DNS SRV seeds (`rustegon+srv://`), multi-endpoint node selection and topology discovery. Packages `Rustegon.Driver.Linq`, `.DependencyInjection`, `.OpenTelemetry`, `rustegon-driver-jackson`, `-reactive`, `-otel` are not published. | The R1 server (M4) serves none of these; stub methods throwing `FeatureNotSupportedException` would be dead API (PD-069 option a). Each is added back additively with its server milestone and gated on a `GetServerInfo.features` flag; `model.yaml` lists the milestone of each. | the milestone in `model.yaml` (`deferred(<ms>)`) |
| Sessions | `StartSession` / `startSession` is a pass-through: the session echoes the last `rgn-causality-token` trailer and sends it on later calls; no server-side session. | The single-node R1 server has nothing more to offer (PD-069). | M5 (causal reads on followers) |
| Bulk `AtomicMode` (PD-071) | `BulkWriteOptions` has no `Atomic` / `atomic(AtomicMode)` option although dotnet-driver.md §4 and java-driver.md §3 show it. | `BulkWriteRequest` has no atomic field; the M4 server runs a bulk write in one transaction outside an interactive transaction where failed operations roll back alone (protocol.md §3, PD-053), which is neither `AUTO` nor `NON_ATOMIC` of transactions.md §6. Adding the option later is additive. | an additive `BulkWriteRequest` field with server support (PD-071) |
| Bulk operations by id | Bulk operations address documents by `_id` (`BulkOperation.Update(id, …)`), not by filter. | `BulkOperation` of `document.proto` is by id only. | additive proto change |
| SCRAM channel binding (PD-074) | Both drivers send the gs2 header `n,,` (SCRAM-SHA-256 without `-PLUS`). | Neither .NET `SocketsHttpHandler` nor grpc-netty-shaded exposes the TLS exporter (RFC 9266) needed for `tls-exporter`; same choice as the Rust CLI (PD-058). TLS 1.3 server authentication still protects the exchange. | a transport exposing the exporter |
| Synchronous API only in Java | The Java R1 driver offers the blocking API only; `RustegonClient.async()` (`CompletableFuture`) and `Flow.Publisher` cursors are not in R1 (`Client.Async`, `Cursor.Publisher`). | The blocking API is virtual-thread friendly (java-driver.md §1) and covers every R1 operation; one API surface halves the R1 work and the conformance runner. | M11-R2 |
| Asynchronous API only in .NET | No synchronous .NET methods. | Documented decision in dotnet-driver.md §4 (no sync-over-async). | permanent |

## 2. Between the drivers

| Item | .NET | Java | Justification |
|---|---|---|---|
| Timeout exception name | `Rustegon.Driver.TimeoutException` (does not derive from `System.TimeoutException`) | `RustegonTimeoutException` | Names as in dotnet-driver.md §8 and java-driver.md §6; Java avoids a clash with `java.util.concurrent.TimeoutException` (a checked exception). The class id `Timeout` in `errors-map.yaml` is the same. |
| Password parameters | `string` | `char[]` | Java convention for secrets (can be zeroed); .NET strings cannot be. |
| Typed field references | expression lambdas (`Filter.Eq<Order>(x => x.Status, …)`, `FieldPath.Of<Order>(x => …)` for the other builders) plus string paths | string paths, optional generated metamodel (`Order_.status`) | Language capabilities; both produce identical ASTs (`ast/*.json`). |
| Discriminator field name (PD-110, PD-111, PD-116) | always `_type` | `_type` by default, overridable on the root of the hierarchy | Same default, pinned by `mapping/vectors.yaml`; a Java model with another field cannot be read by .NET. The .NET override is additive (an attribute property on the root) and left out of R1 (PD-116). |
| Operator overloads | `&`, `\|`, `!` on filters | `and`, `or`, `not` methods | Java has no operator overloading. |
| Mapping errors on read | `RDocException` (RGN-1001) naming the field | `IllegalArgumentException` naming the field | Each language's argument convention (PD-108, PD-111); `mapping/vectors.yaml` accepts each driver's class for its `invalid` vectors. |
| User without password in the connection string | parsed (password null, or `""` for `user:@`); `RustegonClient` refuses the credential until `Credential = RustegonCredential.Scram(user, password)` is set | SCRAM credential with an empty password; the real password is passed with `.credential(…)` on the builder | Keeps secrets out of connection strings (`char[]`); to be pinned in `connstring.yaml`. |
| Client TLS versions | OS defaults (TLS 1.2 and 1.3 offered; `EnabledSslProtocols` not set), see §4.2 | JDK defaults (TLS 1.3 and 1.2 offered; TLS 1.3 negotiated with a default node, tested) | `TlsChannelCredentials` cannot restrict protocol versions; the server's TLS 1.3-only default still applies. |
| Per-operation overrides (consistency, write concern, timeout, session) | options objects per call (`FindOptions`, `QueryOptions`, `InsertOptions`, `UpdateOptions`, … with `ReadConsistency`/`MaxStaleness`, `WriteConcern`, `Timeout`, `Session`; PD-095) | derived handles (`withReadConsistency`/`withWriteConcern`/`withTimeout`/`withSession`), no per-call options in R1 (PD-100) | dotnet-driver.md §4/§6 specify options types (`new FindOptions { … }`, `new UpdateOptions { IfRev = … }`) and the .NET API already needs them for `IfRev`/`IsUpsert`/`Ordered`; both reach the same request fields, so conformance results are identical. |
| `connectTimeout` | enforced by `SocketsHttpHandler.ConnectTimeout` (TCP + TLS handshake), tested (`tc_drv_net_017_connect_timeout_is_enforced`); an expired connect timeout is RGN-3002 Unavailable | enforced per call by node selection: the chosen channel must connect (TLS handshake included) within `connectTimeout`, else RGN-3002 `UnavailableException`; tested (`tc_drv_java_019_connect_timeout_is_enforced_per_call`) | Mechanism differs (the shaded Netty connect option is not reachable from the JPMS module, PD-081, closed); the observable behaviour is the same. |

## 3. Clarifications that are not divergences

- Exception hierarchy: both drivers have `RustegonClientException` (client errors, 1xxx not
  mapped elsewhere) with `QuerySyntaxException` (RGN-1010/1011/1012) as its subclass, and
  `PasswordChangeRequiredException` under `AuthenticationException` (PD-076). The complete
  code → class table is `drivers/conformance/errors-map.yaml`. `PasswordChangeRequiredException`
  carries RGN-4002 PermissionDenied in both drivers although no catalog code maps to it (it is
  raised by the driver from the login result, PD-076).
- `UpdateOne` / `ReplaceOne` / `DeleteOne` with a non-id filter are supported in both drivers
  through RGQL's `LIMIT 1` form (PD-070); no `Many`-only restriction applies.

## 4. .NET driver (lane DN1 list, re-derived)

The original DN1 report was lost; this list was re-derived on 2026-11-11 by running the shared
suite through the .NET runners (`tc_drv_net_001_conformance_codec_vectors`: 185 codec vectors;
`tc_drv_net_008_conformance_connstring_cases`: 47 strings; `tc_drv_net_006_conformance_*`: every
catalog code, the unknown code and every transport fallback of `generated/errors.json`) and by
reviewing the driver against dotnet-driver.md §2, §3, §8, §9 (codec, connection strings, errors,
auth, retry).

### 4.1 Fixed (the driver now follows the suite)

| Area | Vector / item | Before (pre-fix driver, by reading its code) | Expected | Fix |
|---|---|---|---|---|
| Errors | `errors-map.yaml` 1010, 1011, 1012 | `RustegonClientException` (no `QuerySyntaxException` class) | `QuerySyntaxException` (subclass of `RustegonClientException`) | class added; mapping from `ErrorCodes.g.cs` |
| Errors | 1034 DescriptorVersionMismatch | `RustegonClientException` (1xxx range) | `RustegonServerException` | table-driven mapping |
| Errors | 4004 TlsRequired | `RustegonClientException` | `AuthenticationException` | table-driven mapping |
| Errors | 5007 VersionIncompatible | `RustegonServerException` (5xxx range) | `RustegonClientException` | table-driven mapping |
| Errors | hierarchy (`classes`) | `DuplicateKeyException`, `DocumentValidationException` derived from `RustegonClientException` | parent `Base` (`RustegonException`), as in Java | reparented |
| Errors | `transport` fallbacks | bare statuses mapped to catalog codes by status (`INVALID_ARGUMENT` → 1001, `NOT_FOUND` → 1030, `UNIMPLEMENTED` → 5007, `CANCELLED` → 5005, …), retryable flag from the catalog | the eight `transport` entries (`default` → 5001 Server, not retryable; `RESOURCE_EXHAUSTED` → 5004 retryable) | fallback table of `ErrorCodes.g.cs` |
| Errors | PD-075 table | interim `ErrorCodes.g.cs` from `tools/Generate-ErrorCodes.ps1` (internal, no exception column) | compile `drivers/conformance/generated/ErrorCodes.g.cs` as is | linked into the project; generator removed |
| Conn. string | `scheme_upper_case_is_not_accepted` | accepted (`OrdinalIgnoreCase`) | rejected | case-sensitive scheme |
| Conn. string | `host_is_lowercased` | host kept as written | `db1.example.com` | lower-cased |
| Conn. string | `unescaped_at_in_password` | accepted (last `@` split: password `p@ss`) | rejected | a second raw `@` is an error |
| Conn. string | `user_without_password`, `empty_password` | rejected ("a user needs a password") | valid; password null / `""`, mechanism SCRAM-SHA-256 | accepted; `RustegonClient` refuses such a credential until `RustegonCredential.Scram(user, password)` is set (secrets stay out of the string) |
| Conn. string | `spec_example_dotnet` (`authMechanism=SCRAM-SHA-256` without user) | rejected | valid, no credential | accepted; the mechanism is recorded by the parser, the credential is set in code |
| Conn. string | `timeouts`, `consistency_and_concern`, `retries_and_pool`, `option_keys_and_booleans_case_insensitive` | `operationTimeoutMs`, `readConsistency`, `maxStalenessMs`, `writeConcern`, `retryReads`, `retryWrites`, `maxRetries` unknown (rejected); the driver used `timeoutMs` | parsed into the settings | options and settings added (`ReadConsistency`, `MaxStaleness`, `WriteConcern`, `RetryReads`, `RetryWrites`, `MaxRetries`); `timeoutMs` removed |
| Conn. string | `defaults.connectionsPerEndpoint` | 1 | 2 | default 2 |
| Conn. string | `bounded_staleness_without_bound`, `unknown_read_consistency`, `max_retries_out_of_range` | not applicable (options unknown) | rejected | validated |
| Conn. string | `x509_with_password` vs a user without password | any user rejected with X509 | only a password is rejected (same as Java) | aligned with Java |
| Retry policy (DN2) | `retry.yaml` R1–R6, 33 scenarios | `RetryReads`, `RetryWrites`, `MaxRetries` parsed and validated; only the one re-authentication on RGN-4005 automatic | retry on `ErrorDetail.retryable` (or the transport fallback) with full-jitter backoff, reads/writes gated by the settings, same `rgn-request-id`, nothing alone inside a transaction, no retry of `GetMore` or of a stream that delivered a batch, never past the caller's deadline; `WithTransactionAsync` per transactions.md §5 | `OperationExecutor` retry loop and `TransactionRunner` (PD-097); all scenarios pass on the in-process fake server (`runRetryScenarios`, TC-DRV-NET-016) |
| Read consistency / write concern (DN2) | dotnet-driver.md §3, §6 | `ReadConsistency`, `MaxStaleness`, `WriteConcern` parsed and validated but not sent | sent on every data-plane request whose proto has the field | `ReadConsistency` on Get / Execute (finds, RGQL), `WriteConcern` on Insert / Replace / Update / Upsert / Delete / BulkWrite / Execute; per-operation overrides; not per operation inside a transaction (`Begin` carries the write concern, and the consistency of a read-only transaction); TC-DRV-NET-017 |
| `ReadConsistency` per operation (DN2) | dotnet-driver.md §6 `ReadConsistency.BoundedStaleness(TimeSpan)` | enum plus `MaxStaleness` in the settings only | per-operation override | `ReadOperationOptions.ReadConsistency` + `.MaxStaleness` (enum + bound as the settings, the connection string, Java and the proto); spec §6 example updated (PD-095) |
| `connectTimeout` (DN2) | PD-081 | enforced, untested | enforced and tested | `tc_drv_net_017_connect_timeout_is_enforced` (a listener that never answers the TLS handshake); the test found that Grpc.Net reports the expired connect timeout as `CANCELLED` (then mapped to RGN-5001 Server), now RGN-3002 Unavailable like any connection failure |
| Packaging and robustness (DNP) | dotnet-driver.md §2, §11, TC-DRV-NET-026…029, AC-DRV-001 | assemblies not strong-named; package without readme, symbols or validation; no sample; reconnect, stress and AOT untested | strong-named, deterministic, SourceLink, validated package, samples compile in CI, AOT publish | every assembly strong-named with the checked-in `Rustegon.snk` (PD-117); package readme, repository metadata, `.snupkg`, `EnablePackageValidation`, versioning rule (PD-118); `samples/Rustegon.Driver.Sample` built with the solution and published with Native AOT and warnings as errors, then run against `rustegond` (`tc_drv_net_026`); pack + contents check (`tc_drv_net_027`); 1000 concurrent operations (`tc_drv_net_028`); node killed and restarted on the same data directory and port under the same client (`tc_drv_net_029`, reconnect backoff capped at 5 s, a retry avoids the failed channel, PD-119); a commit reply lost after sending is RGN-2006 `CommitOutcomeUnknownException`, never a retryable RGN-3002, so `WithTransactionAsync` cannot apply a transaction twice (PD-119 (4), same rule as Java PD-122) |
| Object mapping (DN3) | dotnet-driver.md §7, TC-DRV-NET-021…025 | `IRustegonCollection<T>` mapped `RDocument` only (`NotSupportedException` for other `T`); builders took string paths only | `[RustegonDocument]` POCOs/records with a source-generated codec, opt-in reflection fallback, `Filter.Eq(x => x.A.B, v)` | generator `Rustegon.Driver.Generators` (packed as an analyzer), `RDocCodecRegistry` resolved when a handle is created, attributes `RgnId`/`RgnField`/`RgnIgnore`/`RgnRev`/`RgnVector`/`RgnGeoPoint`/`RgnCounter`/`RgnDiscriminator`, `FieldPath.Of` and generic filter overloads (rules: PD-108, PD-109, PD-110) |

Codec: all 185 vectors of `codec/{values,documents,invalid}.yaml` passed on the first run, including
the rejection codes of `invalid.yaml`; no codec divergence.

### 4.2 Open (legitimately deferred or .NET-specific)

| Item | Observed | Expected (spec) | Rationale | Until |
|---|---|---|---|---|
| `MaxConcurrentStreamsPerConnection` | not a setting | dotnet-driver.md §3 | not in `connstring.yaml`; HTTP/2 stream limits come from the server's SETTINGS frame, and `SocketsHttpHandler` (`EnableMultipleHttp2Connections`) opens another connection of the same channel when they are reached: 1000 concurrent calls over the 2 default channels complete without errors (`tc_drv_net_028`) | add only if a server-independent client cap is needed |
| Node health | power-of-two choices on in-flight calls only; no ejection of unhealthy endpoints, no topology refresh | dotnet-driver.md §3 (ejection 5–60 s, refresh every 60 s) | multi-endpoint selection and topology discovery are deferred (§1, PD-069) | M5 |
| Observability | no `ILogger`, `ActivitySource` or `Meter` | dotnet-driver.md §9 | needs `Microsoft.Extensions.Logging.Abstractions` and `System.Diagnostics.DiagnosticSource` (§2 dependencies), out of the packaging lane's scope; no secrets are logged because nothing is logged | observability work after M11 wave 3 |
| Package signing | strong-named (PD-117), but the `.nupkg` and the DLLs carry no author / Authenticode signature | dotnet-driver.md §2 "signed" | needs the project's code-signing certificate, which does not exist yet; `dotnet nuget sign` is a release step outside the build (PD-118) | first NuGet release (M14) |
| Compatibility matrix (TC-DRV-NET-030) | no protocol-version check on connect; no N−2..N+1 test matrix | protocol.md §9, dotnet-driver.md §11 | only one server version and protocol `1.0` exist; an eager `GetServerInfo` would change the call counts of the shared `retry.yaml` scenarios, so both drivers add it together (PD-119) | second server version / protocol minor |
| ~~Transaction across a node restart (server)~~ **Resolved (PD-121 option (a'))** | Was: `Commit` of a transaction begun before the node was killed failed with RGN-1030 (not retryable). Now the server reads the transaction's persisted record: `Status` is `COMMITTING` until `txn.liveness_timeout` has passed since its last write, then `ABORTED` `coordinator_lost`, and `Commit` fails with retryable RGN-2002 `coordinator_lost` | transactions.md §3 (coordinator restart) | `tc_drv_net_029` asserts it (polls `ResolveAsync` to `Aborted`, never `Committed`; `Commit` → `TransactionAbortedException` 2002 `coordinator_lost`, retryable); a transaction without a record (e.g. committed) stays RGN-1030, never ABORTED | done |
| `QueryAsync` parameters (PD-096) | `RDocument? parameters` (`new RDocument { { "s", "paid" } }`) | `object? parameters` with anonymous objects (model.yaml, dotnet-driver.md §4) | binding an arbitrary object needs reflection, which the trimming/AOT analyzers of the package refuse; spec §4 example updated | object mapping (TC-DRV-NET-021…025, source-generated codecs) |
| Expression builder coverage (DN3) | generic overloads `Filter.Eq/Ne/Gt/Gte/Lt/Lte/In/Nin/Exists<T>(x => x.A.B, value)`; the other filters, `Sort`, `Update` and `Projection` take `FieldPath.Of<T>(x => …)`; values stay `RDocValue` (an enum is passed by name, e.g. `nameof(Status.Paid)`); indexes and dictionary keys must be constants | `Filter.Eq(x => x.A.B, v)` (dotnet-driver.md §7), a LINQ-like builder | the subset covers member paths and comparisons with the same AST as string paths (`tc_drv_net_022_expression_filters_build_the_same_ast_as_string_paths`); typed values need the member converter at build time | M11 wave 3 or LINQ (PD-069) |
| Codec path (DN3) | generated and reflection codecs map objects to an `RDocument`, then the RDoc writer encodes it (and the reverse on reads) | dotnet-driver.md §7 "span-based, zero-copy" codec | one intermediate tree per document; the byte format is unchanged, so streaming codecs can replace it without an API change | performance work (M14) |
| Polymorphism scope (DN3, PD-110) | abstract or concrete base **classes**; derived types found in the same compilation (generator) / assembly (reflection) | java-driver.md §5: sealed interfaces with a discriminator | C# has no sealed interfaces; a base class plus `[RgnDiscriminator]` on the derived types is the closest shape | PD-110 decision |
| Reflection fallback (DN3) | process-wide opt-in `RDocCodecRegistry.EnableReflectionFallback()` (`RequiresUnreferencedCode`, `RequiresDynamicCode`); unlike the generator it also maps nested types without `[RustegonDocument]` | "fallback reflection-based codec (opt-in, not trimming-safe)" | same rules as the generator otherwise (byte-identity tests, TC-DRV-NET-025) | permanent |
| Document types | `IRustegonCollection<T>` keeps `where T : class`: top-level documents are classes or records; structs map as nested documents only | dotnet-driver.md §7 "POCO/records" | the R1 handle API is constrained to reference types (`FindByIdAsync` returns `T?`) | permanent |
| Client TLS versions | `SslClientAuthenticationOptions` without `EnabledSslProtocols`: the OS defaults (TLS 1.2 and 1.3) are offered | — | the server's TLS 1.3-only default still applies; restricting the client is a hardening choice | M11 wave 3 (lane DNP) |

### 4.3 Suite corrections found by the .NET runner (DN2)

The first run of every test file (`tc_drv_net_020_conformance_suite`, 107 tests) found three
problems in the shared files, fixed there (the server and the specifications were right):
`auth.yaml` granted `readWrite@${database}`, a role that does not exist (the built-in role is
`read_write`; also README §5 and `schema/test.schema.json`); `TC-DRV-CONF-CRUD-009` expected
RGN-1030 for an insert into a missing collection, but FR-SCH-001 creates collections implicitly
(`implicitCollectionCreation` defaults to true), so the test now asserts the implicit creation;
README §5 required equal lengths for `match: subset` lists, which `TC-DRV-CONF-SCHEMA-001`
(`listDatabaseNames`, which also sees the databases of other files) cannot meet: an unordered
subset list may now hold extra rows. The test node also needs its authentication rate limits off
(PD-098).

## 5. Java driver (lanes DJ2, DJ3, DJP)

Derived on 2026-11-12 from the client API work of wave 2 (TC-DRV-JAVA-011…020): the whole shared
suite runs through the Java runner (`ConformanceSuiteTest`: 107 conformance tests against
`rustegond`, every `r1` operation of `model.yaml` covered; `retry.yaml` on the in-process fake
server; `ast/*.json`), reviewed against java-driver.md §2–§6 and dotnet-driver.md §1, §4, §8.

### 5.1 Fixed (the driver now follows the suite)

| Area | Item | Before (DJ1) | Expected | Fix |
|---|---|---|---|---|
| Transport | `connectTimeout` | parsed, gRPC default 20 s applied | enforced (PD-081) | per-call wait for the channel connection in node selection, RGN-3002 after the timeout (§2) |
| Retries | `retryReads`, `retryWrites`, `maxRetries` | parsed only; RGN-4005 re-authentication only | `retry.yaml` R1–R6 | retry policy in `Operations` (full jitter 10 ms ×2 cap 1 s, `retry_after_ms`, same request id, no retry in transactions, after a delivered batch or on the caller's deadline); `withTransaction` per transactions.md §5; all scenarios pass on the fake server |
| Settings | read consistency, max staleness, write concern | parsed, not sent | sent on every data-plane request that has the field | `Get`/`Execute` consistency, `WriteOptions`/`ExecOptions` concern, `Begin` commit concern (and consistency for read-only transactions); not inside transactions |
| Credentials | model members `RustegonCredential.apiKey(String)`, `x509(KeyManager)` | `apiKey(char[])`, `x509()` (certificate in `TlsSettings`) only | as in `model.yaml` | overloads added; the existing forms stay |
| Client API | data plane, cursors, RGQL, bulk, schema, sessions, transactions | ping, server info, password change only | `model.yaml` `r1` operations | implemented (synchronous API, §1) |
| Mapping (DJ3) | document types | `collection(String, Class<T>)` accepted `RDocument` only | records, POJOs, sealed hierarchies (java-driver.md §5) | `io.rustegon.driver.mapping`: annotations, `Mapper` (MethodHandles), `rustegon-processor` generated codecs and `Order_` metamodel, used by `collection`, `Transaction.collection` and `query(..., Class<T>)`; rules PD-111…PD-113; TC-DRV-JAVA-021…025 |
| Transactions (DJP) | commit failing in transport | `Commit` without `ErrorDetail` (node killed, connection reset) → retryable `UnavailableException`; `withTransaction` rolled back and re-ran the callback although the commit may have applied | unknown outcome → RGN-2006, resolved through `Status` (transaction-management.md §7, §10; transactions.md §5) | `Operations.commit` reports it as `CommitOutcomeUnknownException` (PD-122); TC-DRV-JAVA-030 |
| Packaging (DJP) | driver jar | carried the option-injected copies of `proto/rustegon/v1/*.proto` | only the driver's classes (java-driver.md §1) | excluded from the jar; checked by `validateCentralBundle` (TC-DRV-JAVA-027) |

### 5.2 Open (by design or deferred)

| Item | Java | .NET / spec | Rationale | Until |
|---|---|---|---|---|
| Per-operation overrides (PD-100) | handle derivation: `withReadConsistency(level[, maxStaleness])`, `withWriteConcern`, `withTimeout`, `withSession` on `RustegonDatabase` / `RustegonCollection`; no `InsertOptions` / `FindOptions` (they would hold nothing else in R1) | option objects (`new FindOptions { ReadConsistency = … }`, dotnet-driver.md §6) | one mechanism for every operation, Java idiom; option fields can be added additively | review at M11 R1 exit (PD-100) |
| Jackson module | none | optional module for Jackson annotations (java-driver.md §5) | out of scope of lane DJ3; it would add a Jackson dependency to an optional artifact | M11-R2 |
| Mapping fallback | the `MethodHandles` mapper is used automatically when no generated codec exists | .NET: reflection codec is opt-in, the source generator is the default (dotnet-driver.md §7) | java-driver.md §5 makes the MethodHandles mapper part of the built-in mapper; both write identical bytes (TC-DRV-JAVA-022) | — |
| Type-safe paths | metamodel `Order_` holds the top-level field names as `String` constants (`Filters.eq(Order_.status, "paid")`); nested paths are written by hand (`"origin.city"`) | .NET expression filters (`Filter.Eq(x => x.A.B, v)`) | the Java spec asks only for the optional `Order_` metamodel; typed nested paths can be added to the processor without API changes | — |
| Mapping rules not in the spec | nulls, unknown fields, `id` convention, missing primitives, datetime offsets, discriminator placement, BigDecimal precision (PD-111); vector/geo/counter representation (PD-112); processor packaging, JPMS (PD-113) | dotnet-driver.md §7 silent as well | provisional choices, mirrored by the .NET mapper (DN3, PD-108…PD-110) except the overridable discriminator field name (§2); both drivers pass the shared `mapping/vectors.yaml` (PD-116) | M11 R1 exit |
| Node selection | round robin over the channels of the endpoints; no in-flight load (power of two choices), no ejection, no topology refresh | dotnet-driver.md §3 | multi-endpoint selection is deferred (`Behavior.MultiEndpoint`, §1); R1 servers are single nodes | M5 |
| Transaction heartbeat | `Heartbeat` every `heartbeat_interval_ms` while the transaction is open, also when it is busy | "while idle" (model `Behavior.TransactionHeartbeat`) | simpler and harmless (one small call per interval); TC-DRV-CONF-TXN-011 passes | — |
| Observability | SLF4J debug logs only (no secrets); no OpenTelemetry module, no JMX pool MBean | java-driver.md §8 | packaging and observability modules are later M11 work | M11-R2 |
| Shaded artifact (DJP) | no extra shaded (`-all`) jar: Netty is relocated inside `grpc-netty-shaded`; gRPC, protobuf, guava and slf4j stay ordinary dependencies | java-driver.md §1 "shaded where needed" | relocating gRPC/protobuf needs the Shadow plugin (not allowed in R1) and would duplicate them for users who also use gRPC; no conflict observed (PD-120) | M11 R1 exit (PD-120) |
| Publishing (DJP) | `maven-publish` into `build/repo` + `validateCentralBundle`; signing only with a configured key; no Central Portal upload task | java-driver.md §1 "signed artifacts (GPG)" | no key and no Central account on the build host; artifacts are never signed with a throwaway key (PD-120) | first release (PD-016, PD-120) |
| ~~Unknown commit after a node restart (DJP)~~ **Resolved (PD-121 option (a'))** | Was: `resolve()` threw RGN-1030. Now `resolve()` returns `UNKNOWN` (`COMMITTING`) until the server's `txn.liveness_timeout` has passed since the transaction's last write, then `ABORTED` (`coordinator_lost`), so `withTransaction` re-runs it; never `COMMITTED` for an uncommitted transaction | protocol.md §3 / transactions.md §3 (coordinator restart) | `tc_drv_java_030` polls `resolve()` to `ABORTED`; an id without a persisted record (committed, rolled back, never wrote) stays RGN-1030 | done |
| Commit transport failure (DJP) | RGN-2006 synthesized by the driver (PD-122) | .NET: not checked by lane DJP; `retry.yaml` has no transport-failure scenario for `Commit` | safety (no double apply); the suite and .NET should follow | M11 R1 exit (PD-122) |

## 6. Cross-driver consistency (lane DX, M11 wave 3)

Closed on 2026-11-12 (PD-114…PD-116):

| Item | Before | Now |
|---|---|---|
| AC-DRV-003 identical results | never compared; Java wrote one results file (JDK 25) | `driver_results.rs` compares .NET, Java JDK 21 and Java JDK 25 test by test (`scripts/ci-local.sh` drivers step): 107 of 107 tests identical, 109 of 109 `r1` operations covered. The 26 first differences were runner normalisation gaps, fixed in README §6 and both runners (PD-114) |
| Operation timeout (retry.yaml R8) | Java: a fresh deadline per attempt (an operation could last `(maxRetries + 1) ×` the timeout); .NET: one deadline | both: one deadline for the whole operation, no retry once the backoff would pass it (`operation_timeout_bounds_all_attempts`) |
| Retry class of unpinned operations (PD-097, PD-101) | same choice in both drivers, untested | retry.yaml R7 with scenarios (listings, RGQL text, DDL, `Begin`); the Java fake server serves SchemaService |
| Test-node rate limits (PD-098) | off in the .NET fixture only; the Java typed CRUD test waited out RGN-4003 | off in both fixtures (README §5); the wait is gone |
| Connection-string extensions | `tlsServerName`, `tlsCertificateFile`, `tlsKeyFile` outside the grammar; `authMechanism=APIKEY`/`apiKey` .NET only; .NET accepted a certificate without its key | all in `connstring.yaml` (4 valid, 9 invalid cases); Java parses `apiKey` (kept out of `options()`, redacted by `toString()`); certificate and key both or neither in both |
| Object mapping across drivers | each mapper tested against its own expectations | `mapping/vectors.yaml` (24 vectors) passes through both codecs of each driver (PD-116) |

## 7. Node.js driver (lane NJ, FR-DRV-004, DEC-014; node-driver.md)

Same model, defaults, retry parameters, connection-string grammar, error mapping and conformance
results as .NET and Java (TC-DRV-CONF-* 107/107, identical observations). Differences that the
language imposes or that the driver chose:

| Item | Node.js | Justification |
|---|---|---|
| Naming | `camelCase` methods (as Java); error classes end in `Error` (`DuplicateKeyError` for `DuplicateKeyException`); `InvalidArgumentError` is a `TypeError` | JavaScript conventions; the class ids of `errors-map.yaml` are unchanged |
| Asynchronous API only | Promises, `AsyncIterable` cursors, `AbortSignal` cancellation, `await using` | Node has no blocking I/O model to offer (same choice as .NET) |
| Timeouts | Options in milliseconds (`connectTimeoutMs`, `operationTimeoutMs`, `timeoutMs`, `maxRetryTimeMs`, `maxStalenessMs`) | No duration type in JavaScript; the connection-string keys are the shared ones |
| Value model (PD-160) | int64 is `bigint`, every `number` is float64; documents are plain objects | Exact round trip: a JavaScript `number` cannot hold every int64 |
| Field order | Integer-like field names (`"1"`, `"42"`) are enumerated first by JavaScript, so such fields are re-ordered on write | Language property of plain objects; documented in node-driver.md §7, no conformance vector depends on it |
| Mapping (PD-162) | `model({...})` with typed field builders instead of annotations/attributes + generator | TypeScript decorators carry no type information at run time; one declaration gives codec and static type |
| Settings object | One `ClientOptions` object (credential fields flat: `user`, `password`, `apiKey`, `authMechanism`) instead of a settings builder with a credential object | The options object of DEC-014; options override the connection string so the password can stay out of it |
| Observability | No logging/OpenTelemetry hooks in this version | Deferred like `.OpenTelemetry` / `-otel` (PD-069) |
| Release scope | Not published (`private: true`); packaging tests TC-DRV-NODE-026, 028…030 deferred | DEC-014: Node ships in a later release than R1 |
## 8. Python driver (lane PY, DEC-014, FR-DRV-006)

The Python driver (python-driver.md) passes the whole suite (107/107) with observations and
outcomes identical to .NET and Java JDK 21/25 (README §6 comparison). Language-level
differences:

| Item | Python | Justification |
|---|---|---|
| API style (PD-170) | asyncio API (`AsyncRustegonClient`, primary) and a blocking facade (`RustegonClient`) with the same methods | Python services use asyncio, scripts and notebooks do not; one core, no duplicated logic. |
| Per-operation overrides (PD-172) | `with_options(...)` on database and collection handles instead of options objects per call | Python keyword-argument conventions; the same settings and one deadline per operation. |
| `Argument` / `InvalidState` class ids | `ValueError`/`TypeError` / `RuntimeError`; `RDocError` is both `RustegonClientException` (RGN-100x) and `ValueError` | Python conventions; the suite's class ids map to them in the runner. |
| Timeout exception | `RustegonTimeoutException` (as Java) | `TimeoutError` is a Python built-in. |
| Password parameters | `str` | Python strings cannot be zeroed either (as .NET). |
| Object mapping (PD-174) | dataclasses with `typing.Annotated` markers; no `int32`/`float32` members, so `mapping/vectors.yaml` `item_int_overflow` does not apply (an `int` member takes any int64) | The language has one integer and one float type. |
| Filter operators | `&`, `\|`, `~` (as .NET) plus `Filter.and_/or_/not_` | `and`, `or`, `not` are keywords. |
| Node selection | round robin over `connections_per_endpoint` channels; no ejection/backoff or topology refresh | R1 nodes are single (`Behavior.MultiEndpoint` is deferred to M5 for every driver); added with M5. |
| Observability | `logging` only; no OpenTelemetry spans/metrics | Deferred like the optional OTel modules of .NET/Java; no extra dependency in R1. |
| TLS default (ADR-034) | `tls` off by default; TLS options or X509 turn it on; `tls=false` with them is an error | Same rule as .NET, Java and Node.js; checked against `connstring.yaml` directly. |
## 9. Go driver (lane GO, DEC-014)

Go member names follow Go conventions (`FindByIdAsync` ↔ `FindByID`, `ListDatabaseNamesAsync` ↔
`ListDatabaseNames`, `WithTransactionAsync` ↔ `WithTransaction`); every I/O method takes a
`context.Context`. Conformance: 107 of 107 tests passed, observations and outcomes identical to .NET
and Java JDK 21/25 (AC-DRV-003). Divergences (PD-190 unless noted):

| Item | Go | Justification | Until |
|---|---|---|---|
| Exception hierarchy | one `*rustegon.Error` type with an `ErrorClass` (the errors-map.yaml class id); `errors.Is(err, ClassClient)` matches descendants; `Argument` = `ErrArgument`, `InvalidState` = `ErrClosed` (sentinels matched with `errors.Is`) | Go has no class hierarchy; this keeps the same ids and the same "instance of" semantics | — |
| Typed collections / object mapping | collections are untyped (`rdoc.Document`); no struct mapping, no `mapping/vectors.yaml` runner | not needed for the conformance suite; struct tags + generics later | a later Go release |
| Manual-mode commit resolution | `Transaction.Resolve(ctx)` instead of a resolver attached to the exception | Go errors carry no behaviour by convention; same `TransactionService.Status` call | — |
| Per-operation options | variadic `OpOption` values shared by every operation (`IfRev`, `Timeout`, `InSession`, …) instead of one options class per operation | idiomatic Go, smaller API; inapplicable options are ignored | — |
| Synchronous only | no separate async API | goroutines are the concurrency model | — |
| Observability | `*slog.Logger` only; no `traceparent`, spans or metrics yet | no OpenTelemetry dependency in R1 | a later Go release |
| Counter values | `rdoc.EncodeDocument` refuses `rdoc.Counter` (decode only); .NET/Java writers encode it | data-model.md §2 "never accepted as input"; the spec should say whether the encoder must refuse it | data-model.md clarification |
| ~~TLS with `rustegon init` certificates (PD-193)~~ **Resolved (ADR-035)** | Was: the handshake failed because Go's `crypto/x509` cannot parse the node-role EKU OID `2.25.<uuid>`, and the test fixture imported a PKI generated in Go. Now the node role is the URI SAN `urn:rustegon:role:node` and the fixture uses `rustegon init --tls --client-user` certificates | — | — |

## 10. Rust driver (lane RS, FR-DRV-005, DEC-014; rust-driver.md)

Rust member names follow Rust conventions (`FindByIdAsync` ↔ `find_by_id`,
`ListDatabaseNamesAsync` ↔ `list_database_names`, `WithTransactionAsync` ↔ `with_transaction`);
every I/O method is `async` (Tokio). Conformance: 107 of 107 tests passed, observations and
outcomes identical to .NET, Java JDK 21, Go, Python and Node.js (AC-DRV-003, 109 of 109 `r1`
operations covered). Divergences (PD-181/PD-182 unless noted):

| Item | Rust | Justification | Until |
|---|---|---|---|
| Exception hierarchy | one `rustegon::Error` enum: `Rustegon(Box<RustegonError>)` carries the errors-map.yaml `ErrorClass` (`err.is(ErrorClass::Client)` matches descendants), `Argument` and `InvalidState` are variants, `Application` wraps a `with_transaction` callback's own error | Rust has no class hierarchy; same ids and "instance of" semantics | — |
| Typed collections / object mapping | collections are untyped (`Document`); no serde mapping, no `mapping/vectors.yaml` runner | not needed for the conformance suite; a serde layer adds API surface (PD-182) | a later Rust release |
| Manual-mode commit resolution | `Transaction::resolve()` instead of a resolver attached to the exception | errors are plain data in Rust; same `TransactionService.Status` call (as Go) | — |
| Per-operation options | awaitable `Action` builders with one option set shared by every operation (`.if_rev(…)`, `.timeout(…)`, `.session(&s)`, …) instead of one options class per operation | idiomatic Rust (`IntoFuture`); inapplicable options are ignored | — |
| `with_transaction` callback | receives an owned (cheap-clone) `Transaction` and returns `rustegon::Result<T>`; application errors travel as `Error::Application` | a callback borrowing the transaction needs higher-ranked boxed futures | — |
| Cancellation | dropping the future cancels the call (no cancellation error type) | Rust's async model; errors-map.yaml leaves cancellation to the language | — |
| Cursor | `next().await` / `to_list()`; not a `futures::Stream` | no `futures` dependency in R1 (PD-182) | a later Rust release |
| Observability | user agent and `ClientInfo` only; no `tracing`, `traceparent`, spans or metrics yet | no OpenTelemetry dependency in R1 (PD-182) | a later Rust release |
| Packaging | separate cargo workspace in `drivers/rust/`, codec copied from `rustegon-doc`, stubs compiled from `proto/` in `build.rs`; `publish = false` until the `.proto` files are vendored into the package (PD-180) | a client crate must not depend on server crates | first driver release |
| TLS with `rustegon init` certificates (ADR-035) | works with the node role as URI SAN `urn:rustegon:role:node`; the fixture uses `init --tls --client-user` certificates as issued (also worked with the earlier EKU OID: rustls compares OIDs as DER bytes) | — | — |
