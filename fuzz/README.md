# Fuzzing: RGQL parser (AC-QL-002) and security parsers (TC-SEC-010), NFR-SEC-004

`cargo-fuzz` (libFuzzer) targets for the RGQL front end of `rustegon-query`. This directory is
its own Cargo workspace (empty `[workspace]` in `Cargo.toml`): the main workspace build, its
lockfile and `cargo deny check` on stable never see it.

| Target | Input | Property (panic = finding) |
|---|---|---|
| `parse_statement` | arbitrary bytes | `parse_statement` never panics, overflows the stack or hangs; an accepted statement round-trips (`parse(print(ast)) == ast`, canonical text is a fixed point, structured JSON decodes to the same AST or is `RGN-1013`) |
| `parse_script` | arbitrary bytes | same for `parse_script`, plus `parse_script(print_script(s)) == s` |
| `roundtrip` | arbitrary bytes | all of the above plus `parse_expr` → `print_expr` → `parse_expr` equality |
| `ast_json` | arbitrary bytes | `Statement::from_json` never panics; an accepted AST prints to text that parses back to it and re-encodes to an equal AST |

The checks live in `crates/rustegon-query/tests/common/fuzz_check.rs` and are shared with the
stable test `crates/rustegon-query/tests/tc_ql_002_fuzz_smoke.rs`, which runs them in every
`cargo nextest run` (no nightly needed) on the golden corpora, on byte-mutated seeds, on random
bytes and on every reproducer committed under `regressions/<target>/`.

## Security parser targets (TC-SEC-010, PD-060)

| Target | Input | Property besides "no panic, no hang" |
|---|---|---|
| `scram_server` | mode byte, client-first `\n` client-final | no SCRAM proof verifies against random keys; server-first has `r=`, `s=`, `i=` |
| `request_headers` | method byte, header lines `name-byte value` | gRPC credentials are exactly `authorization`; on REST a cookie-authenticated unsafe request is admitted only with the session's CSRF token; ids are passed through; `If-Match` yields a clean revision |
| `rest_body` | mode byte + JSON body / filter `\n` sort / path id | accepted documents and values round-trip through canonical extended JSON (and RDoc); a list `filter`/`sort` always becomes exactly one query |
| `continuation_token` | mode byte + sealed bytes or base64url text | a token opens for its owner only; seal/open round-trips |
| `authorization` | `authorization` header value | only the stored session token and API key authenticate |
| `x509_identity` | certificate DER | node role read by `rustegon-security` (x509-cert) and `rustegon-net` (x509-parser) agree; users are `x509:…` |

The oracles live in `crates/rustegon-server/src/fuzzing.rs` (compiled for tests and with the
`fuzzing` feature, which `fuzz/Cargo.toml` enables) and run on stable in
`tc_sec_010_fuzz_smoke_*` (`RGN_SEC_FUZZ_CASES`, default 1500). Seed the corpora with
`RGN_SEC_FUZZ_SEED_DIR="$PWD/fuzz/corpus" cargo nextest run -p rustegon-server -E 'test(tc_sec_010_fuzz_smoke)'`,
then e.g. `cargo +nightly fuzz run x509_identity corpus/x509_identity -- -max_total_time=300 -timeout=10 -max_len=8192`.
On a violated oracle the input is saved as `artifacts/<target>/violation-<hash>` before the
panic (on Windows the panic aborts with `STATUS_STACK_BUFFER_OVERRUN`, bypassing libFuzzer's own
artifact writer).

## Requirements
- nightly toolchain (`rustup toolchain install nightly`) and `cargo install cargo-fuzz`;
- Windows/MSVC: libFuzzer builds with AddressSanitizer, whose runtime DLL must be on `PATH`, e.g.
  `C:\Program Files\Microsoft Visual Studio\<ver>\<edition>\VC\Tools\MSVC\<msvc>\bin\Hostx64\x64`
  (`clang_rt.asan_dynamic-x86_64.dll`; otherwise the target exits with `STATUS_DLL_NOT_FOUND`).
  Linux needs nothing extra.

## Seed corpus
The corpus directories (`corpus/<target>/`) are not committed. Seed them from the golden files
(RGQL inputs and recorded structured JSON, ~390 files):

```bash
RGQL_FUZZ_SEED_DIR="$PWD/fuzz/corpus/seed" \
  cargo nextest run -p rustegon-query --test tc_ql_002_fuzz_smoke tc_ql_002_fuzz_seed_corpus
for t in parse_statement parse_script roundtrip ast_json; do
  mkdir -p fuzz/corpus/$t && cp fuzz/corpus/seed/* fuzz/corpus/$t/
done
```

## Short run (smoke)
```bash
cd fuzz
cargo +nightly fuzz run roundtrip -- -max_total_time=150 -timeout=10 -max_len=4096
```

## Acceptance campaign (AC-QL-002: ≥ 1 CPU-hour per release candidate, zero panics/timeouts)
One CPU-hour in total, split over the targets (the parser targets dominate the risk):

```bash
cd fuzz
for t in roundtrip parse_script parse_statement ast_json; do
  cargo +nightly fuzz run $t -- -max_total_time=900 -timeout=10 -max_len=65536 \
      -rss_limit_mb=4096 -print_final_stats=1 2>&1 | tee fuzz-$t.log
done
```

(4 × 900 s = 3600 s on one core; with `-fork=N` / `-jobs=N` the wall time divides by N, the
CPU time does not.) Record per target the duration, `stat::number_of_executed_units`, corpus size
and findings in the release notes / PROGRESS.md; never quote numbers that were not measured.

## Handling a finding
1. Reproduce: `cargo +nightly fuzz run <target> artifacts/<target>/crash-…`; minimise with
   `cargo +nightly fuzz tmin <target> artifacts/<target>/crash-…`.
2. Fix the bug in `rustegon-query`.
3. Commit the minimised input as `regressions/<target>/<short-name>`: the stable
   `tc_ql_002_fuzz_regressions_stay_fixed` test replays it on every CI run.

Timeouts (`-timeout=10`) and out-of-memory reports are findings too: the parser must be linear
in the input and bounded by the limits of query-language.md §3.1 (`RGN-1013`).
