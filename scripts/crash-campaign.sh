#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Long randomized crash campaign (TC-STO-002, M1 exit: 24 h of randomized crash simulation without
# invariant violation, development-phases.md; may be split into runs over disjoint workloads,
# DEC-013). Runs the full-engine crash test `tc_sto_002_engine_crash_at_every_operation` in
# release mode as JOBS parallel processes until HOURS have elapsed. Job j runs workload blocks
# START+j, START+j+JOBS, ...; block b covers workloads [b*BLOCK, (b+1)*BLOCK) with SEEDS crash
# seeds per crash point and mode, so within a run every workload number is run once, and runs
# started with --after cover workloads no earlier run touched. A failure is reproducible with:
#   RUSTEGON_CRASH_WORKLOAD_START=<start> RUSTEGON_CRASH_WORKLOADS=<count> RUSTEGON_CRASH_SEEDS=<seeds> \
#     cargo test --release -p rustegon-storage --test engine tc_sto_002_engine_crash_at_every_operation
# A block in progress at the deadline is finished, so the run ends at most one block late. If a
# run is interrupted, its completed blocks (job-*.tsv) still count.
#
# Usage:
#   scripts/crash-campaign.sh [--hours H] [--jobs N] [--block W] [--seeds S] [--out DIR]
#                             [--start-block B | --after DIR...]
#   scripts/crash-campaign.sh [--min-workloads N] [--min-hours H] --summarize DIR...
#     cumulative result over several runs; exits 1 on a failure, a repeated block, or totals below
#     the thresholds (M1 exit, DEC-013: --min-workloads 25000 --min-hours 24)
# job-*.tsv columns: first workload, workloads, seeds, seconds, status, end epoch.
# Exit status: 0 if every block passed, 1 otherwise. Summary in DIR/summary.txt.
set -uo pipefail
cd "$(dirname "$0")/.."

# Highest block index recorded in the given run directories, -1 if none; fails on mixed sizes.
last_block() {
  local max=-1 dir size
  for dir in "$@"; do
    size=$(sed -n 's/.* block=\([0-9]*\) .*/\1/p' "$dir/summary.txt" 2>/dev/null | head -1)
    [[ -z "$size" ]] && { echo "no summary.txt in $dir" >&2; return 1; }
    [[ "$size" != "$block" ]] && { echo "$dir used --block $size, not $block" >&2; return 1; }
    local m
    m=$(cat "$dir"/job-*.tsv 2>/dev/null | awk -v w="$block" 'BEGIN{m=-1} {b=$1/w; if (b>m) m=b} END{print m}')
    (( m > max )) && max=$m
  done
  echo "$max"
}

summarize() {
  local dir all
  all=$(for dir in "$@"; do cat "$dir"/job-*.tsv 2>/dev/null; done)
  local dup
  dup=$(awk '{print $1}' <<<"$all" | sort -n | uniq -d | head -1)
  local wall=0 d started ended
  for dir in "$@"; do
    started=$(sed -n 's/^started_epoch=//p' "$dir/summary.txt")
    ended=$(cat "$dir"/job-*.tsv 2>/dev/null | awk 'BEGIN{m=0} {if ($6>m) m=$6} END{print m}')
    (( ended > started )) && wall=$(( wall + ended - started ))
    echo "$dir: $(sed -n 's/^commit=\([^ ]*\).*/commit \1/p' "$dir/summary.txt"), $(cat "$dir"/job-*.tsv 2>/dev/null | wc -l) blocks, $(awk -v s="$started" -v e="$ended" 'BEGIN{printf "%.2f", (e-s)/3600}') h"
  done
  echo "total: $(wc -l <<<"$all") blocks, $(awk '{n+=$2} END{print n+0}' <<<"$all") workloads, $(grep -c FAIL <<<"$all") failed, $(awk -v w="$wall" 'BEGIN{printf "%.2f", w/3600}') h of runs"
  if [[ -n "$dup" ]]; then echo "OVERLAP: workload block starting at $dup ran more than once"; return 1; fi
  grep -q FAIL <<<"$all" && return 1
  local workloads
  workloads=$(awk '{n+=$2} END{print n+0}' <<<"$all")
  if (( workloads < min_workloads )); then
    echo "NOT MET: $workloads workloads < required $min_workloads"; return 1
  fi
  if (( wall < min_hours * 3600 )); then
    echo "NOT MET: $(awk -v w="$wall" 'BEGIN{printf "%.2f", w/3600}') h of runs < required $min_hours h"; return 1
  fi
  echo "MET: >= $min_hours h over disjoint workloads, >= $min_workloads workloads, 0 failures"
  return 0
}

hours=24 jobs=$(( $(nproc 2>/dev/null || echo 4) - 2 )) block=4 seeds=4 out="" start_block=0
after=() summarize_dirs=() min_workloads=0 min_hours=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hours) hours="$2"; shift 2 ;;
    --jobs) jobs="$2"; shift 2 ;;
    --block) block="$2"; shift 2 ;;
    --seeds) seeds="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --start-block) start_block="$2"; shift 2 ;;
    --after) shift; while [[ $# -gt 0 && $1 != --* ]]; do after+=("$1"); shift; done ;;
    --min-workloads) min_workloads="$2"; shift 2 ;;
    --min-hours) min_hours="$2"; shift 2 ;;
    --summarize) shift; while [[ $# -gt 0 && $1 != --* ]]; do summarize_dirs+=("$1"); shift; done ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if (( ${#summarize_dirs[@]} > 0 )); then summarize "${summarize_dirs[@]}"; exit $?; fi
(( jobs < 1 )) && jobs=1
if (( ${#after[@]} > 0 )); then
  last=$(last_block "${after[@]}") || exit 2
  start_block=$(( last + 1 ))
fi
out="${out:-target/crash-campaign/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$out"

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "working tree has uncommitted changes: a campaign must name an exact commit" >&2
  exit 2
fi
commit="$(git rev-parse --short HEAD)"
# Build once; every block then starts the already-built test binary through cargo.
cargo test --release --locked -p rustegon-storage --test engine --no-run >"$out/build.log" 2>&1 || {
  echo "release build failed, see $out/build.log" >&2; exit 2; }

start_epoch=$(date +%s)
# Fractional hours are allowed (calibration runs): seconds = hours * 3600.
deadline=$(( start_epoch + $(awk -v h="$hours" 'BEGIN { printf "%d", h * 3600 }') ))
{
  echo "commit=$commit hours=$hours jobs=$jobs block=$block seeds=$seeds start_block=$start_block"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "started_epoch=$start_epoch"
} >"$out/summary.txt"
echo "crash campaign: commit $commit, $hours h, $jobs jobs, blocks from $start_block (workloads from $(( start_block * block ))), output $out"

run_job() {
  local j=$1 b=$(( start_block + $1 ))
  while (( $(date +%s) < deadline )); do
    local first=$(( b * block )) t0 t1 status
    t0=$(date +%s)
    if RUSTEGON_CRASH_WORKLOAD_START=$first RUSTEGON_CRASH_WORKLOADS=$block RUSTEGON_CRASH_SEEDS=$seeds \
        cargo test --release --locked -q -p rustegon-storage --test engine \
        tc_sto_002_engine_crash_at_every_operation >"$out/block-$b.log" 2>&1; then
      status=pass; rm -f "$out/block-$b.log"
    else
      status=FAIL
    fi
    t1=$(date +%s)
    echo "$first $block $seeds $(( t1 - t0 )) $status $t1" >>"$out/job-$j.tsv"
    [[ $status == FAIL ]] && return 1
    b=$(( b + jobs ))
  done
}

pids=()
for (( j = 0; j < jobs; j++ )); do run_job "$j" & pids+=($!); done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done

end_epoch=$(date +%s)
blocks=$(cat "$out"/job-*.tsv 2>/dev/null | wc -l)
fails=$(cat "$out"/job-*.tsv 2>/dev/null | grep -c FAIL)
{
  echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) elapsed_s=$(( end_epoch - start_epoch ))"
  echo "blocks=$blocks workloads=$(( blocks * block )) failed_blocks=$fails"
  if (( failed )); then echo "FAILED: see $out/block-*.log"; else echo "PASSED: no invariant violation"; fi
  echo "next run: scripts/crash-campaign.sh --hours $hours --jobs $jobs --block $block --seeds $seeds --after $out"
} >>"$out/summary.txt"
cat "$out/summary.txt"
exit "$failed"
