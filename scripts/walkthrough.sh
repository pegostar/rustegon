#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# TC-INS-009 (NFR-USE-001, AC-INS-004, PD-156): the scripted first-run walk-through from a
# release archive, timed from unpacking to the administrator signed in to the web console.
# Steps: unpack the archive into a new temporary directory; then the GUI e2e harness
# (gui/e2e/rustegond.ts) runs the archive's own binaries as the README quick start does —
# `rustegon init --non-interactive` with a generated admin password file, `rustegond` — and
# Playwright signs in as `admin` on the /ui served by that rustegond
# (gui/e2e/walkthrough.spec.ts). Fails when the wall time exceeds 10 minutes.
# Docker variant (--docker): docker.md §4 with the shipped packaging/docker/compose.yaml — a
# generated secret file, `docker compose up -d`, wait for `healthy`, then the same Playwright
# login against http://localhost:7780/ui/ (plain http, the default, ADR-034; RGN_E2E_SERVE=external); timed from `up` (the image
# rustegon/rustegon:1 must already be built: packaging/docker/build.sh or scripts/docker-tests.sh).
# Uses the fixed host ports 7700 and 7780, as docker.md does.
# Needs gui/node_modules (npm ci) and Playwright's chromium.
# Usage: scripts/walkthrough.sh [archive]   (default: this host's archive in dist/, newest)
#        scripts/walkthrough.sh --docker
set -euo pipefail
cd "$(dirname "$0")/.."

limit=600
if [[ "${1:-}" == --docker ]]; then
  work="$(mktemp -d)"; project="rgn-tc-ins-009-$$"
  trap '(cd "$work" && docker compose -p "$project" down -v >/dev/null 2>&1) || true; rm -rf "$work"' EXIT
  cp packaging/docker/compose.yaml "$work/docker-compose.yml"
  start=$(date +%s)
  openssl rand -base64 24 > "$work/admin_password.txt"
  # Readable by uid 10001 through the bind-mounted secret: the one change to docker.md, as TC-INS-008 (PD-150).
  chmod 644 "$work/admin_password.txt"
  (cd "$work" && docker compose -p "$project" up -d)
  id="$(cd "$work" && docker compose -p "$project" ps -q rustegon)"
  until [[ "$(docker inspect -f '{{.State.Health.Status}}' "$id")" == healthy ]]; do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$id")" != true ]] || (( $(date +%s) - start > limit )); then
      docker logs "$id" >&2 || true; echo "TC-INS-009 (Docker): not healthy" >&2; exit 1
    fi
    sleep 2
  done
  (cd gui && RGN_E2E_SERVE=external RGN_E2E_WALKTHROUGH=1 RGN_E2E_BASE_URL=http://localhost:7780/ui/ \
    RGN_E2E_API=localhost:7780 RGN_E2E_ADMIN_PASSWORD="$(tr -d '\r\n' < "$work/admin_password.txt")" \
    npx playwright test e2e/walkthrough.spec.ts)
  elapsed=$(( $(date +%s) - start ))
  echo "TC-INS-009 (Docker): docker.md §4 compose up -> healthy -> GUI login in ${elapsed} s (limit ${limit} s)"
  (( elapsed <= limit ))
  exit 0
fi
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) suffix="windows-x86_64.zip" ;;
  *) suffix="linux-$(uname -m).tar.gz" ;;
esac
archive="${1:-$(ls -t dist/rustegon-*-"$suffix" 2>/dev/null | head -n1)}"
if [[ -z "$archive" || ! -f "$archive" ]]; then
  echo "no archive (run 'cargo xtask dist --target host' or pass one)" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
start=$(date +%s)
case "$archive" in
  *.zip) unzip -q "$archive" -d "$work" ;;
  *.tar.gz) tar -xzf "$archive" -C "$work" ;;
  *) echo "unknown archive type: $archive" >&2; exit 2 ;;
esac
dirs=("$work"/rustegon-*/)
bin_dir="$(cd "${dirs[0]}" && (pwd -W 2>/dev/null || pwd))"
# The binaries carry the archive's version (PD-154): rustegon-<version>-<os>-<arch>/.
version="$(basename "${dirs[0]}")"; version="${version#rustegon-}"; version="${version%-*-*}"
for b in rustegond rustegon; do
  "$bin_dir/$b" --version | tr -d '\r' | grep -qxF "$b $version" \
    || { echo "$b --version does not print $version" >&2; exit 1; }
done
(cd gui && RUSTEGON_BIN_DIR="$bin_dir" RGN_E2E_SERVE=rustegond RGN_E2E_WALKTHROUGH=1 \
  npx playwright test e2e/walkthrough.spec.ts)
elapsed=$(( $(date +%s) - start ))
echo "TC-INS-009: $(basename "$archive"): unpack -> init -> rustegond -> GUI login in ${elapsed} s (limit ${limit} s)"
(( elapsed <= limit ))
