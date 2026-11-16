#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Docker image tests (docker.md §8, FR-INS-003, AC-INS-003, PD-150), run by scripts/ci-local.sh:
# - build packaging/docker/Dockerfile for one platform and load it as rustegon/rustegon:1 (the
#   tag the docker.md §4 compose file names);
# - TC-INS-007 image smoke with TLS on (RUSTEGON__SECURITY__TLS=true, ADR-034): runs as uid/gid
#   10001 with a read-only root FS and a tmpfs /tmp, initializes itself (auto-init, auto-TLS,
#   generated admin password: only its path is printed), becomes `healthy` (the healthcheck
#   follows the variable to HTTPS), serves /ui and /api/v1/health/ready over TLS verified with
#   the CA from `rustegon cert export-ca`;
# - TC-INS-008 single node: the docker.md §4 compose file extracted verbatim (and equal to
#   packaging/docker/compose.yaml), run with a generated secret in the default plain-text mode,
#   `healthy`, REST login as admin over http (session cookies without `Secure`), /ui over http,
#   torn down with volumes.
# The compose file publishes the fixed ports 7700 and 7780 on the host: they must be free.
# Usage: scripts/docker-tests.sh [--platform linux/amd64|linux/arm64] [--no-build]
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -m)" in aarch64|arm64) platform=linux/arm64 ;; *) platform=linux/amd64 ;; esac
build=1
while (($#)); do
  case "$1" in
    --platform) platform="${2:?--platform needs a value}"; shift ;;
    --no-build) build="" ;;
    *) echo "usage: scripts/docker-tests.sh [--platform linux/amd64|linux/arm64] [--no-build]" >&2; exit 2 ;;
  esac
  shift
done
IMAGE=rustegon/rustegon:1
# Pinned (same digest as the build stage): used only to inspect the data volume from outside.
INSPECT_IMAGE=rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea
HEALTH_TIMEOUT=180
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

work="$(mktemp -d)"
smoke_id=""; smoke_vol="rgn-tc-ins-007-$$"; project="rgn-tc-ins-008-$$"
cleanup() {
  [[ -n "$smoke_id" ]] && docker rm -f "$smoke_id" >/dev/null 2>&1 || true
  docker volume rm -f "$smoke_vol" >/dev/null 2>&1 || true
  if [[ -f "$work/compose/docker-compose.yml" ]]; then
    (cd "$work/compose" && docker compose -p "$project" down -v >/dev/null 2>&1) || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

if [[ -n "$build" ]]; then
  step "image build $platform → $IMAGE"
  docker buildx build --platform "$platform" --build-arg "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-}" \
    -f packaging/docker/Dockerfile -t "$IMAGE" --load .
fi
size="$(docker image inspect -f '{{.Size}}' "$IMAGE")"
echo "image $IMAGE ($(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$IMAGE")): $((size / 1000 / 1000)) MB"

# Waits until container $1 is healthy; prints the seconds it took.
wait_healthy() {
  local start=$SECONDS status
  while ((SECONDS - start < HEALTH_TIMEOUT)); do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$1")"
    [[ "$status" == healthy ]] && { echo "$((SECONDS - start))"; return 0; }
    [[ "$(docker inspect -f '{{.State.Running}}' "$1")" == true ]] || break
    sleep 2
  done
  docker logs "$1" >&2 || true
  return 1
}

# HTTPS GET of $2 on 127.0.0.1:$1 verified with $work/$3; prints the HTTP status.
# --ssl-no-revoke: Windows curl (Schannel) cannot check revocation of the private CA (no CRL
# endpoint) and refuses; other TLS backends ignore the option.
https_status() {
  curl -sS --ssl-no-revoke -o "$work/body" -w '%{http_code}' --cacert "$work/$3" \
    --resolve "localhost:$1:127.0.0.1" "https://localhost:$1$2"
}

step "TC-INS-007: image smoke with TLS (uid 10001, read-only root FS, healthy, /ui, readiness)"
[[ "$(docker image inspect -f '{{.Config.User}}' "$IMAGE")" == "10001:10001" ]] || fail "image user is not 10001:10001"
smoke_id="$(MSYS_NO_PATHCONV=1 docker run -d --platform "$platform" --read-only --tmpfs /tmp \
  -e RUSTEGON__SECURITY__TLS=true -v "$smoke_vol:/var/lib/rustegon" -p 127.0.0.1::7780 "$IMAGE")"
secs="$(wait_healthy "$smoke_id")" || fail "TC-INS-007: container not healthy within ${HEALTH_TIMEOUT}s"
echo "healthy after ${secs}s"
port="$(docker port "$smoke_id" 7780/tcp | head -n1 | sed 's/.*://')"
docker exec "$smoke_id" rustegon cert export-ca > "$work/smoke-ca.crt"
code="$(https_status "$port" /api/v1/health/ready smoke-ca.crt)"
[[ "$code" == 200 ]] || fail "TC-INS-007: /api/v1/health/ready → $code"
code="$(https_status "$port" /ui/ smoke-ca.crt)"
[[ "$code" == 200 ]] && grep -qi '<html' "$work/body" || fail "TC-INS-007: /ui/ → $code (GUI not embedded?)"
logs="$(docker logs "$smoke_id" 2>&1)"
grep -q 'initial password of user admin written to /var/lib/rustegon/initial-admin-password' <<<"$logs" \
  || fail "TC-INS-007: generated admin password path not reported"
owner="$(MSYS_NO_PATHCONV=1 docker run --rm -v "$smoke_vol:/d:ro" --entrypoint stat "$INSPECT_IMAGE" \
  -c '%u:%g %a' /d/certs/node.key /d/initial-admin-password)"
echo "$owner"
[[ "$(grep -c '^10001:10001 600$' <<<"$owner")" == 2 ]] || fail "TC-INS-007: files not owned by 10001 owner-only"
docker stop -t 90 "$smoke_id" >/dev/null
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$smoke_id")" == 0 ]] || fail "TC-INS-007: SIGTERM stop exit code not 0"
echo "TC-INS-007 passed"

step "TC-INS-008: docker.md §4 single-node compose, verbatim"
mkdir -p "$work/compose"
# The first yaml block of section 4, unchanged.
awk '/^## 4\./{s=1} /^## 5\./{s=0} s&&/^```yaml/{y=1;next} y&&/^```/{exit} y' docs/deployment/docker.md \
  > "$work/compose/docker-compose.yml"
grep -q 'image: rustegon/rustegon:1' "$work/compose/docker-compose.yml" || fail "TC-INS-008: compose block not found"
# packaging/docker/compose.yaml is the shipped copy of that block: it must not drift.
cmp -s "$work/compose/docker-compose.yml" packaging/docker/compose.yaml \
  || fail "TC-INS-008: packaging/docker/compose.yaml differs from docker.md §4"
cd "$work/compose"
openssl rand -base64 24 > admin_password.txt
# The secret file is the only change to the verbatim steps: readable by uid 10001 inside the container (bind-mounted secret).
chmod 644 admin_password.txt
DOCKER_DEFAULT_PLATFORM="$platform" docker compose -p "$project" up -d
id="$(docker compose -p "$project" ps -q rustegon)"
secs="$(wait_healthy "$id")" || fail "TC-INS-008: compose service not healthy within ${HEALTH_TIMEOUT}s"
echo "healthy after ${secs}s"
# Plain text by default (ADR-034): no certificate was generated, login and GUI over http.
docker compose -p "$project" exec -T rustegon rustegon cert export-ca >/dev/null 2>&1 \
  && fail "TC-INS-008: a CA was generated although TLS is off"
printf '{"user":"admin","password":"%s"}' "$(tr -d '\r\n' < admin_password.txt)" > login.json
code="$(curl -sS -o "$work/body" -D "$work/headers" -w '%{http_code}' \
  -H 'content-type: application/json' --data-binary @login.json http://localhost:7780/api/v1/auth/login)"
rm -f login.json
[[ "$code" == 200 ]] || { cat "$work/body" >&2; fail "TC-INS-008: login as admin → $code"; }
# Browsers drop `Secure` cookies received over http from non-localhost hosts.
grep -qi '^set-cookie: rgn_session=' "$work/headers" || fail "TC-INS-008: no session cookie"
grep -qi '^set-cookie:.*secure' "$work/headers" && fail "TC-INS-008: Secure cookie over plain http"
code="$(curl -sS -o "$work/body" -w '%{http_code}' http://localhost:7780/ui/)"
[[ "$code" == 200 ]] || fail "TC-INS-008: /ui/ → $code"
docker compose -p "$project" down -v
cd - >/dev/null
echo "TC-INS-008 passed"
