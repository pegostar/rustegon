#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# TC-INS-017 (FR-INS-002, ADR-036, PD-221): the newest x86_64 DEB in an ubuntu:24.04 container
# booted with systemd as PID 1 (privileged; systemd is installed from the Ubuntu archive, so
# this needs network access). Checks that the install enables and starts rustegon.service, that
# the console answers on 127.0.0.1:7780 with admin/admin flagged must-change, and that removal
# disables the unit and keeps the configuration and data.
# Usage: scripts/package-systemd-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

UBUNTU_2404=ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5
deb="$(ls -t dist/rustegon-*-amd64.deb 2>/dev/null | head -n1)"
[[ -n "$deb" ]] || fail "no dist/rustegon-*-amd64.deb (cargo xtask dist --target linux-x86_64 --packages)"
src="$(pwd -W 2>/dev/null || pwd)"
name="rustegon-systemd-test-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

step "boot ubuntu:24.04 with systemd"
MSYS_NO_PATHCONV=1 docker run -d --name "$name" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  --mount "type=bind,src=$src,dst=/src,readonly" "$UBUNTU_2404" bash -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv >/dev/null && exec /lib/systemd/systemd' >/dev/null
run_in() { MSYS_NO_PATHCONV=1 docker exec "$name" bash -c "$1"; }
for _ in $(seq 1 180); do
  state="$(run_in 'systemctl is-system-running 2>/dev/null' || true)"
  [[ "$state" == running || "$state" == degraded ]] && break
  sleep 1
done
[[ "${state:-}" == running || "${state:-}" == degraded ]] || fail "systemd did not boot (state: ${state:-none})"

step "install $(basename "$deb")"
run_in "dpkg -i /src/$deb"
run_in 'systemctl is-enabled rustegon.service' | grep -qx enabled || fail "unit not enabled"
for _ in $(seq 1 60); do
  run_in 'rustegon health --ready >/dev/null 2>&1' && break
  sleep 1
done
run_in 'systemctl is-active rustegon.service' | grep -qx active || { run_in 'journalctl -u rustegon --no-pager | tail -50' || true; fail "unit not active"; }
http() {
  run_in "exec 3<>/dev/tcp/127.0.0.1/7780; printf '%s %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s' '$1' '$2' ${#3} '$3' >&3; cat <&3"
}
http GET /ui/ '' | head -n1 | grep -q ' 200' || fail "console not served on /ui/"
http POST /api/v1/auth/login '{"user":"admin","password":"admin","delivery":"token"}' \
  | grep -q '"mustChangePassword":true' || fail "admin/admin is not flagged must-change"

step "remove disables the unit, keeps configuration and data"
run_in 'dpkg -r rustegon'
! run_in 'systemctl is-enabled rustegon.service 2>/dev/null' | grep -qx enabled || fail "unit still enabled"
run_in 'test -f /etc/rustegon/rustegon.toml && test -d /var/lib/rustegon/store' || fail "configuration or data removed"

step "reinstall enables and starts it again (PD-222)"
run_in "dpkg -i /src/$deb"
run_in 'systemctl is-enabled rustegon.service' | grep -qx enabled || fail "unit not re-enabled"
for _ in $(seq 1 60); do
  run_in 'rustegon health --ready >/dev/null 2>&1' && break
  sleep 1
done
run_in 'systemctl is-active rustegon.service' | grep -qx active || fail "unit not active after the reinstall"
echo "systemd package test passed: $(basename "$deb")"
