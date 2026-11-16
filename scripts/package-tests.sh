#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Installer tests of the packages built by `cargo xtask dist --packages` (FR-INS-001/002,
# AC-INS-001/002, PD-200…PD-203), run by scripts/ci-local.sh. They test the newest package of
# their kind in dist/.
#
# Default (Docker): the x86_64 DEB in ubuntu:24.04 and ubuntu:26.04, the RPM in fedora:45, each
# in a fresh container (no systemd: rustegond is started directly, as the unit would):
# - TC-INS-004 install: files, owners and modes, the `rustegon` system account without a
#   password, unit not enabled (no systemd), `--version` of both binaries;
# - TC-INS-016 turnkey (ADR-036, PD-220…PD-222): the install ran `rustegon init --turnkey` as
#   `rustegon` (only /etc/rustegon/rustegon.toml, owned by `rustegon`, loopback listeners,
#   `security.turnkey_admin`, `log.dir`, no TLS, no password; empty data directory), printed
#   the console step and the missing-systemd message; rustegond started as `rustegon` serves
#   /ui/, logs to /var/log/rustegon, admin/admin logs in with mustChangePassword, REST and gRPC
#   are refused before the change, the change works, only the new password works afterwards;
# - TC-INS-005 upgrade to a newer package (same binaries repackaged with a higher version by the
#   pinned nfpm image): no init, configuration and data kept, the node starts again on them;
# - TC-INS-013 remove (and purge for the DEB): binaries gone, configuration and data kept;
#   reinstalling reuses them (no init) and the changed password still works.
# The real systemd path (enable --now, console on 7780) is scripts/package-systemd-test.sh.
# --msi (Windows host, Git Bash): TC-INS-011 on the MSI: ICE validation (`wix msi validate`),
#   the decompiled tables (PATH entry, per-machine, version mapping) and an administrative
#   image (`msiexec /a`, no install, no elevation) holding the expected files, whose
#   rustegond.exe/rustegon.exe print the build version; TC-INS-015 the turnkey tables
#   (ServiceInstall/ServiceControl of `Rustegon` as NT SERVICE\Rustegon, the first-install-only
#   `rustegon init --turnkey` custom action and its rollback, the ProgramData ACL, the console
#   shortcut and the exit text). The real install is scripts/msi-smoke.ps1 (owner, elevated).
# Usage: scripts/package-tests.sh [--msi]
#        scripts/package-tests.sh --inner deb|rpm <package> <upgrade package> <version> <upgrade version>
set -euo pipefail

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
# Inside the distribution container.
inner() {
  local kind="$1" pkg="$2" pkg_up="$3" version="$4" version_up="$5"
  if [[ "$kind" == deb ]]; then
    # The Ubuntu images are minimized and drop /usr/share/doc on install: keep it for the checks.
    rm -f /etc/dpkg/dpkg.cfg.d/excludes
    install() { dpkg -i "$1"; }
    upgrade() { dpkg -i "$1"; }
    remove() { dpkg -r rustegon; dpkg -P rustegon; }
    installed_version() { dpkg-query -W -f='${Version}' rustegon; }
  else
    # dnf as the docs say: rpm 6 (Fedora 45) refuses unsigned packages with plain `rpm -i`, while
    # dnf skips the OpenPGP check for a local file with a warning (PD-205). No network needed.
    install() { dnf install -y --disablerepo='*' "$1"; }
    upgrade() { dnf install -y --disablerepo='*' "$1"; }
    remove() { dnf remove -y --disablerepo='*' rustegon; }
    installed_version() { rpm -q --qf '%{VERSION}' rustegon; }
  fi
  mode() { [[ "$(stat -c '%a %U:%G' "$1")" == "$2" ]] || fail "$1: $(stat -c '%a %U:%G' "$1"), want $2"; }
  # coreutils only: the Fedora image has neither runuser nor su.
  as_rustegon() { HOME=/var/lib/rustegon chroot --userspec=rustegon:rustegon --skip-chdir / "$@"; }
  local pid=""
  start() {
    # Not through the function: $! must be the rustegond process itself for the SIGTERM.
    HOME=/var/lib/rustegon chroot --userspec=rustegon:rustegon --skip-chdir / rustegond --config /etc/rustegon/rustegon.toml >/tmp/rustegond.log 2>&1 &
    pid=$!
    for _ in $(seq 1 60); do
      if rustegon health --ready >/dev/null 2>&1; then return 0; fi
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    cat /tmp/rustegond.log >&2
    fail "rustegond did not become ready"
  }
  stop() { kill -TERM "$pid"; wait "$pid" || true; }

  # Plain-text HTTP/1.1 to the REST listener with bash's /dev/tcp (no curl in the images).
  http() {
    local method="$1" path="$2" body="${3:-}" token="${4:-}" auth=""
    [[ -n "$token" ]] && auth="Authorization: Bearer $token"$'\r\n'
    exec 3<>/dev/tcp/127.0.0.1/7780
    printf '%s %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s' \
      "$method" "$path" "$auth" "${#body}" "$body" >&3
    cat <&3
    exec 3<&-
  }
  shell_as() { RUSTEGON_PASSWORD="$1" rustegon shell --host 127.0.0.1 --port 7700 --user admin -c "$2"; }
  local new_pw='Package-Test-Passw0rd-2026'

  step "TC-INS-004/016: install $(basename "$pkg") (turnkey)"
  install "$pkg" 2>&1 | tee /tmp/install.out
  grep -q 'sign in as admin / admin' /tmp/install.out || fail "no next step printed"
  grep -q 'systemd is not running' /tmp/install.out || fail "no message about the missing systemd"
  [[ "$(installed_version)" == "$version"* ]] || fail "installed version $(installed_version)"
  mode /usr/bin/rustegond "755 root:root"
  mode /usr/bin/rustegon "755 root:root"
  mode /usr/lib/systemd/system/rustegon.service "644 root:root"
  mode /etc/rustegon "750 rustegon:rustegon"
  mode /var/lib/rustegon "700 rustegon:rustegon"
  mode /var/log/rustegon "750 rustegon:rustegon"
  for f in README.md LICENSE NOTICE THIRD-PARTY-LICENSES.txt rustegon.toml.sample; do
    mode "/usr/share/doc/rustegon/$f" "644 root:root"
  done
  grep -q 'ExecStart=/usr/bin/rustegond --config /etc/rustegon/rustegon.toml' \
    /usr/lib/systemd/system/rustegon.service || fail "unit ExecStart"
  local account
  account="$(getent passwd rustegon)" || fail "no rustegon account"
  [[ "$account" == *:/usr/sbin/nologin ]] || fail "account shell: $account"
  (( $(id -u rustegon) < 1000 )) || fail "rustegon is not a system account"
  [[ "$(getent shadow rustegon | cut -d: -f2)" =~ ^[!*] ]] || fail "rustegon has a password"
  # TC-INS-016: the turnkey configuration, owned by the account; no password anywhere.
  [[ "$(stat -c '%U:%G' /etc/rustegon/rustegon.toml)" == rustegon:rustegon ]] || fail "config owner"
  [[ "$(ls -A /etc/rustegon)" == rustegon.toml ]] || fail "init wrote more than the configuration: $(ls -A /etc/rustegon)"
  [[ -z "$(ls -A /var/lib/rustegon)" ]] || fail "install wrote data"
  grep -qx 'turnkey_admin = true' /etc/rustegon/rustegon.toml || fail "no security.turnkey_admin"
  grep -q '^grpc = "127.0.0.1:7700"' /etc/rustegon/rustegon.toml || fail "gRPC listener not on loopback"
  grep -q '^http = "127.0.0.1:7780"' /etc/rustegon/rustegon.toml || fail "REST listener not on loopback"
  grep -q '^dir = "/var/log/rustegon"' /etc/rustegon/rustegon.toml || fail "log.dir"
  ! grep -qi 'tls = true\|password' /etc/rustegon/rustegon.toml || fail "unexpected TLS or password setting"
  [[ ! -e /etc/systemd/system/multi-user.target.wants/rustegon.service ]] || fail "unit enabled without systemd"
  local tag="${version##*+}"; tag="${tag%%.dirty}"
  rustegond --version | grep -q "$tag" || fail "rustegond --version: $(rustegond --version)"
  rustegon --version | grep -q "$tag" || fail "rustegon --version: $(rustegon --version)"

  step "TC-INS-016: rustegond as rustegon; admin/admin must change first"
  start
  [[ -n "$(ls -A /var/log/rustegon)" ]] || fail "no log files in /var/log/rustegon"
  [[ ! -e /var/lib/rustegon/initial-admin-password ]] || fail "a generated password in turnkey mode"
  http GET /ui/ | head -n1 | grep -q ' 200' || fail "console not served on /ui/"
  local login token
  login="$(http POST /api/v1/auth/login '{"user":"admin","password":"admin","delivery":"token"}')"
  [[ "$login" == *'"mustChangePassword":true'* ]] || fail "admin/admin login: $login"
  token="$(sed -n 's/.*"sessionToken":"\([^"]*\)".*/\1/p' <<<"$login")"
  http GET /api/v1/databases '' "$token" | grep -q 'password_change_required' \
    || fail "REST data plane reachable before the change"
  ! shell_as admin 'CREATE DATABASE shop' 2>/tmp/refused || fail "gRPC statement before the change"
  grep -q 'must be changed' /tmp/refused || fail "refusal: $(cat /tmp/refused)"
  RUSTEGON_PASSWORD=admin RUSTEGON_NEW_PASSWORD="$new_pw" \
    rustegon user --host 127.0.0.1 --port 7700 --user admin passwd || fail "password change"
  ! shell_as admin 'CREATE DATABASE shop' 2>/dev/null || fail "admin/admin still works"
  shell_as "$new_pw" 'CREATE DATABASE shop' || fail "the new password does not work"
  ! grep -rq '"password":"admin"' /var/log/rustegon || fail "the password is in the logs"
  stop
  local kept
  kept="$(sha256sum /etc/rustegon/rustegon.toml)"

  step "TC-INS-005: upgrade to $(basename "$pkg_up")"
  upgrade "$pkg_up" 2>&1 | tee /tmp/upgrade.out
  ! grep -q 'sign in as admin / admin' /tmp/upgrade.out || fail "upgrade ran init again"
  [[ "$(installed_version)" == "$version_up"* ]] || fail "upgraded version $(installed_version)"
  [[ "$(sha256sum /etc/rustegon/rustegon.toml)" == "$kept" ]] || fail "upgrade changed the configuration"
  mode /var/lib/rustegon "700 rustegon:rustegon"
  start
  shell_as "$new_pw" 'CREATE DATABASE shop_up' || fail "login after the upgrade"
  stop

  step "TC-INS-013: remove keeps configuration and data"
  remove
  [[ ! -e /usr/bin/rustegond && ! -e /usr/bin/rustegon ]] || fail "binaries left after remove"
  [[ -d /var/lib/rustegon/store ]] || fail "data directory removed"
  [[ "$(sha256sum /etc/rustegon/rustegon.toml)" == "$kept" ]] || fail "remove changed the configuration"
  getent passwd rustegon >/dev/null || fail "remove deleted the rustegon account"

  step "TC-INS-013/016: reinstall reuses the kept configuration and data"
  install "$pkg_up" 2>&1 | tee /tmp/reinstall.out
  grep -q 'kept the existing configuration' /tmp/reinstall.out || fail "reinstall: $(cat /tmp/reinstall.out)"
  [[ "$(sha256sum /etc/rustegon/rustegon.toml)" == "$kept" ]] || fail "reinstall changed the configuration"
  start
  shell_as "$new_pw" 'CREATE DATABASE shop_again' || fail "login after the reinstall"
  stop
  echo "package tests ($kind) passed"
}

if [[ "${1:-}" == --inner ]]; then
  shift
  inner "$@"
  exit 0
fi

cd "$(dirname "$0")/.."
newest() { ls -t dist/$1 2>/dev/null | head -n1; }

# ---------------------------------------------------------------------------------------------
# --msi: Windows host.
if [[ "${1:-}" == --msi ]]; then
  msi="$(newest 'rustegon-*-windows-x86_64.msi')"
  [[ -n "$msi" ]] || fail "no dist/rustegon-*-windows-x86_64.msi (cargo xtask dist --packages)"
  version="$(basename "$msi")"; version="${version#rustegon-}"; version="${version%-windows-x86_64.msi}"
  msi_w="$(cygpath -w "$(pwd)/$msi")"
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  wix() { (cd packaging/windows && dotnet tool restore >/dev/null && dotnet tool run wix -- "$@"); }
  for ext in WixToolset.Util.wixext/5.0.2 WixToolset.UI.wixext/5.0.2; do wix extension add "$ext"; done

  step "TC-INS-011: ICE validation of $(basename "$msi")"
  wix msi validate -nologo "$msi_w"

  step "TC-INS-011: decompiled tables"
  wix msi decompile -nologo -ext WixToolset.Util.wixext -ext WixToolset.UI.wixext \
    -o "$(cygpath -w "$work/decompiled.wxs")" "$msi_w" >"$work/decompile.log" 2>&1 \
    || { cat "$work/decompile.log" >&2; fail "decompile failed"; }
  wxs="$work/decompiled.wxs"
  grep -q 'UpgradeCode="{\?A09780E7-FBB6-4E78-8A29-BA350ACF46C1}\?"' "$wxs" || fail "upgrade code"
  commits="${version#*-dev.}"; commits="${commits%%+*}"
  grep -q "Version=\"${version%%-*}.$commits\"" "$wxs" || fail "ProductVersion is not ${version%%-*}.$commits"
  env_line="$(grep '<Environment' "$wxs" || true)"
  for attr in 'Name="PATH"' 'System="yes"' 'Action="set"' 'Part="last"' 'Value="[BINFOLDER]"'; do
    [[ "$env_line" == *"$attr"* ]] || fail "system PATH entry lacks $attr: $env_line"
  done
  grep -q '<MajorUpgrade' "$wxs" || grep -q 'Upgrade Id=' "$wxs" || fail "no major upgrade"
  # TC-INS-015 (ADR-036, PD-207…PD-209): the turnkey parts.
  svc="$(grep '<ServiceInstall' "$wxs" || true)"
  for attr in 'Name="Rustegon"' 'Account="NT SERVICE\Rustegon"' 'Start="auto"' \
      'Arguments="--service --config &quot;[DATAROOT]rustegon.toml&quot;"'; do
    [[ "$svc" == *"$attr"* ]] || fail "ServiceInstall lacks $attr: $svc"
  done
  ctl="$(grep '<ServiceControl' "$wxs" || true)"
  for attr in 'Start="install"' 'Stop="both"' 'Remove="uninstall"' 'Wait="yes"'; do
    [[ "$ctl" == *"$attr"* ]] || fail "ServiceControl lacks $attr: $ctl"
  done
  # The decompiler drops the util extension's table as well: check the MSI's string pool.
  grep -aq 'Wix4ServiceConfig' "$msi" || fail "no service failure actions"
  init="$(grep '<CustomAction Id="TurnkeyInit"' "$wxs" || true)"
  for attr in 'Execute="deferred"' 'Impersonate="no"' 'init --turnkey' \
      '--data-dir &quot;[DATAROOT]data&quot;' '--config &quot;[DATAROOT]rustegon.toml&quot;' \
      '--log-dir &quot;[DATAROOT]logs&quot;'; do
    [[ "$init" == *"$attr"* ]] || fail "TurnkeyInit lacks $attr: $init"
  done
  grep -q '<CustomAction Id="TurnkeyInitRollback".*Execute="rollback"' "$wxs" || fail "no init rollback"
  for ca in TurnkeyInit TurnkeyInitRollback; do
    grep -q "<Custom Action=\"$ca\" Condition=\"NOT Installed AND NOT RUSTEGON_CONFIG_FOUND AND NOT REMOVE\"" "$wxs" \
      || fail "$ca is not first-install only"
  done
  grep -q '<FileSearch .*Name="rustegon.toml"' "$wxs" || fail "no search for an existing configuration"
  shortcut="$(grep '<IniFile Id="ConsoleUrl"' "$wxs" || true)"
  [[ "$shortcut" == *'Name="Rustegon Console.url"'* && "$shortcut" == *'Value="http://localhost:7780/ui/"'* ]] \
    || fail "no Rustegon Console shortcut: $shortcut"
  grep -q 'sign in as admin / admin' "$wxs" || fail "no exit text"
  # The decompiler drops MsiLockPermissionsEx rows; the SDDL is in the string pool.
  grep -aqF 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2543126537-3050816147-2030542042-337991617-3549228777)' "$msi" \
    || fail "no protected ProgramData ACL for the service account"
  ! grep -qi 'Scope="perUser"' "$wxs" || fail "not a per-machine package"

  step "TC-INS-011: administrative image (no install)"
  target_w="$(cygpath -w "$work/image")"
  log_w="$(cygpath -w "$work/admin.log")"
  powershell -NoProfile -Command "\$p = Start-Process msiexec -ArgumentList '/a','\"$msi_w\"','/qn','TARGETDIR=\"$target_w\"','/l*v','\"$log_w\"' -Wait -PassThru; exit \$p.ExitCode" \
    || { cat "$work/admin.log" >&2 || true; fail "msiexec /a failed"; }
  dir="$(find "$work/image" -type d -name Rustegon | head -n1)"
  [[ -n "$dir" ]] || fail "no Rustegon folder in the administrative image"
  for f in bin/rustegond.exe bin/rustegon.exe README.md LICENSE NOTICE THIRD-PARTY-LICENSES.txt rustegon.toml.sample; do
    [[ -s "$dir/$f" ]] || fail "administrative image lacks $f"
  done
  "$dir/bin/rustegond.exe" --version | grep -qF "$version" || fail "rustegond.exe --version"
  "$dir/bin/rustegon.exe" --version | grep -qF "$version" || fail "rustegon.exe --version"
  echo "MSI tests passed: $(basename "$msi")"
  exit 0
fi
[[ $# == 0 ]] || { echo "usage: scripts/package-tests.sh [--msi]" >&2; exit 2; }

# ---------------------------------------------------------------------------------------------
# Default: DEB and RPM in containers (pinned images).
UBUNTU_2404=ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5
UBUNTU_2604=ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96
FEDORA_45=fedora:45@sha256:a7d72ba2745b100a3351087472e5ee7b2450af7cf331e7673007e3817612839c
NFPM_IMAGE="$(tr -d '[:space:]' < packaging/linux/nfpm-image.txt)"

deb="$(newest 'rustegon-*-amd64.deb')"
[[ -n "$deb" ]] || fail "no dist/rustegon-*-amd64.deb (cargo xtask dist --target linux-x86_64 --packages)"
version="$(basename "$deb")"; version="${version#rustegon-}"; version="${version%-amd64.deb}"
rpm="dist/rustegon-$version-x86_64.rpm"
[[ -f "$rpm" ]] || fail "no $rpm"
[[ -x dist/build/linux-x86_64/pkg/rustegond || -f dist/build/linux-x86_64/pkg/rustegond ]] \
  || fail "no staged binaries in dist/build/linux-x86_64/pkg"
pkg_version="${version/-/\~}"
up_version="$pkg_version.1"

src="$(pwd -W 2>/dev/null || pwd)"
step "TC-INS-005 fixture: the same binaries as $up_version (nfpm)"
rm -rf dist/build/package-tests; mkdir -p dist/build/package-tests
for packager in deb rpm; do
  MSYS_NO_PATHCONV=1 docker run --rm --mount "type=bind,src=$src,dst=/src,readonly" \
    --mount "type=bind,src=$src/dist/build/linux-x86_64/pkg,dst=/stage,readonly" \
    --mount "type=bind,src=$src/dist,dst=/dist" \
    -e VERSION="$up_version" -e ARCH=amd64 \
    -w /src "$NFPM_IMAGE" package --config packaging/linux/nfpm.yaml --packager "$packager" \
    --target "/dist/build/package-tests/upgrade.$packager"
done

run_in() {
  local image="$1" kind="$2" pkg="$3"
  step "$image: $(basename "$pkg")"
  MSYS_NO_PATHCONV=1 docker run --rm --mount "type=bind,src=$src,dst=/src,readonly" -w /src "$image" \
    bash /src/scripts/package-tests.sh --inner "$kind" "/src/$pkg" \
    "/src/dist/build/package-tests/upgrade.$kind" "$pkg_version" "$up_version"
}
run_in "$UBUNTU_2404" deb "$deb"
run_in "$UBUNTU_2604" deb "$deb"
run_in "$FEDORA_45" rpm "$rpm"
step "DEB/RPM package tests passed: $version"
