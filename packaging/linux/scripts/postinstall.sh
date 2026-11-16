#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# DEB postinst / RPM %post (FR-INS-002, linux.md §1, ADR-036, PD-220…PD-222). Arguments: DEB
# `configure <old version>` (empty on a first install), RPM `1` (install) or `2` (upgrade).
#
# Turnkey: without /etc/rustegon/rustegon.toml, `rustegon init --turnkey` runs as the rustegon
# account (plain text on 127.0.0.1:7700/7780; the first start creates admin/admin, which must be
# changed at first login and is accepted only on loopback). Then, where systemd runs, the unit
# is enabled and started, also over a distribution preset that disables new units (the owner
# wants a running node after install). An upgrade keeps everything and restarts a running
# service. Without systemd (containers) nothing is started.
set -e
CONFIG=/etc/rustegon/rustegon.toml
# Left by preremove on `remove`: dpkg passes the old version to a reinstall after a remove as
# if it were an upgrade, but the unit was disabled by that remove and must come back.
REMOVED=/etc/rustegon/.removed

# The directories only, never their content (data and keys written by init stay as they are).
chown rustegon:rustegon /etc/rustegon /var/lib/rustegon /var/log/rustegon
chmod 0750 /etc/rustegon /var/log/rustegon
chmod 0700 /var/lib/rustegon

upgrade=""
case "$1" in
  configure) [ -n "$2" ] && upgrade=1 ;;
  2) upgrade=1 ;;
esac
if [ -e "$REMOVED" ]; then
  upgrade=""
  rm -f "$REMOVED"
fi

initialized=""
if [ -z "$upgrade" ] && [ ! -e "$CONFIG" ]; then
  # As the service account, so that every file belongs to it. coreutils only: the minimal
  # Fedora image has neither runuser nor su.
  if HOME=/var/lib/rustegon chroot --userspec=rustegon:rustegon --skip-chdir / \
      /usr/bin/rustegon init --turnkey --data-dir /var/lib/rustegon --config "$CONFIG" \
      --log-dir /var/log/rustegon --grpc-port 7700 --http-port 7780; then
    initialized=1
  else
    # Not fatal: the package is installed; the node can be initialized by hand.
    echo "rustegon: the turnkey initialization failed; run it by hand:" >&2
    echo "  sudo -u rustegon rustegon init --turnkey --data-dir /var/lib/rustegon --config $CONFIG --log-dir /var/log/rustegon" >&2
  fi
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ -n "$upgrade" ]; then
    # An upgrade restarts a running service on the new binaries, a stopped one stays stopped.
    systemctl try-restart rustegon.service >/dev/null 2>&1 || true
  elif [ -e "$CONFIG" ]; then
    systemctl enable --now rustegon.service || \
      echo "rustegon: could not start rustegon.service; see journalctl -u rustegon" >&2
  fi
elif [ -z "$upgrade" ]; then
  echo "rustegon: systemd is not running (container?): the service was not started; start" \
    "rustegond as the rustegon user: rustegond --config $CONFIG"
fi

if [ -n "$initialized" ]; then
  cat <<'EOF'
Rustegon is installed and initialized (plain text on 127.0.0.1:7700 and 127.0.0.1:7780).
Open http://localhost:7780/ui/, sign in as admin / admin; you will be asked to change the
password. Until then the node accepts only loopback listeners (/usr/share/doc/rustegon/README.md).
EOF
elif [ -z "$upgrade" ] && [ -e "$CONFIG" ]; then
  echo "rustegon: kept the existing configuration $CONFIG and data in /var/lib/rustegon."
fi
