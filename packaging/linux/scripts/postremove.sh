#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# DEB postrm / RPM %postun (FR-INS-002): forget the removed unit. Nothing is deleted, not even on
# `apt purge`: /etc/rustegon holds the encryption key file without which the data in
# /var/lib/rustegon is unreadable (PD-203). The rustegon account is kept as well, so that a
# reinstall finds the files owned by the same user.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
