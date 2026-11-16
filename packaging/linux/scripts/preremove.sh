#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# DEB prerm / RPM %preun (FR-INS-002, linux.md §1): stops and disables the service on removal
# (DEB `remove`, RPM `0`), not on upgrade. Data, configuration and keys are never touched; a
# marker tells a later reinstall to enable the service again (postinstall.sh, PD-222).
set -e
case "$1" in
  remove|0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now rustegon.service >/dev/null 2>&1 || true
    fi
    if [ -e /etc/rustegon/rustegon.toml ]; then
      : > /etc/rustegon/.removed || true
    fi
    ;;
esac
