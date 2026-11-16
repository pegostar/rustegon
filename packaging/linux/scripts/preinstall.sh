#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# DEB preinst / RPM %pre (FR-INS-002, linux.md §1): the system account the service runs as,
# created before the files so that their owner resolves. No login shell, no home directory of
# its own, no password: packaging never creates credentials.
set -e
if ! getent group rustegon >/dev/null 2>&1; then
  groupadd --system rustegon
fi
if ! getent passwd rustegon >/dev/null 2>&1; then
  useradd --system --gid rustegon --home-dir /var/lib/rustegon --no-create-home \
    --shell /usr/sbin/nologin --comment "Rustegon database" rustegon
fi
