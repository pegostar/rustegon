# Rustegon (DEB/RPM package)

A distributed ACID document database. This package installs:

| Path | |
|---|---|
| `/usr/bin/rustegond` | the server, with the web console embedded under `/ui` |
| `/usr/bin/rustegon` | the command-line tool (`init`, `shell`, users, backups, certificates) |
| `/usr/lib/systemd/system/rustegon.service` | the unit, enabled and started on the first install (where systemd runs) |
| `/etc/rustegon/rustegon.toml` | configuration written by the first install (`rustegon init --turnkey`) |
| `/var/lib/rustegon/` | data directory |
| `/var/log/rustegon/` | log files |
| `/usr/share/doc/rustegon/` | this file, licenses, `rustegon.toml.sample` (every default, commented out) |

The package creates the system account `rustegon` (no shell, no password). This is an
**unsigned development build**: check the package against `SHA256SUMS` before installing it.
Install it with `sudo apt install ./<file>.deb` or `sudo dnf install ./<file>.rpm` (dnf warns
that it skipped the OpenPGP check; plain `rpm -i` refuses unsigned packages on rpm 6).

## Quick start (turnkey)

The first install (no `/etc/rustegon/rustegon.toml` yet) runs `rustegon init --turnkey` as the
`rustegon` account: plain text on `127.0.0.1:7700` (gRPC) and `127.0.0.1:7780` (REST and
console), logs in `/var/log/rustegon`. It then enables and starts `rustegon.service` (also on
distributions whose preset would leave new units disabled, e.g. Fedora).

1. Browse to **http://localhost:7780/ui/**.
2. Sign in as **`admin` / `admin`**: you are asked to change the password first. Until it is
   changed, every other operation is refused, and `rustegond` refuses to start with a listener
   that is not on loopback (ADR-036).
3. Drivers then connect with `rustegon://admin:<new password>@localhost:7700/<database>`.

```bash
systemctl status rustegon
rustegon health --ready
rustegon user --user admin passwd        # the same change from the command line
```

To serve other hosts, change the password first, then set `[listen]` to `0.0.0.0` in
`/etc/rustegon/rustegon.toml` (and enable TLS: linux.md §3) and `sudo systemctl restart rustegon`.

In a container without systemd nothing is started: run
`sudo -u rustegon rustegond --config /etc/rustegon/rustegon.toml`.

## Upgrade and removal

Installing a newer package keeps `/etc/rustegon`, `/var/lib/rustegon` and `/var/log/rustegon`
and restarts a running service. `apt remove` / `apt purge` / `dnf remove` stop and disable the
service and remove the binaries; **they never delete the configuration, the keys or the data**
(the key file is needed to read encrypted data). A later install reuses them without running
init again. Delete `/etc/rustegon` and `/var/lib/rustegon` by hand once you have a backup.

The full guide is `docs/deployment/linux.md` in the source repository.
