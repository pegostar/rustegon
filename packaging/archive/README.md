# Rustegon

A distributed ACID document database. This archive holds a single build for one platform:

| File | |
|---|---|
| `rustegond` (`rustegond.exe`) | the server, with the web console embedded under `/ui` |
| `rustegon` (`rustegon.exe`) | the command-line tool (`init`, `shell`, users, backups, certificates) |
| `rustegon.toml` | sample configuration: every setting at its default, commented out |
| `LICENSE`, `NOTICE` | Apache-2.0 |
| `THIRD-PARTY-LICENSES.txt` | licenses of the bundled Rust crates and web-console packages |

This is an **unsigned development build** (version in the archive name and in
`rustegond --version`). Check the archive against `SHA256SUMS` before unpacking:
`sha256sum -c SHA256SUMS --ignore-missing` (Linux) or
`Get-FileHash <archive> -Algorithm SHA256` (PowerShell, compare by hand).

## Quick start: one node, web console in a few minutes

`rustegon init` creates the configuration in a new data directory. The node listens in
plain text by default; `init --tls` also creates a CA and a node certificate and turns TLS on
(see "Enable TLS" below). With a password file the first administrator `admin` gets that password on the
server's first start; without one, `init` asks for it on a terminal (or `rustegond` generates
one into `<data dir>/initial-admin-password`). Passwords never go on the command line.

### Linux

```bash
tar -xzf rustegon-<version>-linux-x86_64.tar.gz
cd rustegon-<version>-linux-x86_64
# a strong random password for `admin`, readable by you only
(umask 077; head -c 18 /dev/urandom | base64 | tr '+/' 'xy' > admin.pw)
./rustegon init --data-dir ./data --admin-password-file admin.pw
./rustegond --config ./data/rustegon.toml --admin-password-file admin.pw
```

### Windows (PowerShell)

```powershell
Expand-Archive rustegon-<version>-windows-x86_64.zip -DestinationPath .
cd rustegon-<version>-windows-x86_64
# a strong random password for `admin`
$b = New-Object byte[] 18; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b).Replace('+','x').Replace('/','y') | Set-Content -NoNewline admin.pw
.\rustegon.exe init --data-dir .\data --admin-password-file admin.pw
.\rustegond.exe --config .\data\rustegon.toml --admin-password-file admin.pw
```

### Open the console

Browse to **http://localhost:7780/ui/** and sign in as `admin` with the password in `admin.pw`.
Then change the password (`rustegon user passwd`) and delete `admin.pw`. Drivers connect with
`rustegon://admin:<password>@localhost:7700/<database>`.

### Enable TLS

Plain text is fine on your own machine or a trusted network; elsewhere add `--tls` to
`rustegon init` (it writes `security.tls = true` and creates `data/ca` and `data/certs`). The
console is then at **https://localhost:7780/ui/**: its certificate is issued by the node's own
CA (`data/certs/ca.crt`), so accept the browser warning or import that CA as trusted. CLI
commands take `--ca data/certs/ca.crt`; drivers add `?tls=true&tlsCaFile=ca.crt`. Move
`data/ca/ca.key` offline.

Prefer an installer? The same build is also published as a Windows MSI
(`rustegon-<version>-windows-x86_64.msi`) and as DEB/RPM packages
(`rustegon-<version>-amd64.deb`, `rustegon-<version>-x86_64.rpm`, and arm64/aarch64) with a
systemd unit; each carries its own quick start.

`rustegon init --help` lists the options (listen address, ports, TLS, extra host names for the
certificate). The full guides (service setup, backups, upgrades) are in the documentation:
`docs/deployment/linux.md` and `docs/deployment/windows.md` of the source repository.
