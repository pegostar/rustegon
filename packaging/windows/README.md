# Rustegon (Windows installer)

A distributed ACID document database. The installer puts into `C:\Program Files\Rustegon`:

| File | |
|---|---|
| `bin\rustegond.exe` | the server, with the web console embedded under `/ui` |
| `bin\rustegon.exe` | the command-line tool (`init`, `shell`, users, backups, certificates) |
| `rustegon.toml.sample` | every setting at its default, commented out |
| `LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES.txt` | Apache-2.0 and bundled licenses |

`bin` is added to the system `PATH` (open a new terminal). It also installs the Windows service
**Rustegon** (account `NT SERVICE\Rustegon`, automatic start) and, on the first install,
initializes a node in `C:\ProgramData\Rustegon` (`rustegon.toml`, `data\`, `logs\`; readable
only by SYSTEM, Administrators and the service): plain text on `127.0.0.1:7700` and
`127.0.0.1:7780`. The service is running when the installer finishes. This is an **unsigned
development build** (SmartScreen may warn); check it against `SHA256SUMS`.

## Quick start

1. Open **Rustegon Console** from the Start menu (or http://localhost:7780/ui/).
2. Sign in as **`admin` / `admin`**: you are asked to change the password first. Until it is
   changed, every other operation is refused, and the service refuses to start with a listener
   that is not on loopback (ADR-036).
3. Drivers then connect with `rustegon://admin:<new password>@localhost:7700/<database>`.

```powershell
Get-Service Rustegon
rustegon health --ready
rustegon user --user admin passwd     # the same change from the command line
```

To serve other hosts, change the password first, then set `[listen]` to `0.0.0.0` in
`C:\ProgramData\Rustegon\rustegon.toml` (and enable TLS, windows.md §6) and
`Restart-Service Rustegon`. Logs: `C:\ProgramData\Rustegon\logs`.

## Upgrade and uninstall

A newer installer replaces the binaries and restarts the service; the configuration and data
are kept and init does not run again. Uninstalling (Settings > Apps, or
`msiexec /x rustegon-<version>-windows-x86_64.msi`) stops and removes the service, the program
files and the `PATH` entry: **`C:\ProgramData\Rustegon` is never touched**; delete it by hand
once you have a backup. Only binaries without a node: use the `.zip` archive instead.

The full guide is `docs/deployment/windows.md` in the source repository.
