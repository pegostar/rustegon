# R1 24 h single-node soak (PD-157, DEC-021) on a Windows host.
# Builds the release binaries, keeps the machine awake for the whole run and starts the runner
# drivers/rust/examples/soak.rs. Result: bench/results/<date>-soak-<duration>-<env>.json.
#
#   powershell -ExecutionPolicy Bypass -File scripts\soak.ps1                 # 24 h
#   powershell -ExecutionPolicy Bypass -File scripts\soak.ps1 -Duration 1h -GcTtl 10m  # trial run that exercises MVCC GC (PD-232)
#   ... -Duration 1h -GcTtl 10m -Set storage.block_cache_size=67108864 -EnvLabel dev-win11-x64-cache64m  # PD-233
#
# Plug the laptop in, charger straight into the wall: the script blocks sleep, but not a battery
# shutdown or Windows Update reboot, and a minute on battery fails a p99 window (PD-233).
# scripts\soak-host.ps1 records the host next to the node logs, in <work dir>\host.jsonl.
param(
    [string]$Duration = "24h",
    [string]$GcTtl = "4h",
    [string]$EnvLabel = "dev-win11-x64",
    # Not under %TEMP%: a temp clean-up during a run deletes the node's data (2026-11-25).
    [string]$WorkDir = "$env:LOCALAPPDATA\rustegon-soak",
    # Extra node settings, key=value (PD-233), passed to rustegond as --set.
    [string[]]$Set = @(),
    # Cargo features of the node build, e.g. rustegond/heap-stats (PD-233 diagnostics).
    [string]$Features = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# ES_CONTINUOUS | ES_SYSTEM_REQUIRED: no sleep while this process runs (no admin rights needed).
Add-Type -Name Power -Namespace Soak -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint flags);
'@
[void][Soak.Power]::SetThreadExecutionState([uint32]"0x80000001")

if (Test-Path $WorkDir) { throw "$WorkDir exists: remove it (after a look) before a new run" }
Add-Type -AssemblyName System.Windows.Forms
if ([System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus -eq "Offline") {
    throw "on battery: plug the charger in before a soak"
}
# Host monitor (PD-233); it waits for the work dir and ends with this process.
Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSScriptRoot\soak-host.ps1`"", "-WorkDir", "`"$WorkDir`"", "-ParentPid", $PID
$date = Get-Date -Format "yyyy-MM-dd"
$sets = @($Set | ForEach-Object { "--set"; $_ })
$out = Join-Path $root "bench\results\$date-soak-$Duration-$EnvLabel.json"

Push-Location $root
try {
    $feat = if ($Features) { @("--features", $Features) } else { @() }
    cargo build --release -p rustegond -p rustegon-cli @feat
    if ($LASTEXITCODE -ne 0) { throw "release build failed" }
    Push-Location drivers\rust
    try {
        cargo run --release --example soak -- --bin-dir "$root\target\release" `
            --work-dir $WorkDir --duration $Duration --gc-ttl $GcTtl @sets --out $out
        $code = $LASTEXITCODE
    } finally { Pop-Location }
} finally {
    Pop-Location
    [void][Soak.Power]::SetThreadExecutionState([uint32]"0x80000000")
}
Write-Host "soak exit code $code (0 = PASS, 1 = FAIL, 2 = aborted); report: $out"
exit $code
