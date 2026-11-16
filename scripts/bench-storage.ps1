# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Runs storage microbenchmarks (BM-STO-*) in release mode, `-Repetitions` times each on a fresh
# store, and writes one result per run to bench/results/ (performance-benchmarks.md §2, §5:
# 3 repetitions, environment manifest with host facts). Run on an otherwise idle machine.
# Usage:
#   powershell -NoProfile -File scripts/bench-storage.ps1 -Env dev-win11-x64 -DataDir C:\bench `
#     -Workloads bench/workloads/bm-sto-01.toml,bench/workloads/bm-sto-03.toml -Repetitions 3 `
#     -Label seq
param(
    [Parameter(Mandatory = $true)][string]$Env,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][string[]]$Workloads,
    [int]$Repetitions = 3,
    [string]$Label = '',
    [string]$Notes = ''
)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
# `powershell -File` passes `a,b` as one string: split it here.
$Workloads = @($Workloads | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$dirty = git status --porcelain --untracked-files=no
if ($dirty) { throw 'working tree has uncommitted changes: results must name an exact commit' }
$commit = (git rev-parse --short HEAD).Trim()
cargo build --release --locked -p rustegon-bench
if ($LASTEXITCODE -ne 0) { throw 'release build failed' }

New-Item -ItemType Directory -Force $DataDir | Out-Null
$hostFile = Join-Path $DataDir 'host.json'
& (Join-Path $PSScriptRoot 'bench-host.ps1') -DataDir $DataDir -Out $hostFile

foreach ($workload in $Workloads) {
    for ($r = 1; $r -le $Repetitions; $r++) {
        $store = Join-Path $DataDir ('store-' + [guid]::NewGuid().ToString('N'))
        # Variant = file name after the workload id (`bm-sto-01-16t.toml` -> `16t`), so variants
        # of one benchmark id get distinct result files.
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($workload)
        $id = (Select-String -Path $workload -Pattern '^id\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value.ToLower()
        $variant = if ($stem.StartsWith("$id-")) { $stem.Substring($id.Length + 1) } else { '' }
        $parts = @($variant, $Label, "r$r") | Where-Object { $_ }
        $runLabel = $parts -join '-'
        & target/release/rustegon-bench storage --workload $workload --dir $store `
            --env $Env --commit $commit --host-file $hostFile --label $runLabel --notes $Notes
        $code = $LASTEXITCODE
        Remove-Item -Recurse -Force $store -ErrorAction SilentlyContinue
        if ($code -ne 0) { throw "benchmark failed: $workload run $r" }
    }
}
