# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Host monitor of a soak run (PD-233), started by scripts\soak.ps1: every 10 s one JSON line in
# <work dir>\host.jsonl with what the runner's own probe cannot see. On 2026-11-25 a p99 window
# failed in the minute the laptop ran on battery, and the probe showed nothing but a busier host.
#   t, dt   Unix ms (UTC) of the sample and the seconds since the one before; all values below
#           are for that interval
#   ac      false while on battery
#   busy    busy share of each logical CPU, percent
#   perf    speed of each logical CPU, percent of its nominal frequency
#   disk    the disk under the work dir: wb/rb bytes, wn/rn requests, wms/rms mean ms per request
#   proc    {name: [CPU seconds, MiB written]} of every process with 0.2 s or 1 MiB, protected
#           ones included (Defender, System), which Get-Process cannot read
# scripts\soak-table.py prints them per window. A failure here never touches the run.
param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    # The monitor ends with this process (soak.ps1), also when that one is killed.
    [Parameter(Mandatory = $true)][int]$ParentPid,
    [int]$EverySeconds = 10
)
Add-Type -AssemblyName System.Windows.Forms
$alive = { $null -ne (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue) }
# The runner creates the work dir and refuses an existing one: wait for it.
while ((& $alive) -and -not (Test-Path $WorkDir)) { Start-Sleep -Seconds 1 }
$out = Join-Path $WorkDir "host.jsonl"
$drive = Split-Path -Qualifier $WorkDir
# The disk counters are 32 bit and wrap.
function Wrap32($a, $b) { ([double]$a - [double]$b + 4294967296) % 4294967296 }
function Ms($ticks, $n, $freq) { if ($n) { [math]::Round(1000 * $ticks / $freq / $n, 3) } else { 0 } }

$prev = $null
while (& $alive) {
    try {
        $now = @{
            t    = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            cpu  = @(Get-CimInstance Win32_PerfRawData_Counters_ProcessorInformation |
                    Where-Object Name -NotMatch "_Total" |
                    Sort-Object { [int]($_.Name -split ",")[0] }, { [int]($_.Name -split ",")[1] })
            disk = Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk |
                Where-Object Name -Like "* $drive*" | Select-Object -First 1
            proc = @{}
        }
        $rows = Get-CimInstance Win32_PerfRawData_PerfProc_Process `
            -Property Name, IDProcess, PercentProcessorTime, IOWriteBytesPersec
        foreach ($p in $rows) { if ($p.IDProcess) { $now.proc[[int]$p.IDProcess] = $p } }
        if ($prev) {
            $old = @{}
            foreach ($c in $prev.cpu) { $old[$c.Name] = $c }
            $busy = @(); $perf = @()
            foreach ($c in $now.cpu) {
                $o = $old[$c.Name]
                # PercentProcessorTime is the idle time of the CPU, in 100 ns.
                $idle = ([double]$c.PercentProcessorTime - [double]$o.PercentProcessorTime) /
                    ([double]$c.Timestamp_Sys100NS - [double]$o.Timestamp_Sys100NS)
                $busy += [int][math]::Round(100 * (1 - $idle))
                $base = Wrap32 $c.PercentProcessorPerformance_Base $o.PercentProcessorPerformance_Base
                $perf += if ($base) {
                    [int][math]::Round(([double]$c.PercentProcessorPerformance - [double]$o.PercentProcessorPerformance) / $base)
                } else { 0 }
            }
            $d = $now.disk; $o = $prev.disk
            $wn = Wrap32 $d.AvgDisksecPerWrite_Base $o.AvgDisksecPerWrite_Base
            $rn = Wrap32 $d.AvgDisksecPerRead_Base $o.AvgDisksecPerRead_Base
            $disk = [ordered]@{
                wb  = [double]$d.DiskWriteBytesPersec - [double]$o.DiskWriteBytesPersec
                wn  = $wn
                wms = Ms (Wrap32 $d.AvgDisksecPerWrite $o.AvgDisksecPerWrite) $wn $d.Frequency_PerfTime
                rb  = [double]$d.DiskReadBytesPersec - [double]$o.DiskReadBytesPersec
                rn  = $rn
                rms = Ms (Wrap32 $d.AvgDisksecPerRead $o.AvgDisksecPerRead) $rn $d.Frequency_PerfTime
            }
            # Per process id, then summed by name: instance names (chrome#3) are renumbered
            # when a process exits, ids are not.
            $sum = @{}
            foreach ($id in $now.proc.Keys) {
                $p = $now.proc[$id]; $o = $prev.proc[$id]
                $name = $p.Name -replace "#\d+$", ""
                if (-not $o -or ($o.Name -replace "#\d+$", "") -ne $name) { continue }
                if (-not $sum.ContainsKey($name)) { $sum[$name] = @(0.0, 0.0) }
                $sum[$name][0] += [math]::Max(0, ([double]$p.PercentProcessorTime - [double]$o.PercentProcessorTime) / 1e7)
                $sum[$name][1] += [math]::Max(0, ([double]$p.IOWriteBytesPersec - [double]$o.IOWriteBytesPersec) / 1MB)
            }
            $top = [ordered]@{}
            foreach ($name in ($sum.Keys | Sort-Object)) {
                if ($sum[$name][0] -ge 0.2 -or $sum[$name][1] -ge 1) {
                    $top[$name] = @([math]::Round($sum[$name][0], 2), [math]::Round($sum[$name][1], 1))
                }
            }
            $line = [ordered]@{
                t    = $now.t
                dt   = [math]::Round(($now.t - $prev.t) / 1000, 1)
                ac   = [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus -ne "Offline"
                busy = $busy
                perf = $perf
                disk = $disk
                proc = $top
            }
            [IO.File]::AppendAllText($out, (ConvertTo-Json $line -Compress -Depth 4) + "`n")
        }
        $prev = $now
    } catch {
        # Diagnostic only: note the failure and go on (the work dir may be gone at the end).
        try {
            $e = @{ t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); error = "$_" }
            [IO.File]::AppendAllText($out, (ConvertTo-Json $e -Compress) + "`n")
        } catch {}
    }
    Start-Sleep -Seconds $EverySeconds
}
