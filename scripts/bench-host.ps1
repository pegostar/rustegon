# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Writes the host part of the benchmark environment manifest (performance-benchmarks.md §2:
# hardware, OS, file system, toolchain) as JSON, for `rustegon-bench storage --host-file`.
# Usage: powershell -NoProfile -File scripts/bench-host.ps1 -DataDir <bench dir> -Out <file.json>
param(
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'

$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$full = (Resolve-Path -LiteralPath $DataDir).Path
$letter = $full.Substring(0, 1)
$vol = Get-Volume -DriveLetter $letter
$part = Get-Partition -DriveLetter $letter
$disk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq [string]$part.DiskNumber } | Select-Object -First 1
$plan = (powercfg /getactivescheme) -join ' '

$host_info = [ordered]@{
    cpu_model        = $cpu.Name.Trim()
    cpu_cores        = $cpu.NumberOfCores
    cpu_logical      = $cpu.NumberOfLogicalProcessors
    cpu_max_mhz      = $cpu.MaxClockSpeed
    ram_bytes        = [int64]$cs.TotalPhysicalMemory
    os               = $os.Caption
    os_version       = $os.Version
    os_build         = $os.BuildNumber
    data_dir         = $full
    filesystem       = $vol.FileSystem
    allocation_unit  = $vol.AllocationUnitSize
    volume_size      = [int64]$vol.Size
    volume_free      = [int64]$vol.SizeRemaining
    disk_model       = $disk.FriendlyName
    disk_media       = [string]$disk.MediaType
    disk_bus         = [string]$disk.BusType
    disk_size        = [int64]$disk.Size
    power_plan       = $plan
    # Win32_Battery.BatteryStatus 2 = on AC power; absent on desktops (laptop throughput depends
    # on it).
    battery_status   = [string](Get-CimInstance Win32_Battery | Select-Object -First 1).BatteryStatus
    rustc            = (rustc -V)
    cargo            = (cargo -V)
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
}
# UTF-8 without BOM: Windows PowerShell 5.1's `Out-File -Encoding utf8` writes a BOM, which
# JSON parsers reject.
$json = $host_info | ConvertTo-Json
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Out), $json, (New-Object System.Text.UTF8Encoding $false))
