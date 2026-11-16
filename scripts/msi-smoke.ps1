# SPDX-License-Identifier: Apache-2.0
# Copyright The Rustegon Authors
#
# Owner's manual check of the turnkey MSI on a real machine (FR-INS-001, ADR-036, TC-INS-015,
# windows.md §10). It INSTALLS Rustegon machine-wide, so run it only on a test machine or VM,
# from an elevated Windows PowerShell, with no Rustegon installed and no C:\ProgramData\Rustegon:
#
#   powershell -ExecutionPolicy Bypass -File scripts\msi-smoke.ps1 [-Msi dist\rustegon-…msi] [-KeepInstalled]
#
# Steps: install (silent, verbose log) → service `Rustegon` running as NT SERVICE\Rustegon →
# GET /api/v1/health/ready = 200 on 127.0.0.1:7780 and /ui/ served → ProgramData ACL without
# Users → login admin/admin says mustChangePassword and other calls are refused → change the
# password → login with the new one works and admin/admin does not → reinstall over itself
# (upgrade path: init not run again, configuration unchanged, new password still works) →
# uninstall → service gone, program files gone, C:\ProgramData\Rustegon kept → install again
# over the kept node (PD-224: init skipped, configuration unchanged, new password works) → uninstall.
# Leaves C:\ProgramData\Rustegon behind (data-loss rule): delete it by hand afterwards.
param(
    [string]$Msi = '',
    [switch]$KeepInstalled
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function Fail([string]$message) { throw "FAIL: $message" }
function Step([string]$message) { Write-Host "`n== $message" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run this script from an elevated PowerShell'
}
$root = Split-Path -Parent $PSScriptRoot
if (-not $Msi) {
    $Msi = Get-ChildItem (Join-Path $root 'dist') -Filter 'rustegon-*-windows-x86_64.msi' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Msi -or -not (Test-Path $Msi)) { Fail 'no MSI (cargo xtask dist --packages)' }
$Msi = (Resolve-Path $Msi).Path
$programData = Join-Path $env:ProgramData 'Rustegon'
$config = Join-Path $programData 'rustegon.toml'
if (Get-Service Rustegon -ErrorAction SilentlyContinue) { Fail 'a Rustegon service already exists' }
if (Test-Path $config) { Fail "$config exists: this check needs a first install" }
$api = 'http://127.0.0.1:7780'
$logDir = Join-Path $env:TEMP "rustegon-msi-smoke-$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Force $logDir | Out-Null

function Msiexec([string[]]$arguments, [string]$log) {
    $p = Start-Process msiexec.exe -ArgumentList ($arguments + @('/qn', '/l*v', "`"$log`"")) -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { Fail "msiexec $arguments exit $($p.ExitCode), log $log" }
}

function Call([string]$method, [string]$path, $body = $null, [string]$token = '') {
    $headers = @{}
    if ($token) { $headers['Authorization'] = "Bearer $token" }
    $json = if ($null -ne $body) { $body | ConvertTo-Json -Compress } else { $null }
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Method $method -Uri "$api$path" -Headers $headers `
            -ContentType 'application/json' -Body $json
        return @{ Status = [int]$r.StatusCode; Body = $r.Content }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { return @{ Status = 0; Body = $_.Exception.Message } }
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        return @{ Status = [int]$resp.StatusCode; Body = $reader.ReadToEnd() }
    }
}

function Wait-Ready {
    $deadline = (Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service Rustegon -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running' -and (Call GET '/api/v1/health/ready').Status -eq 200) { return }
        Start-Sleep -Seconds 2
    }
    Fail "the service did not become ready; logs in $programData\logs"
}

function Login([string]$password) {
    return Call POST '/api/v1/auth/login' @{ user = 'admin'; password = $password; delivery = 'token' }
}

Step "install $Msi"
Msiexec @('/i', "`"$Msi`"") (Join-Path $logDir 'install.log')
Wait-Ready
$svc = Get-CimInstance Win32_Service -Filter "Name='Rustegon'"
if ($svc.StartName -ne 'NT SERVICE\Rustegon') { Fail "service account $($svc.StartName)" }
if ($svc.StartMode -ne 'Auto') { Fail "start mode $($svc.StartMode)" }
if ($svc.PathName -notmatch '--service --config') { Fail "service command line $($svc.PathName)" }
if ((Call GET '/ui/').Status -ne 200) { Fail 'the console is not served on /ui/' }
foreach ($f in @($config, (Join-Path $programData 'data\store'))) {
    if (-not (Test-Path $f)) { Fail "$f missing" }
}
if (-not (Get-ChildItem (Join-Path $programData 'logs'))) { Fail 'no log files in ProgramData\Rustegon\logs' }
$toml = Get-Content -Raw $config
foreach ($want in @('turnkey_admin = true', 'grpc = "127.0.0.1:7700"', 'http = "127.0.0.1:7780"')) {
    if ($toml -notmatch [regex]::Escape($want)) { Fail "configuration lacks $want" }
}
$acl = (Get-Acl $programData).Access | ForEach-Object { $_.IdentityReference.Value }
if (-not ($acl -contains 'NT SERVICE\Rustegon')) { Fail "ProgramData ACL lacks the service account: $acl" }
if ($acl | Where-Object { $_ -match 'Users$|Everyone' }) { Fail "ProgramData ACL exposes the files: $acl" }
if ((Get-Acl $programData).AreAccessRulesProtected -ne $true) { Fail 'ProgramData ACL inherits' }

Step 'admin/admin must change the password first'
$login = Login 'admin'
if ($login.Status -ne 200) { Fail "admin/admin login: $($login.Status) $($login.Body)" }
$session = $login.Body | ConvertFrom-Json
if ($session.mustChangePassword -ne $true) { Fail "mustChangePassword: $($login.Body)" }
$refused = Call GET '/api/v1/databases' $null $session.sessionToken
if ($refused.Status -ne 403 -or $refused.Body -notmatch 'password_change_required') {
    Fail "data plane before the change: $($refused.Status) $($refused.Body)"
}
$newPassword = 'Msi-Smoke-Passw0rd-' + (Get-Random -Minimum 100000 -Maximum 999999)
$changed = Call POST '/api/v1/auth/password' @{ currentPassword = 'admin'; newPassword = $newPassword } $session.sessionToken
if ($changed.Status -ge 300) { Fail "password change: $($changed.Status) $($changed.Body)" }
if ((Login 'admin').Status -eq 200) { Fail 'admin/admin still works' }
$login = Login $newPassword
if ($login.Status -ne 200 -or ($login.Body | ConvertFrom-Json).mustChangePassword) { Fail "new password: $($login.Body)" }
$token = ($login.Body | ConvertFrom-Json).sessionToken
if ((Call GET '/api/v1/databases' $null $token).Status -ne 200) { Fail 'data plane after the change' }
$configHash = (Get-FileHash $config).Hash

Step 'reinstall over the installed product (upgrade path: no init, data kept)'
Msiexec @('/i', "`"$Msi`"", 'REINSTALL=ALL', 'REINSTALLMODE=vomus') (Join-Path $logDir 'reinstall.log')
Wait-Ready
if ((Get-FileHash $config).Hash -ne $configHash) { Fail 'the reinstall changed the configuration' }
if ((Login $newPassword).Status -ne 200) { Fail 'the new password does not work after the reinstall' }

if ($KeepInstalled) { Write-Host "`nMSI smoke passed (left installed)."; exit 0 }
Step 'uninstall keeps C:\ProgramData\Rustegon'
Msiexec @('/x', "`"$Msi`"") (Join-Path $logDir 'uninstall.log')
if (Get-Service Rustegon -ErrorAction SilentlyContinue) { Fail 'the service is still registered' }
if (Test-Path (Join-Path $env:ProgramFiles 'Rustegon\bin\rustegond.exe')) { Fail 'program files left' }
if ((Get-FileHash $config).Hash -ne $configHash) { Fail 'uninstall changed the configuration' }
if (-not (Test-Path (Join-Path $programData 'data\store'))) { Fail 'uninstall removed the data' }

Step 'install again over the kept C:\ProgramData\Rustegon (PD-224: no init, configuration kept)'
Msiexec @('/i', "`"$Msi`"") (Join-Path $logDir 'install-again.log')
Wait-Ready
if ((Get-FileHash $config).Hash -ne $configHash) { Fail 'the second install changed the configuration' }
if (Test-Path (Join-Path $programData 'msi-init')) { Fail 'the msi-init marker was left behind' }
if ((Login $newPassword).Status -ne 200) { Fail 'the new password does not work after the second install' }
Msiexec @('/x', "`"$Msi`"") (Join-Path $logDir 'uninstall-again.log')
if ((Get-FileHash $config).Hash -ne $configHash) { Fail 'the second uninstall changed the configuration' }
Write-Host "`nMSI smoke passed. Logs: $logDir. $programData was kept: delete it by hand when done."
