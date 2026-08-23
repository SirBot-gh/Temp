# Sanitize-DeviceState.ps1 test runner (no Pester required)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'Sanitize-DeviceState.ps1'
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$outRoot = Join-Path $PSScriptRoot '_test-out'

function Assert-True($cond, [string]$msg) {
    if (-not $cond) { throw "FAIL: $msg" }
}

function Assert-False($cond, [string]$msg) {
    if ($cond) { throw "FAIL: $msg" }
}

function Assert-Eq($a, $b, [string]$msg) {
    if ($a -ne $b) { throw "FAIL: $msg (expected '$b', got '$a')" }
}

function Clean-Out {
    if (Test-Path -LiteralPath $outRoot) {
        Remove-Item -LiteralPath $outRoot -Recurse -Force
    }
}

function Run-Sanitize {
    param(
        [string]$InputPath,
        [switch]$Force
    )
    $invokeArgs = @(
        '-NoProfile', '-File', $scriptPath,
        '-InputPath', $InputPath,
        '-OutputRoot', $outRoot
    )
    if ($Force) { $invokeArgs += '-Force' }
    & $psExe @invokeArgs
    return $LASTEXITCODE
}

function Join-MultiPath {
    param([Parameter(Mandatory)][string[]]$Parts)
    $p = $Parts[0]
    foreach ($part in $Parts[1..($Parts.Length - 1)]) {
        $p = Join-Path $p $part
    }
    return $p
}

function Get-ManifestJson([string]$bundleName) {
    $p = Join-MultiPath @($outRoot, $bundleName, 'MANIFEST.json')
    return Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
}

function Get-PowerShellExe {
    foreach ($cmd in @('pwsh', 'powershell')) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) { return $cmd }
    }
    throw 'PowerShell not found (install pwsh or Windows PowerShell)'
}

$psExe = Get-PowerShellExe

Write-Host '=== Sanitize-DeviceState tests ===' -ForegroundColor Cyan
# --- Sample device_state_cfg.tar ---
Clean-Out
$code = Run-Sanitize -InputPath (Join-Path $fixtures 'device_state_cfg.tar') -Force
Assert-Eq $code 0 'device_state_cfg exit code'
$bundleDir = Join-Path $outRoot 'device_state_cfg'
$txtFiles = @(Get-ChildItem -LiteralPath $bundleDir -Recurse -File -Filter '*.txt' |
    Where-Object { $_.Name -notlike 'MANIFEST*' })
Assert-Eq $txtFiles.Count 5 'device_state_cfg output file count'

$manifest = Get-ManifestJson 'device_state_cfg'
$running = $manifest.files | Where-Object { $_.source -eq 'running-config.xml' }
Assert-Eq $running.tier1_redacted_values 3 'running-config tier1 count'
Assert-Eq $running.safety_net_hits 0 'running-config safety_net'
Assert-Eq ($manifest.totals.safety_net_total) 0 'total safety_net sample'

$runningTxt = Join-Path $bundleDir 'running-config.txt'
$runningContent = Get-Content -LiteralPath $runningTxt -Raw
Assert-Eq ([regex]::Matches($runningContent, 'REDACTED').Count) 3 'REDACTED count in running-config'
Assert-False ($runningContent -match '\$5\$') 'no $5$ hashes in running-config'
Assert-True ($runningContent -match '<hostname>PA-VM</hostname>') 'hostname preserved'

$knobSrc = Join-MultiPath @($fixtures, 'device_state_cfg', 'knob-setting.xml')
$knobOut = Join-Path $bundleDir 'knob-setting.txt'
$knobBytesIn = [IO.File]::ReadAllBytes($knobSrc)
$knobBytesOut = [IO.File]::ReadAllBytes($knobOut)
Assert-Eq $knobBytesIn.Length $knobBytesOut.Length 'knob-setting byte length'
for ($i = 0; $i -lt $knobBytesIn.Length; $i++) {
    if ($knobBytesIn[$i] -ne $knobBytesOut[$i]) {
        throw "FAIL: knob-setting byte mismatch at offset $i"
    }
}

Write-Host 'PASS device_state_cfg.tar' -ForegroundColor Green

# --- Canary fixture ---
Clean-Out
$code = Run-Sanitize -InputPath (Join-Path $fixtures 'canary_device_state.tar') -Force
Assert-Eq $code 3 'canary exit code (parse failure)'
$canaryDir = Join-Path $outRoot 'canary_device_state'
$spOut = Join-MultiPath @($canaryDir, 'sp', 'vsys1', 'pretrans-sp-config.txt')
$templateOut = Join-MultiPath @($canaryDir, 'template', 'pretrans-template-config.txt')
Assert-True (Test-Path -LiteralPath $spOut) 'sp output path'
Assert-True (Test-Path -LiteralPath $templateOut) 'template output path'
Assert-False (Test-Path -LiteralPath (Join-Path $canaryDir 'broken.txt')) 'no broken.txt'

$canaryManifest = Get-ManifestJson 'canary_device_state'
$roles = @($canaryManifest.files | Where-Object { $_.status -eq 'OK' } | ForEach-Object { $_.role })
Assert-True ($roles -contains 'local-config') 'role local-config'
Assert-True ($roles -contains 'pushed-template') 'role pushed-template'
Assert-True ($roles -contains 'pushed-device-group') 'role pushed-device-group'

$runningCanary = Get-Content -LiteralPath (Join-Path $canaryDir 'running-config.txt') -Raw
Assert-False ($runningCanary -match 'CANARY-') 'no CANARY strings in output'

$runRow = $canaryManifest.files | Where-Object { $_.source -eq 'running-config.xml' }
Assert-Eq $runRow.safety_net_hits 1 'canary safety_net on running-config'

$brokenRow = $canaryManifest.files | Where-Object { $_.source -eq 'broken.xml' }
Assert-Eq $brokenRow.status 'FAILED' 'broken.xml FAILED'
$skipped = $canaryManifest.files | Where-Object { $_.source -eq 'foo.log' }
Assert-Eq $skipped.status 'SKIPPED' 'foo.log SKIPPED'

Write-Host 'PASS canary_device_state.tar' -ForegroundColor Green

# --- TESTFW-01 (filename-agnostic classification) ---
Clean-Out
$code = Run-Sanitize -InputPath (Join-Path $fixtures 'TESTFW-01_device_state.tgz') -Force
Assert-Eq $code 0 'TESTFW-01 exit code'
$tfwManifest = Get-ManifestJson 'TESTFW-01_device_state'
$tfwRoles = @($tfwManifest.files | Where-Object { $_.status -eq 'OK' } | ForEach-Object { $_.role })
Assert-True ($tfwRoles -contains 'local-config') 'TESTFW local-config'
Assert-True ($tfwRoles -contains 'pushed-template') 'TESTFW pushed-template'
Assert-True ($tfwRoles -contains 'pushed-device-group') 'TESTFW pushed-device-group'

$tfwOut = Join-Path $outRoot 'TESTFW-01_device_state'
$allTxt = Get-Content -LiteralPath (Join-Path $tfwOut 'running-config.txt') -Raw
Assert-False ($allTxt -match 'TESTHASH|CANARY-COMMUNITY') 'TESTFW secrets redacted'

Write-Host 'PASS TESTFW-01_device_state.tgz' -ForegroundColor Green

Write-Host ''
Write-Host 'All tests passed.' -ForegroundColor Green
