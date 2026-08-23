<#
.SYNOPSIS
  Sanitize PAN-OS device state bundles: redact secrets in every XML file and
  write upload-safe .txt copies with paths preserved.

.DESCRIPTION
  Accepts a device state archive (.tar / .tgz / .tar.gz) or an extracted folder,
  redacts known secret-bearing XML elements to the literal string REDACTED, runs a
  regex safety-net pass, verifies output, and writes MANIFEST.txt plus MANIFEST.json.
  Output is well-formed XML text with a .txt extension for tools that reject .xml.

  Never upload the raw bundle or unredacted extraction — only the sanitized .txt
  files and manifests.

.PARAMETER InputPath
  Path to one archive, one extracted folder, or a folder containing several archives.

.PARAMETER OutputRoot
  Parent folder for per-bundle output subfolders.

.PARAMETER MaskIdentity
  Reserved. Tier 2 identity masking is not implemented in this release.

.PARAMETER Force
  Overwrite an existing per-bundle output subfolder.

.EXAMPLE
  .\Sanitize-DeviceState.ps1 -InputPath .\device_state_cfg.tgz -OutputRoot .\out

.NOTES
  Windows PowerShell 5.1 and PowerShell 7+. $RedactElements is shared with
  Split-PanBundle.ps1 — keep both lists identical.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [switch]$MaskIdentity,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===========================================================================
# CONSTANTS (keep $RedactElements in sync with Split-PanBundle.ps1)
# ===========================================================================

$ScriptVersion = '1.0.0'

$RedactElements = @(
    'phash', 'password', 'private-key', 'public-key', 'preshared-key',
    'bind-password', 'secret', 'api-key', 'auth-password', 'priv-password',
    'community', 'shared-secret', 'client-key', 'master-key',
    'snmp-community-string', 'authpwd', 'privpwd'
)

$IdentityElements = @(
    'hostname', 'serial', 'serial-number'
)

$SafetyNetPatterns = @(
    '\$[156]\$[^\s<]{1,120}',
    '-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----',
    '(?i)(?<=<(?!(?:password-complexity|password-profile)(?:\s|>))[^>]*(?:key|secret|passw)[^>]*>)[^<]{8,}'
)

$OutputExtension = '.txt'
$ArchiveExtensions = @('.tar', '.tgz', '.gz')
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

# ===========================================================================
# HELPERS
# ===========================================================================

function Normalize-PathForIo([string]$Path) {
    if ($Path.Length -gt 259 -and -not $Path.StartsWith('\\?\')) {
        if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
        return '\\?\' + $Path
    }
    return $Path
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath (Normalize-PathForIo $Path) -Algorithm SHA256).Hash
}

function Resolve-InputBundles {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Input path does not exist: $Path"
    }

    $full = (Resolve-Path -LiteralPath $Path).Path
    $bundles = New-Object System.Collections.Generic.List[object]

    if (Test-Path -LiteralPath $full -PathType Leaf) {
        $item = Get-Item -LiteralPath $full
        $ext = $item.Extension.ToLowerInvariant()
        $isArchive = ($ext -in '.tar', '.tgz') -or ($item.Name -like '*.tar.gz')
        if (-not $isArchive) {
            throw "Input file must be .tar, .tgz, or .tar.gz: $full"
        }
        $bundles.Add([pscustomobject]@{
            Name = [IO.Path]::GetFileNameWithoutExtension($item.Name) -replace '\.tar$', ''
            Kind = 'Archive'
            Path = $item.FullName
        })
        return $bundles
    }

    $children = Get-ChildItem -LiteralPath $full -File -Force
    $archives = $children | Where-Object {
        $_.Extension.ToLowerInvariant() -in '.tar', '.tgz' -or $_.Name -like '*.tar.gz'
    }

    if ($archives) {
        foreach ($a in $archives) {
            $bundles.Add([pscustomobject]@{
                Name = [IO.Path]::GetFileNameWithoutExtension($a.Name) -replace '\.tar$', ''
                Kind = 'Archive'
                Path = $a.FullName
            })
        }
        return $bundles
    }

    $bundles.Add([pscustomobject]@{
        Name = Split-Path -Leaf $full
        Kind = 'Folder'
        Path = $full
    })
    return $bundles
}

function Get-TarCommand {
    if (Get-Command tar -ErrorAction SilentlyContinue) { return 'tar' }
    $tarExe = Join-Path $env:WINDIR 'System32\tar.exe'
    if (Test-Path -LiteralPath $tarExe) { return $tarExe }
    throw 'tar is not available. On Windows, tar.exe ships with Windows 10 1803+ / Server 2019+.'
}

function Expand-NestedArchives {
    param([string]$Root, [string]$TarCmd)

    Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
        Where-Object {
            $_.Extension.ToLowerInvariant() -in '.tar', '.tgz', '.gz' -and
            ($_.Name -like '*.tar.gz' -or $_.Extension.ToLowerInvariant() -in '.tar', '.tgz')
        } |
        ForEach-Object {
            $nestedDir = Join-Path $_.DirectoryName $_.BaseName
            if (Test-Path -LiteralPath $nestedDir) { return }
            New-Item -ItemType Directory -Force -Path $nestedDir | Out-Null
            & $TarCmd -xzf $_.FullName -C $nestedDir 2>$null
            if ($LASTEXITCODE -ne 0) {
                & $TarCmd -xf $_.FullName -C $nestedDir 2>$null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Nested file is not a tar ($($_.Name)); left packed"
                }
            }
        }
}

function Expand-Bundle {
    param(
        [string]$ArchivePath,
        [string]$TarCmd
    )

    $temp = Join-Path $env:TEMP ("sds_" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    & $TarCmd -xzf $ArchivePath -C $temp 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $TarCmd -xf $ArchivePath -C $temp
        if ($LASTEXITCODE -ne 0) {
            Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
            throw "tar failed on $ArchivePath"
        }
    }
    Expand-NestedArchives -Root $temp -TarCmd $TarCmd
    return $temp
}

function Read-XmlText {
    param([string]$Path)

    $bytes = [IO.File]::ReadAllBytes((Normalize-PathForIo $Path))
    if ($bytes.Length -eq 0) { throw 'Empty file' }

    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $offset = 3
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }

    return $Utf8NoBom.GetString($bytes, $offset, $bytes.Length - $offset)
}

function Classify-PanXml {
    param([System.Xml.XmlDocument]$Doc)

    $root = $Doc.DocumentElement.Name
    $hasDeviceconfig = $Doc.SelectNodes('//deviceconfig/system').Count -gt 0
    $hasMgtConfig    = $Doc.SelectNodes('//mgt-config').Count -gt 0
    $hasTemplate     = ($root -eq 'template') -or ($Doc.SelectNodes('/config/template').Count -gt 0)
    $hasDg           = ($root -eq 'device-group') -or
                       ($Doc.SelectNodes('//device-group').Count -gt 0) -or
                       ($Doc.SelectNodes('//pre-rulebase').Count -gt 0) -or
                       ($Doc.SelectNodes('//post-rulebase').Count -gt 0)

    if ($hasTemplate)                        { return 'pushed-template' }
    if ($hasDg -and -not $hasDeviceconfig)   { return 'pushed-device-group' }
    if ($root -eq 'config' -and ($hasDeviceconfig -or $hasMgtConfig)) { return 'local-config' }
  return 'other'
}

function Invoke-Tier1Redaction {
    param([System.Xml.XmlDocument]$Doc)

    $count = 0
    foreach ($name in $RedactElements) {
        foreach ($n in $Doc.SelectNodes("//*[local-name()='$name']")) {
            if ($n.InnerText.Length -gt 0) {
                $n.InnerText = 'REDACTED'
                $count++
            }
        }
        foreach ($a in $Doc.SelectNodes("//@*[local-name()='$name']")) {
            if ($a.Value.Length -gt 0) {
                $a.Value = 'REDACTED'
                $count++
            }
        }
    }
    return $count
}

function ConvertTo-XmlString {
    param([System.Xml.XmlDocument]$Doc)

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $false
    $settings.OmitXmlDeclaration = $false
    $settings.Encoding = $Utf8NoBom
    $settings.NewLineHandling = [System.Xml.NewLineHandling]::None

    $sb = New-Object System.Text.StringBuilder
    $writer = [System.Xml.XmlWriter]::Create($sb, $settings)
    try { $Doc.Save($writer) }
    finally { $writer.Close() }
    return $sb.ToString()
}

function Invoke-SafetyNet {
    param([string]$Text)

    $hits = 0
    $out = $Text
    foreach ($pattern in $SafetyNetPatterns) {
        $matches = [regex]::Matches($out, $pattern)
        foreach ($m in $matches) {
            if ($m.Value -eq 'REDACTED') { continue }
            if ($m.Value.Trim().Length -lt 8) { continue }
            $hits++
            $out = $out.Replace($m.Value, 'REDACTED')
        }
    }
    return [pscustomobject]@{ Text = $out; Hits = $hits }
}

function Test-OutputClean {
    param(
        [string]$BundleOut,
        [System.Collections.Generic.List[string]]$WrittenFiles
    )

    foreach ($rel in $WrittenFiles) {
        $path = Join-Path $BundleOut $rel
        $text = [IO.File]::ReadAllText((Normalize-PathForIo $path), $Utf8NoBom)

        foreach ($pattern in $SafetyNetPatterns) {
            foreach ($m in [regex]::Matches($text, $pattern)) {
                if ($m.Value -ne 'REDACTED') {
                    return [pscustomobject]@{
                        Ok = $false
                        File = $rel
                        Detail = "safety-net pattern matched: $($m.Value.Substring(0, [Math]::Min(40, $m.Value.Length)))"
                    }
                }
            }
        }

        try {
            $doc = New-Object System.Xml.XmlDocument
            $doc.PreserveWhitespace = $true
            $doc.LoadXml($text)
            foreach ($name in $RedactElements) {
                foreach ($n in $doc.SelectNodes("//*[local-name()='$name']")) {
                    if ($n.InnerText.Length -gt 0 -and $n.InnerText -ne 'REDACTED') {
                        return [pscustomobject]@{
                            Ok = $false
                            File = $rel
                            Detail = "tier1 element '$name' still has value"
                        }
                    }
                }
                foreach ($a in $doc.SelectNodes("//@*[local-name()='$name']")) {
                    if ($a.Value.Length -gt 0 -and $a.Value -ne 'REDACTED') {
                        return [pscustomobject]@{
                            Ok = $false
                            File = $rel
                            Detail = "tier1 attribute '$name' still has value"
                        }
                    }
                }
            }
        } catch {
            return [pscustomobject]@{
                Ok = $false
                File = $rel
                Detail = "verification re-parse failed: $($_.Exception.Message)"
            }
        }
    }

    return [pscustomobject]@{ Ok = $true; File = ''; Detail = '' }
}

function Write-Manifest {
    param(
        [string]$BundleOut,
        [object[]]$Rows,
        [hashtable]$Header
    )

    $txtPath = Join-Path $BundleOut 'MANIFEST.txt'
    $jsonPath = Join-Path $BundleOut 'MANIFEST.json'

    $lines = @(
        "Sanitize-DeviceState $ScriptVersion"
        "timestamp_utc=$($Header['timestamp_utc'])"
        "input=$($Header['input'])"
        "mask_identity=$($Header['mask_identity'])"
        "exit_status=$($Header['exit_status'])"
        "files_ok=$($Header['files_ok'])"
        "files_failed=$($Header['files_failed'])"
        "files_skipped=$($Header['files_skipped'])"
        "tier1_total=$($Header['tier1_total'])"
        "safety_net_total=$($Header['safety_net_total'])"
        ''
    )

    foreach ($row in $Rows) {
        if ($row.status -eq 'SKIPPED') {
            $lines += "SKIPPED $($row.source) ($($row.bytes_in) bytes)"
            continue
        }
        $lines += @(
            "FILE $($row.source)"
            "  output=$($row.output)"
            "  role=$($row.role)"
            "  bytes_in=$($row.bytes_in)"
            "  bytes_out=$($row.bytes_out)"
            "  tier1_redacted_values=$($row.tier1_redacted_values)"
            "  tier2_masked_values=$($row.tier2_masked_values)"
            "  safety_net_hits=$($row.safety_net_hits)"
            "  sha256=$($row.sha256)"
            "  status=$($row.status)"
            ''
        )
    }

    [IO.File]::WriteAllLines((Normalize-PathForIo $txtPath), $lines, $Utf8NoBom)

    $payload = @{
        script_version   = $ScriptVersion
        timestamp_utc    = $Header['timestamp_utc']
        input            = $Header['input']
        mask_identity    = $Header['mask_identity']
        exit_status      = $Header['exit_status']
        totals           = @{
            files_ok       = $Header['files_ok']
            files_failed   = $Header['files_failed']
            files_skipped  = $Header['files_skipped']
            tier1_total    = $Header['tier1_total']
            safety_net_total = $Header['safety_net_total']
        }
        files = $Rows
    }
    $json = $payload | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText((Normalize-PathForIo $jsonPath), $json, $Utf8NoBom)
}

function Get-XmlFiles {
    param([string]$Root)

    Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
        Where-Object {
            $name = $_.Name
            $name -match '(?i)\.xml$' -or $name -match '^\..*\.xml$'
        }
}

function Process-Bundle {
    param(
        [object]$Bundle,
        [string]$OutputRoot,
        [string]$TarCmd,
        [bool]$UseForce,
        [bool]$WhatIfMode
    )

    $bundleOut = Join-Path $OutputRoot $Bundle.Name
    $inputFull = (Resolve-Path -LiteralPath $Bundle.Path).Path
    $outRootFull = (Resolve-Path -LiteralPath $OutputRoot).Path

    if ($inputFull.StartsWith($outRootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'InputPath must not be inside OutputRoot (prevents mixing raw and sanitized output).'
    }

    if ((Test-Path -LiteralPath $bundleOut) -and -not $UseForce) {
        throw "Output subfolder already exists: $bundleOut (use -Force to overwrite)"
    }

    $tempDir = $null
    $parseFailures = 0
    $manifestRows = New-Object System.Collections.Generic.List[object]
    $writtenRelPaths = New-Object System.Collections.Generic.List[string]
    $tier1Total = 0
    $safetyNetTotal = 0
    $filesOk = 0
    $filesFailed = 0
    $filesSkipped = 0

    try {
        if ($Bundle.Kind -eq 'Archive') {
            $extractRoot = Expand-Bundle -ArchivePath $Bundle.Path -TarCmd $TarCmd
            $tempDir = $extractRoot
        } else {
            $extractRoot = $Bundle.Path
        }

        $spDir = Join-Path $extractRoot 'sp'
        $templateDir = Join-Path $extractRoot 'template'
        if ((Test-Path -LiteralPath $spDir) -and -not (Get-XmlFiles -Root $spDir)) {
            Write-Warning "sp/ folder exists but contains no XML — export may be out of sync with Panorama."
        }
        if ((Test-Path -LiteralPath $templateDir) -and -not (Get-XmlFiles -Root $templateDir)) {
            Write-Warning "template/ folder exists but contains no XML — export may be out of sync with Panorama."
        }

        $allFiles = Get-ChildItem -LiteralPath $extractRoot -Recurse -File -Force
        $xmlFiles = Get-XmlFiles -Root $extractRoot

        $xmlFullNames = @($xmlFiles | ForEach-Object { $_.FullName })
        foreach ($f in $allFiles) {
            if ($xmlFullNames -contains $f.FullName) { continue }
            $rel = $f.FullName.Substring($extractRoot.Length).TrimStart('\', '/')
            $filesSkipped++
            $manifestRows.Add([pscustomobject]@{
                source = $rel
                output = ''
                role = 'non-xml'
                bytes_in = $f.Length
                bytes_out = 0
                tier1_redacted_values = 0
                tier2_masked_values = 0
                safety_net_hits = 0
                sha256 = ''
                status = 'SKIPPED'
            })
        }

        if ($WhatIfMode) {
            foreach ($f in $xmlFiles) {
                $rel = $f.FullName.Substring($extractRoot.Length).TrimStart('\', '/')
                $outRel = [IO.Path]::ChangeExtension($rel, $OutputExtension)
                Write-Verbose "Would write $outRel"
            }
            return 0
        }

        if (Test-Path -LiteralPath $bundleOut) {
            Remove-Item -LiteralPath $bundleOut -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $bundleOut | Out-Null

        foreach ($f in $xmlFiles) {
            $rel = $f.FullName.Substring($extractRoot.Length).TrimStart('\', '/')
            $outRel = [IO.Path]::ChangeExtension($rel, $OutputExtension)
            $outPath = Join-Path $bundleOut $outRel
            $bytesIn = $f.Length

            try {
                $rawText = Read-XmlText -Path $f.FullName
                $doc = New-Object System.Xml.XmlDocument
                $doc.PreserveWhitespace = $true
                $doc.LoadXml($rawText)

                $role = Classify-PanXml -Doc $doc
                $tier1 = Invoke-Tier1Redaction -Doc $doc
                $tier2 = 0

                if ($tier1 -gt 0) {
                    $serialized = ConvertTo-XmlString -Doc $doc
                    $sn = Invoke-SafetyNet -Text $serialized
                    $writeBytes = $null
                } else {
                    $sn = Invoke-SafetyNet -Text $rawText
                    if ($sn.Hits -eq 0) {
                        $sn = [pscustomobject]@{ Text = $rawText; Hits = 0 }
                        $writeBytes = [IO.File]::ReadAllBytes((Normalize-PathForIo $f.FullName))
                    } else {
                        $writeBytes = $null
                    }
                }
                $tier1Total += $tier1
                $safetyNetTotal += $sn.Hits

                $parent = Split-Path -Parent $outPath
                if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                    New-Item -ItemType Directory -Force -Path $parent | Out-Null
                }

                if ($writeBytes) {
                    [IO.File]::WriteAllBytes((Normalize-PathForIo $outPath), $writeBytes)
                } else {
                    [IO.File]::WriteAllText((Normalize-PathForIo $outPath), $sn.Text, $Utf8NoBom)
                }
                $writtenRelPaths.Add($outRel)
                $bytesOut = ([IO.File]::ReadAllBytes((Normalize-PathForIo $outPath))).Length
                $filesOk++

                $manifestRows.Add([pscustomobject]@{
                    source = $rel
                    output = $outRel
                    role = $role
                    bytes_in = $bytesIn
                    bytes_out = $bytesOut
                    tier1_redacted_values = $tier1
                    tier2_masked_values = $tier2
                    safety_net_hits = $sn.Hits
                    sha256 = Get-Sha256 $outPath
                    status = 'OK'
                })
            } catch {
                $filesFailed++
                $parseFailures++
                $manifestRows.Add([pscustomobject]@{
                    source = $rel
                    output = ''
                    role = 'other'
                    bytes_in = $bytesIn
                    bytes_out = 0
                    tier1_redacted_values = 0
                    tier2_masked_values = 0
                    safety_net_hits = 0
                    sha256 = ''
                    status = 'FAILED'
                })
                Write-Verbose "FAILED $rel : $($_.Exception.Message)"
            }
        }

        $verify = Test-OutputClean -BundleOut $bundleOut -WrittenFiles $writtenRelPaths
        if (-not $verify.Ok) {
            Write-Host "VERIFICATION FAILED: $($verify.File) — $($verify.Detail)" -ForegroundColor Red
            Remove-Item -LiteralPath $bundleOut -Recurse -Force
            return 2
        }

        $exitForBundle = if ($parseFailures -gt 0) { 3 } else { 0 }
        $header = @{
            timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
            input            = $Bundle.Path
            mask_identity    = $false
            exit_status      = $exitForBundle
            files_ok         = $filesOk
            files_failed     = $filesFailed
            files_skipped    = $filesSkipped
            tier1_total      = $tier1Total
            safety_net_total = $safetyNetTotal
        }
        Write-Manifest -BundleOut $bundleOut -Rows $manifestRows -Header $header

        return $exitForBundle
    } finally {
        if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ===========================================================================
# MAIN
# ===========================================================================

if ($MaskIdentity) {
    Write-Host 'MaskIdentity is reserved but not implemented in this release.' -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
}

$outRootResolved = (Resolve-Path -LiteralPath $OutputRoot).Path
$inputResolved = $null
try {
    $inputResolved = (Resolve-Path -LiteralPath $InputPath).Path
} catch {
    Write-Host "Input error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($inputResolved.StartsWith($outRootResolved, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host 'InputPath must not be inside OutputRoot.' -ForegroundColor Red
    exit 1
}

try {
    $tarCmd = Get-TarCommand
    $bundles = Resolve-InputBundles -Path $InputPath
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

$whatIfMode = $false
if ($WhatIfPreference) { $whatIfMode = $true }

$maxExit = 0
foreach ($bundle in $bundles) {
    Write-Verbose "Processing $($bundle.Name) ($($bundle.Kind))"
    $code = Process-Bundle -Bundle $bundle -OutputRoot $outRootResolved -TarCmd $tarCmd `
        -UseForce $Force.IsPresent -WhatIfMode $whatIfMode
    if ($code -gt $maxExit) { $maxExit = $code }
}

if (-not $whatIfMode) {
    Write-Host ''
    Write-Host 'Sanitized .txt files are upload-safe; raw bundles and unredacted archives are NOT.' -ForegroundColor Yellow
    Write-Host "Output: $outRootResolved"
}

exit $maxExit
