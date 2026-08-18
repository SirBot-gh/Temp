<#
.SYNOPSIS
  Split PAN-OS device state bundles (device_state_cfg.tgz) or standalone
  running-config XML files into small per-control-area fragments plus a
  manifest, for AI-assisted management plane assessment.

.DESCRIPTION
  For each input bundle or XML file this script:
    1. Extracts the archive (tar.exe, built into Windows 10+).
    2. Identifies every XML file by CONTENT (root element and structural
       markers), never by filename, because bundle-internal filenames are
       undocumented and vary by PAN-OS version.
    3. Classifies each XML as: local-config, pushed-template,
       pushed-device-group / pushed-policy, or other.
    4. Extracts a fixed set of control-area fragments from each config
       via XPath. Missing fragments are recorded as NOT-PRESENT in the
       manifest rather than silently skipped.
    5. Optionally redacts secrets (password hashes, keys, SNMP
       communities) so fragments are safe to paste into an external AI.
    6. Writes MANIFEST.txt and MANIFEST.csv per device with file roles,
       SHA256 hashes of sources, fragment line counts, and ground-truth
       element counts (interfaces, admins, profiles, rules) that the AI
       extraction output must reconcile against.

.PARAMETER InputPath
  A single .tgz/.tar.gz/.xml file, or a folder containing them.

.PARAMETER OutputRoot
  Folder to write per-device output folders into. Created if missing.

.PARAMETER Redact
  Mask secret material in fragments (recommended before AI upload).

.EXAMPLE
  .\Split-PanBundle.ps1 -InputPath C:\assess\bundles -OutputRoot C:\assess\split -Redact

.NOTES
  Windows PowerShell 5.1 compatible. No modules required.
  Read-only with respect to inputs.

  Output layout for an input named DEVICE_device_state.tgz:
    <OutputRoot>\DEVICE_device_state\
      _extracted\       Local evidence copy; remains unredacted.
      fragments\        Extracted XML fragments; redacted when -Redact is used.
      MANIFEST.txt       Human-readable inventory and reconciliation counts.
      MANIFEST.csv.txt   Complete machine-readable manifest, including hashes.

  The Lines field in the CSV has three meanings, determined by Kind:
    source-file / fragment : physical line count
    count                  : number of XML elements matched by the count XPath
    redaction              : number of populated secret elements masked
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [switch]$Redact
)

# Make unexpected PowerShell errors terminating so a partial result is not
# silently presented as complete. Native programs such as tar are checked
# separately through $LASTEXITCODE because this setting does not cover them.
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fragment map: control area -> ordered XPath alternatives. For each control
# area, the first XPath that returns one or more nodes wins; every node returned
# by that XPath is written. Later alternatives are fallbacks and are not also
# written. This prevents the same logical section from being duplicated when a
# more general XPath also matches it.
#
# PAN-OS configuration XML has no namespaces, which keeps these expressions
# simple. The prefixes group the output by assessment area:
#   MGT  management-plane settings       AUTH authentication/authorization
#   IMP  interface management plane      NSC  network security controls
#   SVC  management services             LOG  logging and forwarding
#
# Paths cover common placements in local configs, pushed templates
# (config/devices/... under a template), and pushed device-group policy files.
# ---------------------------------------------------------------------------
$FragmentMap = [ordered]@{
    'MGT_deviceconfig-system' = @(
        "//deviceconfig/system"
    )
    'MGT_setting-management' = @(
        "//deviceconfig/setting/management"
    )
    'AUTH_mgt-config' = @(                       # local users, password-complexity, access settings
        "//mgt-config"
    )
    'AUTH_authentication-profile' = @(
        "//shared/authentication-profile",
        "//vsys/entry/authentication-profile",
        "//authentication-profile"
    )
    'AUTH_certificate-profile' = @(
        "//shared/certificate-profile",
        "//certificate-profile"
    )
    'AUTH_server-profiles' = @(                  # radius/tacplus/ldap/saml/kerberos
        "//shared/server-profile",
        "//server-profile[entry]"               # exclude leaf references inside auth profiles
    )
    'AUTH_admin-role' = @(
        "//shared/admin-role",
        "//admin-role"
    )
    'IMP_interface-mgmt-profiles' = @(
        "//network/profiles/interface-management-profile"
    )
    'IMP_interfaces' = @(
        "//network/interface"
    )
    'NSC_zones' = @(
        "//vsys/entry/zone",
        "//zone"
    )
    'NSC_rulebase-security' = @(                 # local rulebase
        "//vsys/entry/rulebase/security",
        "//rulebase/security"
    )
    'NSC_pre-rulebase-security' = @(             # panorama pushed
        "//pre-rulebase/security"
    )
    'NSC_post-rulebase-security' = @(
        "//post-rulebase/security"
    )
    'NSC_rulebase-nat' = @(
        "//vsys/entry/rulebase/nat",
        "//rulebase/nat",
        "//pre-rulebase/nat",
        "//post-rulebase/nat"
    )
    'NSC_address-objects' = @(                   # needed to resolve rule sources
        "//vsys/entry/address",
        "//shared/address",
        "//address"
    )
    'NSC_address-groups' = @(
        "//vsys/entry/address-group",
        "//shared/address-group",
        "//address-group"
    )
    'SVC_ssl-tls-service-profile' = @(
        "//shared/ssl-tls-service-profile",
        "//ssl-tls-service-profile"
    )
    'SVC_snmp' = @(
        "//deviceconfig/system/snmp-setting",
        "//snmp-setting"
    )
    'LOG_log-settings' = @(
        "//shared/log-settings",
        "//log-settings"
    )
    'LOG_syslog-profiles' = @(
        "//shared/log-settings/syslog",
        "//syslog"
    )
    'MGT_service-routes' = @(
        "//deviceconfig/system/route",
        "//deviceconfig/system/service"
    )
}

# Ground-truth counts are calculated directly from the full in-memory source
# document, not from the smaller fragments. This makes the manifest an
# independent reconciliation checklist: later analysis should account for the
# same number of interfaces, users, profiles, zones, and rules.
#
# XPath's union operator (|), used for nat_rules, combines nodes from several
# rulebase locations into one count without counting the same node twice.
$CountMap = [ordered]@{
    'interfaces_ethernet'      = "//network/interface/ethernet/entry"
    'interfaces_aggregate'     = "//network/interface/aggregate-ethernet/entry"
    'interfaces_loopback'      = "//network/interface/loopback/units/entry"
    'interfaces_tunnel'        = "//network/interface/tunnel/units/entry"
    'interfaces_vlan'          = "//network/interface/vlan/units/entry"
    'mgmt_profiles'            = "//network/profiles/interface-management-profile/entry"
    'admin_users'              = "//mgt-config/users/entry"
    'admin_roles'              = "//admin-role/entry"
    'auth_profiles'            = "//authentication-profile/entry"
    'zones'                    = "//zone/entry"
    'security_rules_local'     = "//rulebase/security/rules/entry"
    'security_rules_pre'       = "//pre-rulebase/security/rules/entry"
    'security_rules_post'      = "//post-rulebase/security/rules/entry"
    'nat_rules'                = "//rulebase/nat/rules/entry | //pre-rulebase/nat/rules/entry | //post-rulebase/nat/rules/entry"
    'permitted_ip_mgt'         = "//deviceconfig/system/permitted-ip/entry"
    'ssl_tls_profiles'         = "//ssl-tls-service-profile/entry"
}

# Exact XML element names whose text values are considered secret-bearing.
# Redaction changes only the in-memory XmlDocument used to create fragments.
# Files in _extracted remain byte-for-byte evidence copies of the input and
# therefore must never be uploaded as redacted output.
$RedactElements = @(
    'phash', 'password', 'private-key', 'public-key', 'preshared-key',
    'bind-password', 'secret', 'api-key', 'auth-password', 'priv-password',
    'community', 'shared-secret', 'client-key', 'master-key',
    'snmp-community-string', 'authpwd', 'privpwd'
)

function Get-Sha256($Path) {
    # Get-FileHash streams the file instead of loading a potentially large
    # bundle into memory. The hash ties each manifest row to exact source or
    # fragment bytes and makes accidental changes detectable.
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function Classify-PanXml {
    param([xml]$Doc, [string]$FileName)

    # Classification deliberately ignores the filename: PAN-OS bundle member
    # names are undocumented and can change between releases. $FileName is
    # retained in the signature for diagnostics/future rules, but structural
    # XML markers are the current source of truth.
    $root = $Doc.DocumentElement.Name
    $hasDeviceconfig = $Doc.SelectNodes("//deviceconfig/system").Count -gt 0
    $hasMgtConfig    = $Doc.SelectNodes("//mgt-config").Count -gt 0
    $hasTemplate     = ($root -eq 'template') -or ($Doc.SelectNodes("/config/template").Count -gt 0)
    $hasDg           = ($root -eq 'device-group') -or
                       ($Doc.SelectNodes("//device-group").Count -gt 0) -or
                       ($Doc.SelectNodes("//pre-rulebase").Count -gt 0) -or
                       ($Doc.SelectNodes("//post-rulebase").Count -gt 0)

    # Rule order matters:
    #   1. A template marker is the strongest template signal.
    #   2. Device-group/policy markers classify as pushed policy only when the
    #      document does not also contain local device configuration.
    #   3. A config root plus management settings identifies a local config.
    #   4. Other config-root documents remain eligible for fragment extraction
    #      as UNCLASS rather than being discarded.
    if ($hasTemplate)                        { return 'pushed-template' }
    if ($hasDg -and -not $hasDeviceconfig)   { return 'pushed-device-group' }
    if ($root -eq 'config' -and ($hasDeviceconfig -or $hasMgtConfig)) { return 'local-config' }
    if ($root -eq 'config')                  { return 'config-unclassified' }
    return 'other'
}

function Redact-Xml {
    param([xml]$Doc)

    # local-name() makes the match independent of any unexpected namespace
    # prefix while still requiring an exact element name from RedactElements.
    # Assigning InnerText replaces all text/child content under the element,
    # ensuring a structured secret cannot survive as a nested child node.
    $count = 0
    foreach ($name in $RedactElements) {
        $nodes = $Doc.SelectNodes("//*[local-name()='$name']")
        foreach ($n in $nodes) {
            # Empty elements are left untouched and are not counted as masked.
            if ($n.InnerText -and $n.InnerText.Trim().Length -gt 0) {
                $n.InnerText = 'REDACTED'
                $count++
            }
        }
    }
    return $count
}

function Save-Fragment {
    param([System.Xml.XmlNode]$Node, [string]$OutFile)

    # XmlWriter produces consistently indented, well-formed XML and includes
    # an XML declaration even though the file uses .xml.txt for upload-tool
    # compatibility. The finally block releases the file handle on any error.
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.OmitXmlDeclaration = $false
    $writer = [System.Xml.XmlWriter]::Create($OutFile, $settings)
    try   { $Node.WriteTo($writer) }
    finally { $writer.Close() }
}

# ---------------------------------------------------------------------------
# Gather inputs
# Folder mode intentionally examines only immediate child files. A recursive
# search could accidentally reprocess prior output trees or unrelated archives.
# .gz is accepted because .tar.gz reports .gz as its final Extension value.
# ---------------------------------------------------------------------------
if (Test-Path $InputPath -PathType Container) {
    $inputs = Get-ChildItem -Path $InputPath -File |
        Where-Object { $_.Extension -in '.tgz', '.gz', '.tar', '.xml' -or $_.Name -like '*.tar.gz' }
} else {
    $inputs = @(Get-Item $InputPath)
}
if (-not $inputs) { throw "No .tgz/.tar.gz/.xml inputs found at $InputPath" }

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

foreach ($item in $inputs) {
    # GetFileNameWithoutExtension removes .tgz/.xml or the final .gz. The
    # replace then removes the remaining .tar from a two-part .tar.gz suffix.
    # The resulting name scopes all generated content for this one input.
    $deviceName = [IO.Path]::GetFileNameWithoutExtension($item.Name) -replace '\.tar$', ''
    $devOut     = Join-Path $OutputRoot $deviceName
    $extractDir = Join-Path $devOut '_extracted'
    $fragDir    = Join-Path $devOut 'fragments'
    $csvPath    = Join-Path $devOut 'MANIFEST.csv.txt'
    $txtPath    = Join-Path $devOut 'MANIFEST.txt'

    # Remove only paths generated by this script. Reusing an output root must
    # not retain fragments or extracted sources from an earlier run. Other
    # user-created files in the per-device directory are intentionally kept.
    foreach ($generatedPath in @($extractDir, $fragDir, $csvPath, $txtPath)) {
        if (Test-Path -LiteralPath $generatedPath) {
            Remove-Item -LiteralPath $generatedPath -Recurse -Force
        }
    }
    New-Item -ItemType Directory -Force -Path $devOut, $extractDir, $fragDir | Out-Null

    Write-Host "=== $($item.Name) -> $devOut" -ForegroundColor Cyan

    # A generic List avoids repeatedly copying an array as rows are appended.
    # Every row uses the same columns so it can later be exported directly.
    $manifest = New-Object System.Collections.Generic.List[object]
    $sourceXmls = @()

    # --- 1. Extract or copy -------------------------------------------------
    if ($item.Extension -eq '.xml') {
        # Copy standalone XML into the same evidence layout used for archives;
        # all later inventory/classification logic can then follow one path.
        Copy-Item $item.FullName -Destination $extractDir
    } else {
        # PAN-OS commonly emits gzip-compressed tar archives. tar.exe ships
        # with supported Windows 10/11 versions, so no PowerShell module is
        # required. Suppress the expected first-attempt error because some
        # exports use a .tgz-like name while containing an uncompressed tar.
        & tar -xzf $item.FullName -C $extractDir 2>$null
        if ($LASTEXITCODE -ne 0) {
            # Retry without gzip decompression for a plain tar archive.
            & tar -xf $item.FullName -C $extractDir
            if ($LASTEXITCODE -ne 0) { Write-Warning "tar failed on $($item.Name); skipping"; continue }
        }

        # Some device-state exports wrap component archives inside the outer
        # bundle. Expand one additional level only: this covers that layout
        # without recursively unpacking arbitrary archive trees forever.
        Get-ChildItem $extractDir -Recurse -File |
            Where-Object { $_.Extension -in '.tgz', '.gz', '.tar' } |
            ForEach-Object {
                $nested = Join-Path $extractDir ("nested_" + $_.BaseName)
                New-Item -ItemType Directory -Force -Path $nested | Out-Null
                & tar -xzf $_.FullName -C $nested 2>$null
                # As above, tolerate nested archives that are plain tar files.
                if ($LASTEXITCODE -ne 0) { & tar -xf $_.FullName -C $nested 2>$null }
            }
    }

    # --- 2/3. Inventory + classify every XML by content ---------------------
    $allFiles = Get-ChildItem $extractDir -Recurse -File
    foreach ($f in $allFiles) {
        # Every extracted member receives a source-file manifest row, including
        # non-XML files and malformed XML. Only recognized configuration roles
        # are added to $sourceXmls for fragment extraction.
        $role = 'non-xml'
        $rootEl = ''
        $relativeName = $f.FullName.Substring($extractDir.Length + 1)

        # Extension is the inexpensive signal. The first-line fallback catches
        # XML stored under undocumented/non-.xml names. Parsing remains inside
        # try/catch because a leading '<' alone does not prove valid XML.
        if ($f.Extension -eq '.xml' -or (Get-Content $f.FullName -TotalCount 1 -ErrorAction SilentlyContinue) -match '^\s*<\?xml|^\s*<') {
            try {
                # Casting to [xml] creates the XmlDocument used for XPath,
                # classification, optional redaction, and fragment writing.
                [xml]$doc = Get-Content $f.FullName -Raw
                $rootEl = $doc.DocumentElement.Name
                $role = Classify-PanXml -Doc $doc -FileName $f.Name
                if ($role -in 'local-config', 'pushed-template', 'pushed-device-group', 'config-unclassified') {
                    $sourceXmls += [pscustomobject]@{
                        File = $f; Doc = $doc; Role = $role; RelativeName = $relativeName
                    }
                }
            } catch {
                # Keep the failed member in the inventory instead of aborting
                # the entire device bundle because one auxiliary file is bad.
                $role = 'xml-parse-failed'
            }
        }

        # Hash the extracted bytes, not the parsed/redacted XML. This preserves
        # provenance back to the exact archive member used as local evidence.
        $manifest.Add([pscustomobject]@{
            Kind = 'source-file'; Name = $relativeName
            Role = $role; RootElement = $rootEl
            Lines = (Get-Content $f.FullName -ErrorAction SilentlyContinue | Measure-Object).Count
            SHA256 = Get-Sha256 $f.FullName; Detail = ''
        })
    }

    if (-not ($sourceXmls | Where-Object Role -eq 'local-config')) {
        # Pushed-only bundles may be legitimate, so this is a warning rather
        # than a terminating error. Manual manifest review is required.
        Write-Warning "No local-config identified in $($item.Name). Check manifest before proceeding."
    }

    # --- 4. Fragment extraction from every classified source ----------------
    # A normal bundle has one source per role and retains the traditional
    # LOCAL/TEMPLATE/DEVGROUP prefixes. If a bundle has multiple sources with
    # the same role, add a stable per-source suffix to prevent overwrites.
    $roleTotals = @{}
    foreach ($src in $sourceXmls) {
        # Hashtable keys are role names; values are the number of source XML
        # documents assigned to that role in this one bundle.
        if (-not $roleTotals.ContainsKey($src.Role)) { $roleTotals[$src.Role] = 0 }
        $roleTotals[$src.Role]++
    }
    $roleIndexes = @{}

    foreach ($src in $sourceXmls) {
        $basePrefix = switch ($src.Role) {
            'local-config'        { 'LOCAL' }
            'pushed-template'     { 'TEMPLATE' }
            'pushed-device-group' { 'DEVGROUP' }
            default               { 'UNCLASS' }
        }
        $prefix = $basePrefix
        if ($roleTotals[$src.Role] -gt 1) {
            # The index guarantees uniqueness even when two nested source files
            # share the same basename. Sanitizing the stem prevents path or
            # wildcard characters from becoming part of an output filename.
            if (-not $roleIndexes.ContainsKey($src.Role)) { $roleIndexes[$src.Role] = 0 }
            $roleIndexes[$src.Role]++
            $sourceStem = [IO.Path]::GetFileNameWithoutExtension($src.File.Name)
            $safeSourceStem = ($sourceStem -replace '[^A-Za-z0-9._-]', '_').Trim('_')
            if ([string]::IsNullOrWhiteSpace($safeSourceStem)) { $safeSourceStem = 'source' }
            $prefix = '{0}_{1:D2}_{2}' -f $basePrefix, $roleIndexes[$src.Role], $safeSourceStem
        }
        $redactedCount = 0
        # Redact once on the in-memory source before selecting any fragments.
        # Thus every overlapping fragment sees the same masked values and the
        # original file under _extracted remains unchanged.
        if ($Redact) { $redactedCount = Redact-Xml -Doc $src.Doc }

        foreach ($fragName in $FragmentMap.Keys) {
            $found = $false
            foreach ($xpath in $FragmentMap[$fragName]) {
                $nodes = $src.Doc.SelectNodes($xpath)
                if ($nodes.Count -gt 0) {
                    $found = $true
                    $i = 0
                    foreach ($node in $nodes) {
                        # A zero-based suffix prevents multiple nodes returned
                        # by one XPath from overwriting one another. A single
                        # node keeps the simpler historical filename.
                        $suffix = if ($nodes.Count -gt 1) { "_$i" } else { '' }
                        # .txt extension: some upload tools accept txt but not xml.
                        # Content is unmodified XML.
                        $outFile = Join-Path $fragDir "$prefix`_$fragName$suffix.xml.txt"
                        Save-Fragment -Node $node -OutFile $outFile
                        # Fragment hashes describe the serialized/redacted
                        # output bytes, unlike source hashes above.
                        $manifest.Add([pscustomobject]@{
                            Kind = 'fragment'; Name = "fragments\$prefix`_$fragName$suffix.xml.txt"
                            Role = $src.Role; RootElement = $node.Name
                            Lines = (Get-Content $outFile | Measure-Object).Count
                            SHA256 = Get-Sha256 $outFile
                            Detail = "xpath=$xpath; from=$($src.RelativeName)"
                        })
                        $i++
                    }
                    # XPath entries are ordered alternatives. Once one matches,
                    # do not also emit a broader fallback for this control area.
                    break
                }
            }
            if (-not $found) {
                # An explicit zero-line row distinguishes "checked and absent"
                # from "not checked" and lets reviewers reconcile every map key.
                $manifest.Add([pscustomobject]@{
                    Kind = 'fragment'; Name = "$prefix`_$fragName"
                    Role = $src.Role; RootElement = ''
                    Lines = 0; SHA256 = ''
                    Detail = 'NOT-PRESENT in this source (all xpaths empty)'
                })
            }
        }

        # --- 6a. Ground-truth counts ----------------------------------------
        foreach ($countName in $CountMap.Keys) {
            # SelectNodes returns a node set; Count is structural and therefore
            # unaffected by replacing secret text during redaction.
            $n = $src.Doc.SelectNodes($CountMap[$countName]).Count
            $manifest.Add([pscustomobject]@{
                Kind = 'count'; Name = "$prefix`_$countName"; Role = $src.Role
                RootElement = ''; Lines = $n; SHA256 = ''
                Detail = $CountMap[$countName]
            })
        }
        if ($Redact) {
            # Record a row even when zero elements were masked. This confirms
            # redaction was enabled and executed for every classified source.
            $manifest.Add([pscustomobject]@{
                Kind = 'redaction'; Name = "$prefix`_redacted_values"; Role = $src.Role
                RootElement = ''; Lines = $redactedCount; SHA256 = ''
                Detail = 'secret-bearing element values masked before fragment write'
            })
        }
    }

    # --- 6b. Write manifest --------------------------------------------------
    # .csv.txt: Excel still opens it (Data > From Text/CSV, or rename) while
    # remaining acceptable to tools that reject a bare .csv. MANIFEST.txt is
    # the human-readable copy. The CSV is the authoritative detailed form:
    # it includes row kind, role, XML root, line/count value, SHA256, XPath,
    # and source-file provenance.
    $manifest | Export-Csv -Path $csvPath -NoTypeInformation

    # Build the readable manifest as an array and write it once. This avoids
    # repeatedly opening the file and preserves a predictable section order.
    $lines = @()
    $lines += "PAN-OS bundle split manifest"
    $lines += "Device bundle : $($item.Name)"
    $lines += "Source SHA256 : $(Get-Sha256 $item.FullName)"
    $lines += "Generated     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += "Redaction     : $(if ($Redact) { 'ON' } else { 'OFF - do not upload unredacted fragments' })"
    $lines += ""
    $lines += "--- SOURCE FILES (role determined by content, not filename) ---"
    $manifest | Where-Object Kind -eq 'source-file' | ForEach-Object {
        $lines += ("{0,-22} {1,7} lines  {2}" -f $_.Role, $_.Lines, $_.Name)
    }
    $lines += ""
    $lines += "--- FRAGMENTS ---"
    $manifest | Where-Object Kind -eq 'fragment' | ForEach-Object {
        # Fragment rows overload Lines: positive means a file was written;
        # zero is the explicit NOT-PRESENT sentinel added above.
        if ($_.Lines -gt 0) { $lines += ("{0,-55} {1,6} lines" -f $_.Name, $_.Lines) }
        else                { $lines += ("{0,-55} NOT-PRESENT" -f $_.Name) }
    }
    $lines += ""
    $lines += "--- GROUND-TRUTH COUNTS (AI extraction must reconcile to these) ---"
    $manifest | Where-Object Kind -eq 'count' | ForEach-Object {
        $lines += ("{0,-45} {1}" -f $_.Name, $_.Lines)
    }
    if ($Redact) {
        # These rows also live in the CSV. Repeating them in MANIFEST.txt makes
        # the human-review copy sufficient to confirm that redaction ran.
        $lines += ""
        $lines += "--- REDACTION COUNTS ---"
        $manifest | Where-Object Kind -eq 'redaction' | ForEach-Object {
            $lines += ("{0,-45} {1}" -f $_.Name, $_.Lines)
        }
    }
    $lines | Set-Content -Path $txtPath -Encoding UTF8

    # Derive the completion summary from manifest rows rather than maintaining
    # separate counters that could drift away from the actual written records.
    Write-Host ("  fragments: {0} written, {1} not present; manifest at {2}" -f `
        (($manifest | Where-Object { $_.Kind -eq 'fragment' -and $_.Lines -gt 0 }).Count), `
        (($manifest | Where-Object { $_.Kind -eq 'fragment' -and $_.Lines -eq 0 }).Count), `
        $txtPath)
}

Write-Host "`nDone. Review each MANIFEST.txt before uploading anything." -ForegroundColor Green
Write-Host "Reminder: only redacted fragments and manifests should be uploaded, never the raw bundle."
