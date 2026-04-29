<#
.SYNOPSIS
    Configures developer CLIs and apps to trust the Netskope tenant CA bundle.

.DESCRIPTION
    Builds a combined PEM (Netskope tenant CA + Mozilla root bundle) at -CertDir\-CertName
    and points common tooling at it via per-tool config or persistent user environment
    variables. Generates a thin replay script next to the bundle for silent deployment on
    other machines (it re-invokes this script with -NonInteractive against the existing
    bundle).

    Replaces the legacy configure_tools_windows.cmd. Fixes for known issues:
      * VS Code JSONC parser is now string-aware (does not eat URLs containing "//").
      * Drops the ineffective top-level "env" edit of claude_desktop_config.json.
      * Atomic bundle creation (temp file -> move).
      * UTF-8 (no BOM) writes for JSON.
      * Yarn version detection (cafile vs httpsCaFilePath).
      * Idempotent: re-runs detect existing config and skip.
      * NonInteractive + existing bundle = reuse, no API token required.

.PARAMETER TenantName
    Full Netskope tenant hostname, e.g. 'tenant-name.goskope.com'. Required when the bundle
    does not yet exist (used to call the API or label the deploy script).

.PARAMETER CertName
    Filename for the generated bundle. Default: netskope-cert-bundle.pem.

.PARAMETER CertDir
    Directory where the bundle is written. Default: C:\netskope.

.PARAMETER ApiToken
    Netskope API bearer token. May also be supplied via $env:NETSKOPE_API_TOKEN.
    Only consulted when (re)building the bundle without -UseLocalCerts.

.PARAMETER UseLocalCerts
    Use the Netskope client's local certs (C:\ProgramData\Netskope\STAgent\data) instead of
    the API. Auto-detected and prompted for if neither this switch nor an API token is set.

.PARAMETER NonInteractive
    Fail rather than prompt. With an existing bundle, this defaults to reusing the bundle
    (deploy-script semantics).

.EXAMPLE
    .\configure_tools_windows.ps1
    Interactive run.

.EXAMPLE
    .\configure_tools_windows.ps1 -TenantName tenant.goskope.com -UseLocalCerts -NonInteractive
    Silent run using locally-installed Netskope client certs.
#>

[CmdletBinding()]
param(
    [string]$TenantName,
    [string]$CertName    = 'netskope-cert-bundle.pem',
    [string]$CertDir     = 'C:\netskope',
    [string]$ApiToken,
    [switch]$UseLocalCerts,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

# ============================================================
# Helpers
# ============================================================

function Write-Section($Text) { Write-Host ''; Write-Host "--- $Text ---" -ForegroundColor Cyan }
function Write-OK($Text)      { Write-Host "[ok]   $Text" -ForegroundColor Green }
function Write-Skip($Text)    { Write-Host "[skip] $Text" -ForegroundColor DarkGray }
function Write-Warn2($Text)   { Write-Host "[warn] $Text" -ForegroundColor Yellow }

function Test-Tool([string]$Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Find-Tool([string[]]$Candidates) {
    foreach ($c in $Candidates) { if (Test-Tool $c) { return $c } }
    return $null
}

function Get-UserEnv([string]$Name) {
    return [Environment]::GetEnvironmentVariable($Name, 'User')
}

# Persist to User-scope env vars (broadcasts WM_SETTINGCHANGE via setx) and update the
# current session. Returns $true if the registry value changed.
function Set-PersistentEnv {
    param([string]$Name, [string]$Value)
    $existing = Get-UserEnv $Name
    Set-Item -Path "Env:$Name" -Value $Value
    if ($existing -eq $Value) { return $false }
    & setx $Name $Value | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "setx failed for $Name (exit $LASTEXITCODE)" }
    return $true
}

# Default Set-Content/Out-File on PS 5.1 emits BOM, which breaks some JSON consumers.
function Set-Utf8NoBom {
    param([string]$Path, [string]$Content)
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

# Strip JSONC comments (// line, /* block */) and trailing commas while respecting string
# literals (the legacy regex ate URLs like https://...).
function Remove-JsonCommentsRespectingStrings {
    param([string]$Content)
    $sb = [System.Text.StringBuilder]::new($Content.Length)
    $i = 0; $n = $Content.Length
    while ($i -lt $n) {
        $c = $Content[$i]
        if ($c -eq '"') {
            [void]$sb.Append($c); $i++
            while ($i -lt $n) {
                $c = $Content[$i]; [void]$sb.Append($c)
                if ($c -eq '\' -and ($i + 1) -lt $n) {
                    [void]$sb.Append($Content[$i + 1]); $i += 2; continue
                }
                if ($c -eq '"') { $i++; break }
                $i++
            }
            continue
        }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Content[$i + 1] -eq '/') {
            while ($i -lt $n -and $Content[$i] -ne "`n") { $i++ }
            continue
        }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Content[$i + 1] -eq '*') {
            $i += 2
            while (($i + 1) -lt $n -and -not ($Content[$i] -eq '*' -and $Content[$i + 1] -eq '/')) { $i++ }
            $i += 2
            continue
        }
        [void]$sb.Append($c); $i++
    }
    return [regex]::Replace($sb.ToString(), ',(\s*[}\]])', '$1')
}

function Get-JsonPath {
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($key in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur.PSObject.Properties.Name -notcontains $key) { return $null }
        $cur = $cur.$key
    }
    return $cur
}

function Set-JsonPath {
    param($Object, [string[]]$Path, $Value)
    $cur = $Object
    for ($i = 0; $i -lt $Path.Count - 1; $i++) {
        $key = $Path[$i]
        $next = $null
        if ($cur.PSObject.Properties.Name -contains $key) { $next = $cur.$key }
        if ($null -eq $next -or $next -isnot [PSCustomObject]) {
            $next = [PSCustomObject]@{}
            if ($cur.PSObject.Properties.Name -contains $key) {
                $cur.$key = $next
            } else {
                $cur | Add-Member -NotePropertyName $key -NotePropertyValue $next
            }
        }
        $cur = $next
    }
    $last = $Path[-1]
    if ($cur.PSObject.Properties.Name -contains $last) {
        $cur.$last = $Value
    } else {
        $cur | Add-Member -NotePropertyName $last -NotePropertyValue $Value
    }
}

# Bootstrap fetches happen before the Netskope cert chain is trusted, so cert validation is
# skipped (matches the legacy script's curl -k behavior). Wraps both PS 5.1 and PS 7+.
function Invoke-InsecureWebRequest {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{},
        [string]$OutFile
    )
    $params = @{ Uri = $Uri; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($OutFile) { $params['OutFile'] = $OutFile }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $params['SkipCertificateCheck'] = $true
        Invoke-WebRequest @params | Out-Null
        return
    }
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $oldCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Invoke-WebRequest @params | Out-Null
    } finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
    }
}

# ============================================================
# Parameter resolution (interactive)
# ============================================================

function Read-RequiredString($Prompt, $Default) {
    if ($NonInteractive) {
        if ($Default) { return $Default }
        throw "Missing required input ($Prompt) in non-interactive mode"
    }
    $promptText = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
    $val = Read-Host $promptText
    if ([string]::IsNullOrWhiteSpace($val)) { return $Default }
    return $val.Trim()
}

if ([string]::IsNullOrWhiteSpace($CertName)) { $CertName = Read-RequiredString 'Certificate bundle name' 'netskope-cert-bundle.pem' }
if ([string]::IsNullOrWhiteSpace($CertDir))  { $CertDir  = Read-RequiredString 'Certificate bundle location' 'C:\netskope' }

$bundlePath = Join-Path $CertDir $CertName
$deployPath = Join-Path $CertDir 'configured_tools.ps1'
$nsCaCert    = 'C:\ProgramData\Netskope\STAgent\data\nscacert.pem'
$nsTenantCrt = 'C:\ProgramData\Netskope\STAgent\data\nstenantcert.pem'

# Decide whether to (re)build the bundle. Default in non-interactive mode is to reuse an
# existing bundle (deploy-script semantics) so that token/tenant args are not required.
$createBundle = $false
if (-not (Test-Path $bundlePath)) {
    $createBundle = $true
} elseif ($NonInteractive) {
    Write-Host "Using existing bundle at $bundlePath"
} else {
    $resp = Read-Host "$CertName already exists in $CertDir. Recreate? (y/N)"
    if ($resp -match '^[Yy]') { $createBundle = $true } else { Write-Skip 'Reusing existing bundle' }
}

if ($createBundle) {
    if ([string]::IsNullOrWhiteSpace($TenantName)) {
        $TenantName = Read-RequiredString 'Please provide full Netskope tenant name (ex: tenant-name.goskope.com)' $null
    }
    if ([string]::IsNullOrWhiteSpace($TenantName)) { throw 'Tenant name cannot be empty' }
    $TenantName = $TenantName.Trim() -replace '^https?://','' -replace '/+$',''
    if ($TenantName -notmatch '^[A-Za-z0-9.\-]+$') { throw "Invalid tenant name: '$TenantName'" }

    if (-not (Test-Path $CertDir)) {
        Write-Host "$CertDir does not exist. Creating."
        New-Item -ItemType Directory -Path $CertDir | Out-Null
    }

    $haveLocalCerts = (Test-Path $nsCaCert) -and (Test-Path $nsTenantCrt)
    if (-not $UseLocalCerts -and $haveLocalCerts -and -not $NonInteractive) {
        Write-Host ''
        Write-Host 'Netskope client is installed. Found local certificates.'
        if (Test-Tool 'openssl') {
            Write-Host '  CA Certificate (nscacert.pem):'
            & openssl x509 -in $nsCaCert -noout -subject 2>$null
            Write-Host '  Tenant Certificate (nstenantcert.pem):'
            & openssl x509 -in $nsTenantCrt -noout -subject 2>$null
        }
        $resp = Read-Host 'Use these local certificates instead of the API? (Y/n)'
        if ($resp -notmatch '^[Nn]') { $UseLocalCerts = $true }
    }
    if ($UseLocalCerts -and -not $haveLocalCerts) {
        throw "UseLocalCerts requested but local certs were not found at $nsCaCert / $nsTenantCrt"
    }

    if (-not $UseLocalCerts) {
        if ([string]::IsNullOrWhiteSpace($ApiToken) -and $env:NETSKOPE_API_TOKEN) {
            if ($NonInteractive) {
                $ApiToken = $env:NETSKOPE_API_TOKEN
            } else {
                $resp = Read-Host 'Found NETSKOPE_API_TOKEN environment variable. Use this token? (Y/n)'
                if ($resp -notmatch '^[Nn]') { $ApiToken = $env:NETSKOPE_API_TOKEN }
            }
        }
        if ([string]::IsNullOrWhiteSpace($ApiToken)) {
            if ($NonInteractive) { throw 'No API token supplied (use -ApiToken, $env:NETSKOPE_API_TOKEN, or -UseLocalCerts)' }
            $secure = Read-Host 'Please provide the Netskope API Bearer token' -AsSecureString
            $bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try     { $ApiToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        if ([string]::IsNullOrWhiteSpace($ApiToken)) { throw 'API token cannot be empty' }
    }
}

# ============================================================
# Cert bundle creation
# ============================================================

function New-CertBundle {
    Write-Section 'Building certificate bundle'
    $tempBundle = [System.IO.Path]::GetTempFileName()
    try {
        if ($UseLocalCerts) {
            Write-Host 'Using local Netskope client certificates...'
            $tenant = (Get-Content -Raw -LiteralPath $nsTenantCrt).TrimEnd()
            $ca     = (Get-Content -Raw -LiteralPath $nsCaCert).TrimEnd()
            $nsContent = "$tenant`n$ca`n"
            Set-Content -LiteralPath $tempBundle -Value $nsContent -Encoding ASCII -NoNewline
        } else {
            Write-Host 'Fetching Netskope tenant CA certificates from API...'
            $headers = @{ 'Authorization' = "Bearer $ApiToken"; 'Accept' = 'application/json' }
            $apiUrl  = "https://$TenantName/api/v2/services/certs/subordinates?purpose=tenant_ca"
            $apiTemp = [System.IO.Path]::GetTempFileName()
            try {
                Invoke-InsecureWebRequest -Uri $apiUrl -Headers $headers -OutFile $apiTemp
                $json  = Get-Content -Raw -LiteralPath $apiTemp | ConvertFrom-Json
                $certs = $json.certificates
                if (-not $certs -or $certs.Count -eq 0) { throw 'API returned no certificates' }
                $pemBlocks = foreach ($c in $certs) {
                    if ($c.PSObject.Properties.Name -contains 'certificate' -and $c.certificate) { $c.certificate.TrimEnd() }
                    if ($c.PSObject.Properties.Name -contains 'issuer'      -and $c.issuer)      { $c.issuer.TrimEnd() }
                }
                if (-not $pemBlocks) { throw 'No PEM content extracted from API response' }
                Set-Content -LiteralPath $tempBundle -Value (($pemBlocks -join "`n") + "`n") -Encoding ASCII -NoNewline
                Write-OK 'Netskope certificates retrieved successfully'
            } finally {
                Remove-Item -LiteralPath $apiTemp -ErrorAction SilentlyContinue
            }
        }

        Write-Host 'Downloading Mozilla CA bundle...'
        $mozTemp = [System.IO.Path]::GetTempFileName()
        try {
            Invoke-InsecureWebRequest -Uri 'https://curl.se/ca/cacert.pem' -OutFile $mozTemp
            if ((Get-Item $mozTemp).Length -lt 10000) {
                throw "Mozilla CA bundle download looks truncated ($((Get-Item $mozTemp).Length) bytes)"
            }
            Add-Content -LiteralPath $tempBundle -Value (Get-Content -Raw -LiteralPath $mozTemp) -Encoding ASCII -NoNewline
        } finally {
            Remove-Item -LiteralPath $mozTemp -ErrorAction SilentlyContinue
        }

        Move-Item -LiteralPath $tempBundle -Destination $bundlePath -Force
        Write-OK "Certificate bundle written: $bundlePath"
    } catch {
        Remove-Item -LiteralPath $tempBundle -ErrorAction SilentlyContinue
        throw
    }
}

if ($createBundle) { New-CertBundle }

# ============================================================
# Tool configuration
# ============================================================

# Tools that just need a single env var pointing at the bundle. First Probe found gates setup.
$envTools = @(
    [pscustomobject]@{ Name = 'OpenSSL';                Probes = @('openssl');         EnvVar = 'SSL_CERT_FILE' }
    [pscustomobject]@{ Name = 'cURL';                   Probes = @('curl');            EnvVar = 'CURL_CA_BUNDLE' }
    [pscustomobject]@{ Name = 'Python Requests Library';Probes = @('python','python3');EnvVar = 'REQUESTS_CA_BUNDLE' }
    [pscustomobject]@{ Name = 'AWS CLI';                Probes = @('aws');             EnvVar = 'AWS_CA_BUNDLE' }
    [pscustomobject]@{ Name = 'NodeJS';                 Probes = @('node');            EnvVar = 'NODE_EXTRA_CA_CERTS' }
    [pscustomobject]@{ Name = 'Ruby';                   Probes = @('ruby');            EnvVar = 'SSL_CERT_FILE' }
    [pscustomobject]@{ Name = 'Azure CLI';              Probes = @('az');              EnvVar = 'REQUESTS_CA_BUNDLE' }
    [pscustomobject]@{ Name = 'Python PIP';             Probes = @('pip3','pip');      EnvVar = 'PIP_CERT' }
    [pscustomobject]@{ Name = 'Oracle Cloud CLI';       Probes = @('oci');             EnvVar = 'OCI_CLI_CA_BUNDLE' }
    [pscustomobject]@{ Name = 'Cargo Package Manager';  Probes = @('cargo');           EnvVar = 'CARGO_HTTP_CAINFO' }
    [pscustomobject]@{ Name = 'Claude CLI';             Probes = @('claude');          EnvVar = 'NODE_EXTRA_CA_CERTS' }
    [pscustomobject]@{ Name = 'Netskope CLI';           Probes = @('ntsk');            EnvVar = 'NETSKOPE_CA_BUNDLE' }
)

Write-Section 'Configuring CLIs (env-var based)'
foreach ($t in $envTools) {
    $found = Find-Tool $t.Probes
    if (-not $found) { Write-Skip "$($t.Name) not installed"; continue }
    $changed = Set-PersistentEnv -Name $t.EnvVar -Value $bundlePath
    if ($changed) { Write-OK "$($t.Name) configured ($($t.EnvVar))" }
    else          { Write-Skip "$($t.Name) already configured" }
}

Write-Section 'Configuring CLIs (native config)'

if (Test-Tool 'git') {
    $current = & git config --global http.sslCAInfo 2>$null
    if ($current -eq $bundlePath) {
        Write-Skip 'Git already configured'
    } else {
        & git config --global http.sslCAInfo $bundlePath
        Write-OK 'Git configured'
    }
} else { Write-Skip 'Git not installed' }

if (Test-Tool 'gcloud') {
    $current = & gcloud config get-value core/custom_ca_certs_file 2>$null
    if ($current -and $current.ToString().Trim() -eq $bundlePath) {
        Write-Skip 'Google Cloud CLI already configured'
    } else {
        & gcloud config set core/custom_ca_certs_file $bundlePath 2>$null | Out-Null
        Write-OK 'Google Cloud CLI configured'
    }
} else { Write-Skip 'Google Cloud CLI not installed' }

if (Test-Tool 'npm') {
    $current = & npm config get cafile 2>$null
    if ($current -and $current.Trim() -eq $bundlePath) {
        Write-Skip 'npm already configured'
    } else {
        & npm config set cafile $bundlePath
        Write-OK 'npm configured'
    }
} else { Write-Skip 'npm not installed' }

if (Test-Tool 'composer') {
    $current = & composer config --global cafile 2>$null
    if ($current -and $current.Trim() -eq $bundlePath) {
        Write-Skip 'PHP Composer already configured'
    } else {
        & composer config --global cafile $bundlePath | Out-Null
        Write-OK 'PHP Composer configured'
    }
} else { Write-Skip 'PHP Composer not installed' }

if (Test-Tool 'yarn') {
    $yarnRaw = (& yarn --version 2>$null) | Select-Object -First 1
    $yarnMajor = 0
    if ($yarnRaw -match '^(\d+)\.') { $yarnMajor = [int]$Matches[1] }
    if ($yarnMajor -ge 2) {
        & yarn config set httpsCaFilePath $bundlePath | Out-Null
        Write-OK "Yarn ($yarnRaw) configured (httpsCaFilePath)"
    } else {
        & yarn config set cafile $bundlePath | Out-Null
        Write-OK "Yarn ($yarnRaw) configured (cafile)"
    }
} else { Write-Skip 'Yarn not installed' }

# ============================================================
# Application configuration
# ============================================================

Write-Section 'Configuring applications'

# --- Azure Storage Explorer -------------------------------------------------
$storageExplorerCertsDirs = @(
    Join-Path $env:LOCALAPPDATA 'Programs\Microsoft Azure Storage Explorer\certs'
    Join-Path $env:USERPROFILE  'AppData\Local\Programs\Microsoft Azure Storage Explorer\certs'
)
$seCertsDir = $storageExplorerCertsDirs | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($seCertsDir) {
    $seTarget = Join-Path $seCertsDir $CertName
    $needsCopy = -not (Test-Path $seTarget)
    if (-not $needsCopy) {
        $a = Get-FileHash -Path $bundlePath -Algorithm SHA256
        $b = Get-FileHash -Path $seTarget   -Algorithm SHA256
        $needsCopy = $a.Hash -ne $b.Hash
    }
    if ($needsCopy) {
        Copy-Item -LiteralPath $bundlePath -Destination $seTarget -Force
        Write-OK 'Azure Storage Explorer configured'
    } else {
        Write-Skip 'Azure Storage Explorer already configured'
    }
} else {
    Write-Skip 'Azure Storage Explorer not installed'
}

# --- Claude Desktop ---------------------------------------------------------
# Claude Desktop is an Electron app; it picks up NODE_EXTRA_CA_CERTS from the user
# environment at launch. The legacy script's edit of claude_desktop_config.json's top-level
# "env" key was a no-op (not a recognized config field). Setting the user env var (already
# done above for NodeJS / Claude CLI) is what actually takes effect on next launch.
$claudeDesktopCandidates = @(
    Join-Path $env:LOCALAPPDATA 'Programs\claude-desktop\Claude.exe'
    Join-Path ${env:ProgramFiles} 'Claude\Claude.exe'
    Join-Path $env:LOCALAPPDATA 'Claude\Claude.exe'
)
$claudeDesktopFound = $claudeDesktopCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($claudeDesktopFound) {
    Set-PersistentEnv -Name 'NODE_EXTRA_CA_CERTS' -Value $bundlePath | Out-Null
    Write-OK 'Claude Desktop will use NODE_EXTRA_CA_CERTS on next launch'
} else {
    Write-Skip 'Claude Desktop not installed'
}

# --- VS Code variants -------------------------------------------------------
function Set-VsCodeSetting {
    param([string]$Variant, [string]$SettingsPath)
    if (-not (Test-Path $SettingsPath)) { Write-Skip "$Variant not installed"; return }

    $original = Get-Content -Raw -LiteralPath $SettingsPath
    $backup   = "$SettingsPath.netskope-bak"
    Copy-Item -LiteralPath $SettingsPath -Destination $backup -Force

    try {
        $stripped = Remove-JsonCommentsRespectingStrings -Content $original
        if ([string]::IsNullOrWhiteSpace($stripped)) { $stripped = '{}' }
        $settings = $stripped | ConvertFrom-Json
        if ($null -eq $settings) { $settings = [PSCustomObject]@{} }

        $existing = Get-JsonPath -Object $settings -Path @('terminal.integrated.env.windows','NODE_EXTRA_CA_CERTS')
        if ($existing -eq $bundlePath) {
            Write-Skip "$Variant already configured"
            return
        }

        Set-JsonPath -Object $settings -Path @('terminal.integrated.env.windows','NODE_EXTRA_CA_CERTS') -Value $bundlePath
        $newJson = $settings | ConvertTo-Json -Depth 100
        Set-Utf8NoBom -Path $SettingsPath -Content $newJson
        Write-OK "$Variant configured (NODE_EXTRA_CA_CERTS in integrated terminal)"
        if ($original -match '(?m)^\s*//' -or $original -match '/\*') {
            Write-Warn2 "  Note: comments in $Variant settings.json were not preserved on rewrite."
        }
    } catch {
        Write-Warn2 "Failed to configure $Variant : $($_.Exception.Message)"
        Copy-Item -LiteralPath $backup -Destination $SettingsPath -Force
    } finally {
        Remove-Item -LiteralPath $backup -ErrorAction SilentlyContinue
    }
}

Set-VsCodeSetting -Variant 'VS Code'          -SettingsPath (Join-Path $env:APPDATA 'Code\User\settings.json')
Set-VsCodeSetting -Variant 'VS Code Insiders' -SettingsPath (Join-Path $env:APPDATA 'Code - Insiders\User\settings.json')
Set-VsCodeSetting -Variant 'Cursor'           -SettingsPath (Join-Path $env:APPDATA 'Cursor\User\settings.json')

# ============================================================
# Finalize - emit replay script and copy main script alongside the bundle
# ============================================================

# Copy this script into $CertDir so the deploy bundle is self-contained.
$selfPath = $PSCommandPath
$selfCopy = Join-Path $CertDir 'configure_tools_windows.ps1'
if ($selfPath -and (Test-Path $selfPath)) {
    $sameFile = $false
    if (Test-Path $selfCopy) {
        $sameFile = (Resolve-Path -LiteralPath $selfPath).Path -eq (Resolve-Path -LiteralPath $selfCopy).Path
    }
    if (-not $sameFile) { Copy-Item -LiteralPath $selfPath -Destination $selfCopy -Force }
}

# Replay script: thin wrapper that re-invokes the main script in non-interactive mode. The
# bundle must already be present at $bundlePath (copy it from the source machine).
$tenantArg = if ($TenantName) { " -TenantName '$TenantName'" } else { '' }
$replay = @"
# Generated by configure_tools_windows.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').
# Replays CLI / app configuration on a new machine using the bundle in this directory.
#
# Pre-requisite: the cert bundle must already exist at:
#   $bundlePath
# Copy it from the source machine before running this script.

`$ErrorActionPreference = 'Stop'
`$here   = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$main   = Join-Path `$here 'configure_tools_windows.ps1'
`$bundle = '$bundlePath'

if (-not (Test-Path `$bundle)) {
    Write-Error "Certificate bundle missing: `$bundle"
    exit 1
}
if (-not (Test-Path `$main)) {
    Write-Error "configure_tools_windows.ps1 must be in the same directory as this deploy script."
    exit 1
}

& `$main -CertName '$CertName' -CertDir '$CertDir'$tenantArg -NonInteractive
"@

Set-Utf8NoBom -Path $deployPath -Content $replay

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Configuration complete.' -ForegroundColor Cyan
Write-Host "   Bundle:           $bundlePath"
Write-Host "   Replay script:    $deployPath"
Write-Host "   Script copy:      $selfCopy"
Write-Host ''
Write-Host ' To deploy on another machine: copy the bundle, configure_tools_windows.ps1,'
Write-Host '   and configured_tools.ps1 to the same directory, then run configured_tools.ps1.'
Write-Host ''
Write-Host ' Note: env-var changes (setx) are visible to NEW console windows / freshly'
Write-Host '   launched apps, not to processes that were already running.'
Write-Host '============================================================' -ForegroundColor Cyan
