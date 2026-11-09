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

.PARAMETER K8s
    Also write Kubernetes CA assets (ConfigMap, example Deployment, trust-manager Bundle and a
    node trust script) to <CertDir>\k8s. Without this switch, and when kubectl is on PATH, an
    interactive run offers to do it (default: no).

.PARAMETER K8sNamespace
    Namespace used in the Kubernetes manifests. Default: default.

.EXAMPLE
    .\configure_tools_windows.ps1
    Interactive run.

.EXAMPLE
    .\configure_tools_windows.ps1 -TenantName tenant.goskope.com -UseLocalCerts -NonInteractive
    Silent run using locally-installed Netskope client certs.

.EXAMPLE
    .\configure_tools_windows.ps1 -K8s -K8sNamespace my-team
    Interactive run that also writes the Kubernetes assets for the "my-team" namespace.
#>

[CmdletBinding()]
param(
    [string]$TenantName,
    [string]$CertName    = 'netskope-cert-bundle.pem',
    [string]$CertDir     = 'C:\netskope',
    [string]$ApiToken,
    [switch]$UseLocalCerts,
    [switch]$NonInteractive,
    [switch]$K8s,
    [string]$K8sNamespace = 'default'
)

$ErrorActionPreference = 'Stop'

# The namespace ends up in YAML, so hold it to a Kubernetes DNS-1123 label (-cmatch: the
# default -match is case-insensitive).
function Test-K8sNamespace([string]$Name) {
    return ($Name.Length -le 63) -and ($Name -cmatch '^[a-z0-9]([-a-z0-9]*[a-z0-9])?\z')
}
if (-not (Test-K8sNamespace $K8sNamespace)) {
    throw "Invalid -K8sNamespace '$K8sNamespace' (lowercase letters, digits and '-', at most 63 characters)"
}

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

# For public downloads (the Mozilla root bundle), verify the TLS chain first — this seeds
# the entire root trust store, so an unvalidated fetch is an injection vector. Verification
# succeeds whenever the host is NOT behind Netskope inspection; only then do we fall back to
# an insecure fetch (behind inspection the resigned cert isn't trusted yet — the very thing
# we're installing).
function Invoke-VerifiedDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile
    )
    try {
        $params = @{ Uri = $Uri; UseBasicParsing = $true; TimeoutSec = 60; OutFile = $OutFile }
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        }
        Invoke-WebRequest @params | Out-Null
    } catch {
        Write-Warn2 'Verified download failed (likely TLS inspection); retrying without certificate verification.'
        Invoke-InsecureWebRequest -Uri $Uri -OutFile $OutFile
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
# Netskope-only certs, split out of the full bundle. Container trust stores already ship the
# Mozilla roots, so what they need is just the Netskope CA chain - and OS trust-store tools
# (update-ca-certificates / update-ca-trust) only pick up files with a .crt extension.
$netskopeCaPath  = Join-Path $CertDir 'netskope-ca.crt'
$dockerAssetDir  = Join-Path $CertDir 'docker'
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

        # Everything in $tempBundle so far is Netskope-only; keep a copy before the Mozilla
        # roots are appended, for use inside containers (see the Docker section below).
        Copy-Item -LiteralPath $tempBundle -Destination $netskopeCaPath -Force

        Write-Host 'Downloading Mozilla CA bundle...'
        $mozTemp = [System.IO.Path]::GetTempFileName()
        try {
            Invoke-VerifiedDownload -Uri 'https://curl.se/ca/cacert.pem' -OutFile $mozTemp
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
)

Write-Section 'Configuring CLIs (env-var based)'
foreach ($t in $envTools) {
    $found = Find-Tool $t.Probes
    if (-not $found) { Write-Skip "$($t.Name) not installed"; continue }
    $changed = Set-PersistentEnv -Name $t.EnvVar -Value $bundlePath
    if ($changed) { Write-OK "$($t.Name) configured ($($t.EnvVar))" }
    else          { Write-Skip "$($t.Name) already configured" }
}

# Netskope CLI (ntsk) — set ALL of these, mirroring the Unix scripts. Empirically ntsk
# hits raw ssl/urllib code paths that only honor SSL_CERT_FILE, even though its docs imply
# NETSKOPE_CA_BUNDLE is enough. On a host without openssl/curl/python installed, none of
# those vars get set by their own tool entries and ntsk fails with TLS errors.
if (Test-Tool 'ntsk') {
    $ntskChanged = $false
    foreach ($v in @('NETSKOPE_CA_BUNDLE', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE')) {
        if (Set-PersistentEnv -Name $v -Value $bundlePath) { $ntskChanged = $true }
    }
    if ($ntskChanged) { Write-OK 'Netskope CLI configured (NETSKOPE_CA_BUNDLE + SSL_CERT_FILE + REQUESTS_CA_BUNDLE + CURL_CA_BUNDLE)' }
    else              { Write-Skip 'Netskope CLI already configured' }
} else { Write-Skip 'Netskope CLI not installed' }

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
# Docker
# ============================================================

# Containers carry their own trust store, so nothing configured above reaches them. The
# Netskope guidance ("Install the Netskope Certificates on the Docker machines that require
# Internet access") covers three deployment styles - patch a running container, bake the CA
# into an image, or gate it on a build arg for compose - and we can't know which one a given
# project uses, so emit ready-to-use assets for all three.
#
# The OS trust store alone is also not enough: Node, Python requests, pip, Cargo and Git each
# carry their own CA list, hence the ENV block in the generated Dockerfiles.

# Assets are written with LF endings and ASCII content: they are consumed inside Linux
# containers, where CRLF breaks shebang lines and RUN continuations.
function Write-DockerAsset {
    param([string]$Path, [string]$Content)
    # Here-strings do not include a trailing newline, and UTF8Encoding($false) avoids the BOM
    # that Set-Content would prepend - a BOM ahead of "#!/bin/sh" stops the kernel finding the
    # interpreter, and ahead of "FROM" breaks the Dockerfile parse.
    $lf = ($Content -replace "`r`n", "`n")
    if (-not $lf.EndsWith("`n")) { $lf += "`n" }
    [System.IO.File]::WriteAllText($Path, $lf, (New-Object System.Text.UTF8Encoding($false)))
}

$dockerfileSnippet = @'
# --- Netskope SSL inspection trust ------------------------------------------
# Paste into your Dockerfile after the base image's package manager is usable.
# Requires netskope-ca.crt in the build context (copy it next to your Dockerfile).

# Debian / Ubuntu / Alpine (needs the ca-certificates package - most Alpine images ship
# only ca-certificates-bundle, so add `RUN apk add --no-cache ca-certificates` first):
COPY netskope-ca.crt /usr/local/share/ca-certificates/netskope-ca.crt
RUN chmod 644 /usr/local/share/ca-certificates/netskope-ca.crt && update-ca-certificates

# RHEL / CentOS / Fedora / Amazon Linux - use instead:
#   COPY netskope-ca.crt /etc/pki/ca-trust/source/anchors/netskope-ca.crt
#   RUN chmod 644 /etc/pki/ca-trust/source/anchors/netskope-ca.crt && update-ca-trust extract
#
# openSUSE / SLES - use instead:
#   COPY netskope-ca.crt /etc/pki/trust/anchors/netskope-ca.crt
#   RUN chmod 644 /etc/pki/trust/anchors/netskope-ca.crt && update-ca-certificates

# The OS trust store does not cover runtimes that ship their own CA list.
# Debian/Ubuntu/Alpine merged-bundle path:
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/netskope-ca.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \
    CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt
# On RHEL-family images the merged bundle lives at /etc/pki/tls/certs/ca-bundle.crt -
# substitute that path above, and point NODE_EXTRA_CA_CERTS at the anchors copy.
# ---------------------------------------------------------------------------
'@

$dockerfileExample = @'
# Standalone example: Debian/Ubuntu base image that trusts the Netskope CA.
# Build from this directory so netskope-ca.crt is in the build context:
#   docker build -f Dockerfile.example -t ubuntu-netskope .
FROM ubuntu

RUN apt-get update -y \
 && apt-get install -y --no-install-recommends ca-certificates curl wget \
 && rm -rf /var/lib/apt/lists/*

# Install the Netskope CA into the OS trust store
COPY netskope-ca.crt /usr/local/share/ca-certificates/netskope-ca.crt
RUN chmod 644 /usr/local/share/ca-certificates/netskope-ca.crt && update-ca-certificates

# Runtimes that ignore the OS trust store
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/netskope-ca.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \
    CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt

# Verify at build time (optional): RUN curl -fsS https://www.google.com -o /dev/null
'@

$dockerfileBuildArg = @'
# Conditional variant for Dockerfiles shared across environments: the CA is installed only
# when BUILD_ENV=development, so images built in CI (no SSL inspection) stay untouched.
#   docker build --build-arg BUILD_ENV=development -f Dockerfile.build-arg -t myimage .
FROM ubuntu

RUN apt-get update -y \
 && apt-get install -y --no-install-recommends ca-certificates curl wget \
 && rm -rf /var/lib/apt/lists/*

ARG BUILD_ENV
ARG CERT_DIR=/usr/local/share/ca-certificates
ENV BUILD_ENV=$BUILD_ENV

COPY netskope-ca.crt /tmp/netskope-ca.crt
RUN if [ "$BUILD_ENV" = "development" ]; then \
        cp /tmp/netskope-ca.crt "$CERT_DIR/netskope-ca.crt" && \
        chmod 644 "$CERT_DIR/netskope-ca.crt" && \
        update-ca-certificates; \
    fi; \
    rm -f /tmp/netskope-ca.crt

# Harmless when the CA was not installed - these paths exist in any ca-certificates image.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
'@

$dockerCompose = @'
# Compose fragment pairing with Dockerfile.build-arg. Put BUILD_ENV=development in a .env
# file next to your compose file (see netskope.env) to switch CA installation on; omit the
# file, or set any other value, to build without the Netskope CA.
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.build-arg
      args:
        BUILD_ENV: ${BUILD_ENV}
    environment:
      - BUILD_ENV=${BUILD_ENV}
    stdin_open: true
    tty: true
'@

$dockerEnvFile = @'
# Copy to ".env" next to your docker-compose file to enable CA installation at build time.
BUILD_ENV=development
'@

$dockerReadme = @'
# Netskope certificates for Docker

Containers ship their own trust store, so the host configuration does not reach them.
Pick whichever of these matches how the project builds:

| File | Use |
| --- | --- |
| `Dockerfile.snippet` | Lines to paste into an existing Dockerfile |
| `Dockerfile.example` | Standalone Debian/Ubuntu image that trusts the CA |
| `Dockerfile.build-arg` | Installs the CA only when `--build-arg BUILD_ENV=development` |
| `docker-compose.netskope.yml` + `netskope.env` | Compose wiring for the build-arg variant |
| `install-netskope-ca-in-container.*` | Patch containers that are already running |
| `trust-netskope-ca-in-docker-daemon.sh` | Make the Docker daemon itself trust the CA (pulls, pushes, builds) |
| `netskope-ca.crt` | The CA itself - must be in the build context |

Baking the CA into the image is the durable option; `docker cp` into a running container is
undone the moment the container is recreated.

The daemon is a separate problem from the containers: it does its own TLS to the registry,
so `docker pull` can fail with `x509: certificate signed by unknown authority` before any
container exists. That is what the daemon script fixes.

Verify from inside a container with `curl -fsS https://www.google.com -o /dev/null` -
success means the resigned certificate is trusted.
'@

$dockerInjectorSh = @'
#!/bin/sh
## Installs the Netskope CA into running Docker containers.
##
##   ./install-netskope-ca-in-container.sh              # all running containers
##   ./install-netskope-ca-in-container.sh <id|name>... # specific containers
##
## Changes are lost when a container is recreated - bake the CA into the image
## (see Dockerfile.snippet) for anything longer-lived than a one-off test.
set -eu

marker='# Netskope CA (install-netskope-ca-in-container)'
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ca="$here/netskope-ca.crt"
[ -f "$ca" ] || { echo "Error: netskope-ca.crt not found next to this script" >&2; exit 1; }

if [ "$#" -gt 0 ]; then
  targets=$*
else
  targets=$(docker ps --format '{{.Names}}')
  [ -n "$targets" ] || { echo "No running containers."; exit 0; }
fi

for c in $targets; do
  if docker exec "$c" test -d /usr/local/share/ca-certificates 2>/dev/null; then
    dir=/usr/local/share/ca-certificates; update='update-ca-certificates'
  elif docker exec "$c" test -d /etc/pki/ca-trust/source/anchors 2>/dev/null; then
    dir=/etc/pki/ca-trust/source/anchors; update='update-ca-trust extract'
  elif docker exec "$c" test -d /etc/pki/trust/anchors 2>/dev/null; then
    dir=/etc/pki/trust/anchors; update='update-ca-certificates'
  else
    dir=''; update=''
  fi

  if [ -n "$dir" ]; then
    if docker cp "$ca" "$c:$dir/netskope-ca.crt" >/dev/null 2>&1 \
       && docker exec "$c" chmod 644 "$dir/netskope-ca.crt" >/dev/null 2>&1 \
       && docker exec "$c" sh -c "$update" >/dev/null 2>&1; then
      echo "[ok]   $c: Netskope CA installed ($dir)"
    else
      echo "[warn] $c: failed to install the Netskope CA"
    fi
    continue
  fi

  # Minimal images (most Alpine-based ones) ship the merged bundle but no anchors directory
  # and no update-ca-certificates. Appending to the bundle is what OpenSSL and cURL read.
  bundle=/etc/ssl/certs/ca-certificates.crt
  if ! docker exec "$c" test -f "$bundle" 2>/dev/null; then
    echo "[skip] $c: no CA trust store found (install the ca-certificates package)"
  elif docker exec "$c" grep -qF "$marker" "$bundle" 2>/dev/null; then
    echo "[ok]   $c: Netskope CA already present in $bundle"
  elif docker cp "$ca" "$c:/tmp/netskope-ca.crt" >/dev/null 2>&1 \
       && docker exec "$c" sh -c "echo '' >> $bundle && echo '$marker' >> $bundle && cat /tmp/netskope-ca.crt >> $bundle && rm -f /tmp/netskope-ca.crt" >/dev/null 2>&1; then
    echo "[ok]   $c: Netskope CA appended to $bundle"
  else
    echo "[warn] $c: failed to install the Netskope CA"
  fi
done
'@

$dockerDaemonSh = @'
#!/bin/sh
## Makes the Docker *daemon* trust the Netskope CA, so image pulls, pushes and builds
## succeed behind SSL inspection. This is separate from the CA inside containers - the
## daemon does its own TLS to the registry. Linux hosts only; run with sudo.
##
##   sudo ./trust-netskope-ca-in-docker-daemon.sh
##       Install into the host OS trust store. Covers every registry, including Docker
##       Hub. Requires a daemon restart afterwards.
##
##   sudo ./trust-netskope-ca-in-docker-daemon.sh myreg.example.com:5000 ...
##       Install per-registry under /etc/docker/certs.d. Takes effect on the next pull
##       with no daemon restart, but only for the registries named. The directory name
##       must match the registry exactly as it appears in the image reference, port
##       included.
##
## Docker Desktop (macOS / Windows) uses neither path: add the CA to the host keychain
## or Windows certificate store, then restart Docker Desktop.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ca="$here/netskope-ca.crt"
[ -f "$ca" ] || { echo "Error: netskope-ca.crt not found next to this script" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "Error: Linux hosts only (see the Docker Desktop note above)" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "Error: run this with sudo" >&2; exit 1; }

if [ "$#" -gt 0 ]; then
  for reg in "$@"; do
    dir="/etc/docker/certs.d/$reg"
    mkdir -p "$dir"
    cp "$ca" "$dir/ca.crt"
    chmod 644 "$dir/ca.crt"
    echo "[ok]   $reg: $dir/ca.crt"
  done
  echo "Takes effect on the next pull or push - no daemon restart needed."
  exit 0
fi

if [ -d /usr/local/share/ca-certificates ]; then
  dir=/usr/local/share/ca-certificates; update='update-ca-certificates'
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
  dir=/etc/pki/ca-trust/source/anchors; update='update-ca-trust extract'
elif [ -d /etc/pki/trust/anchors ]; then
  dir=/etc/pki/trust/anchors; update='update-ca-certificates'
else
  echo "Error: no CA trust directory found on this host" >&2
  exit 1
fi

cp "$ca" "$dir/netskope-ca.crt"
chmod 644 "$dir/netskope-ca.crt"
$update
echo "[ok]   Netskope CA installed in $dir"
echo "Restart the Docker daemon to pick it up, e.g. sudo systemctl restart docker"
'@

$dockerInjectorPs1 = @'
<#
.SYNOPSIS
    Installs the Netskope CA into running Docker containers.
.DESCRIPTION
    Pass container names/IDs, or none to patch every running container. Changes are lost
    when a container is recreated - bake the CA into the image (see Dockerfile.snippet)
    for anything longer-lived than a one-off test.
#>
param([string[]]$Containers)

$ErrorActionPreference = 'Stop'
$marker = '# Netskope CA (install-netskope-ca-in-container)'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ca   = Join-Path $here 'netskope-ca.crt'
if (-not (Test-Path $ca)) { Write-Error 'netskope-ca.crt not found next to this script'; exit 1 }

if (-not $Containers) {
    $Containers = @(& docker ps --format '{{.Names}}' 2>$null | Where-Object { $_ })
    if (-not $Containers) { Write-Host 'No running containers.'; exit 0 }
}

# Ordered so the first directory that exists wins, matching the .sh variant.
$layouts = @(
    @{ Dir = '/usr/local/share/ca-certificates'; Update = 'update-ca-certificates' }
    @{ Dir = '/etc/pki/ca-trust/source/anchors'; Update = 'update-ca-trust extract' }
    @{ Dir = '/etc/pki/trust/anchors';           Update = 'update-ca-certificates' }
)

foreach ($c in $Containers) {
    $layout = $null
    foreach ($l in $layouts) {
        & docker exec $c test -d $l.Dir 2>$null
        if ($LASTEXITCODE -eq 0) { $layout = $l; break }
    }
    if ($layout) {
        $target = "$($layout.Dir)/netskope-ca.crt"
        & docker cp $ca "${c}:$target" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { & docker exec $c chmod 644 $target 2>$null | Out-Null }
        if ($LASTEXITCODE -eq 0) { & docker exec $c sh -c $layout.Update 2>$null | Out-Null }

        if ($LASTEXITCODE -eq 0) { Write-Host "[ok]   ${c}: Netskope CA installed ($($layout.Dir))" }
        else                     { Write-Host "[warn] ${c}: failed to install the Netskope CA" }
        continue
    }

    # Minimal images (most Alpine-based ones) ship the merged bundle but no anchors directory
    # and no update-ca-certificates. Appending to the bundle is what OpenSSL and cURL read.
    $bundle = '/etc/ssl/certs/ca-certificates.crt'
    & docker exec $c test -f $bundle 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[skip] ${c}: no CA trust store found (install the ca-certificates package)"
        continue
    }
    & docker exec $c grep -qF $marker $bundle 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[ok]   ${c}: Netskope CA already present in $bundle"
        continue
    }
    & docker cp $ca "${c}:/tmp/netskope-ca.crt" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        & docker exec $c sh -c "echo '' >> $bundle && echo '$marker' >> $bundle && cat /tmp/netskope-ca.crt >> $bundle && rm -f /tmp/netskope-ca.crt" 2>$null | Out-Null
    }
    if ($LASTEXITCODE -eq 0) { Write-Host "[ok]   ${c}: Netskope CA appended to $bundle" }
    else                     { Write-Host "[warn] ${c}: failed to install the Netskope CA" }
}
'@

Write-Section 'Configuring Docker'

if (Test-Tool 'docker') {
    if (-not (Test-Path $dockerAssetDir)) { New-Item -ItemType Directory -Path $dockerAssetDir | Out-Null }

    # The CA that goes *into* containers. Prefer the Netskope-only chain; fall back to the
    # full bundle when the user reused a bundle built before this split existed.
    $caSource = $netskopeCaPath
    if (-not (Test-Path $netskopeCaPath) -or (Get-Item $netskopeCaPath).Length -eq 0) {
        $caSource = $bundlePath
        Write-Warn2 'netskope-ca.crt not found - using the full bundle (includes Mozilla roots)'
        Write-Host  '         Recreate the bundle to get a Netskope-only netskope-ca.crt.'
    }
    Copy-Item -LiteralPath $caSource -Destination (Join-Path $dockerAssetDir 'netskope-ca.crt') -Force

    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'Dockerfile.snippet')                    -Content $dockerfileSnippet
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'Dockerfile.example')                    -Content $dockerfileExample
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'Dockerfile.build-arg')                  -Content $dockerfileBuildArg
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'docker-compose.netskope.yml')           -Content $dockerCompose
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'netskope.env')                          -Content $dockerEnvFile
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'README.md')                             -Content $dockerReadme
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'install-netskope-ca-in-container.sh')   -Content $dockerInjectorSh
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'trust-netskope-ca-in-docker-daemon.sh') -Content $dockerDaemonSh
    Write-DockerAsset -Path (Join-Path $dockerAssetDir 'install-netskope-ca-in-container.ps1')  -Content $dockerInjectorPs1

    Write-OK "Docker build assets written: $dockerAssetDir"

    # `docker ps` fails when the daemon is not running (Docker Desktop stopped); the assets
    # above are still useful, so treat that as a soft skip.
    $runningContainers = @()
    try { $runningContainers = @(& docker ps --format '{{.Names}}' 2>$null | Where-Object { $_ }) } catch { }

    if ($runningContainers.Count -eq 0) {
        Write-Skip 'No running containers to patch (or the Docker daemon is not reachable)'
    } elseif ($NonInteractive) {
        Write-Skip 'Running containers left unchanged (non-interactive)'
    } else {
        Write-Host '  Running containers:'
        $runningContainers | ForEach-Object { Write-Host "    $_" }
        $resp = Read-Host '  Install the Netskope CA into these running containers now? (y/N)'
        if ($resp -match '^[Yy]') {
            & (Join-Path $dockerAssetDir 'install-netskope-ca-in-container.ps1')
            Write-Warn2 'Container changes are lost on recreate - bake the CA in via Dockerfile.snippet'
        } else {
            Write-Skip 'Running containers left unchanged'
        }
    }
} else {
    Write-Skip 'Docker not installed'
}

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
#
# Add -K8s [-K8sNamespace <name>] to also (re)generate the Kubernetes assets in:
#   $CertDir\k8s

[CmdletBinding()]
param([switch]`$K8s, [string]`$K8sNamespace)

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

`$k8sArgs = @()
if (`$K8s) { `$k8sArgs += '-K8s' }
if (`$K8sNamespace) { `$k8sArgs += @('-K8sNamespace', `$K8sNamespace) }

& `$main -CertName '$CertName' -CertDir '$CertDir'$tenantArg -NonInteractive @k8sArgs
"@

Set-Utf8NoBom -Path $deployPath -Content $replay

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Configuration complete.' -ForegroundColor Cyan
Write-Host "   Bundle:           $bundlePath"
Write-Host "   Replay script:    $deployPath"
Write-Host "   Script copy:      $selfCopy"
if (Test-Path $dockerAssetDir) { Write-Host "   Docker assets:    $dockerAssetDir" }
Write-Host ''
Write-Host ' To deploy on another machine: copy the bundle, configure_tools_windows.ps1,'
Write-Host '   and configured_tools.ps1 to the same directory, then run configured_tools.ps1.'
Write-Host ''
Write-Host ' Note: env-var changes (setx) are visible to NEW console windows / freshly'
Write-Host '   launched apps, not to processes that were already running.'
Write-Host '============================================================' -ForegroundColor Cyan
