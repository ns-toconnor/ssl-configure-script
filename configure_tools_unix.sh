#!/bin/bash
## Detects common CLI tools/apps on macOS or Linux and points them at a Netskope SSL
## certificate bundle. Uses the Netskope API (Bearer token) or the local STAgent certs.
##
## This single script replaces the former configure_tools_mac.sh / configure_tools_linux.sh;
## platform differences (rc file, STAgent path, app config locations) are detected via uname.

# Enable strict error handling
set -euo pipefail

# --- Platform detection ---
case "$(uname -s)" in
  Darwin) IS_MAC=true;  IS_LINUX=false ;;
  Linux)  IS_MAC=false; IS_LINUX=true  ;;
  *) echo "Error: unsupported OS '$(uname -s)' (this script handles macOS and Linux; use universal_configure_tools.py elsewhere)"; exit 1 ;;
esac

# --- Output helpers (mirrors configure_tools_windows.ps1 formatting) ---
if [ -t 1 ]; then
  C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_GRAY=$'\033[90m'; C_RESET=$'\033[0m'
else
  C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_GRAY=''; C_RESET=''
fi
say_section() { echo; printf '%s--- %s ---%s\n' "$C_CYAN" "$*" "$C_RESET"; }
say_ok()      { printf '%s[ok]%s   %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
say_skip()    { printf '%s[skip]%s %s\n' "$C_GRAY"   "$C_RESET" "$*"; }
say_warn()    { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }

# Constants
CURL_TIMEOUT=30
CURL_MAX_TIME=60
NETSKOPE_CERT_API_PATH="/api/v2/services/certs/subordinates?purpose=tenant_ca"
MOZILLA_BUNDLE_URL="https://curl.se/ca/cacert.pem"
# cacert.pem is ~230 KB; anything well below that is a captive-portal/proxy error page,
# not the real bundle. Guards against silently writing junk into the trust store.
MOZILLA_MIN_BYTES=50000

# --- Command-line options ---
# With no options the script is fully interactive, exactly as before. --cert-dir / --cert-name
# pre-answer the matching prompt; --non-interactive and --k8s are described in usage().
K8S=false
K8S_NAMESPACE=default
K8S_NAMESPACE_SET=false
CERT_DIR_ARG=""
CERT_NAME_ARG=""
NON_INTERACTIVE=false

usage() {
  cat <<'USAGE'
Usage: configure_tools_unix.sh [options]

With no options the script asks for everything it needs.

  --k8s                 Also write Kubernetes CA assets to <certDir>/k8s/
  --k8s-namespace NAME  Namespace used in the Kubernetes manifests (default: default)
  --cert-dir DIR        Bundle directory (skips that prompt)
  --cert-name NAME      Bundle filename (skips that prompt)
  --non-interactive     Never prompt. Reuses the existing bundle in --cert-dir/--cert-name,
                        so no tenant name or API token is needed. The tool configuration is
                        re-applied (it is idempotent) and configured_tools.sh is left as it
                        is. Fails if the bundle does not exist yet.
  -h, --help            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s)             K8S=true; shift ;;
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    -h|--help)         usage; exit 0 ;;
    --k8s-namespace|--cert-dir|--cert-name)
      [[ $# -ge 2 ]] || { echo "Error: $1 requires a value" >&2; exit 2; }
      case "$1" in
        --k8s-namespace) K8S_NAMESPACE=$2; K8S_NAMESPACE_SET=true ;;
        --cert-dir)      CERT_DIR_ARG=$2 ;;
        --cert-name)     CERT_NAME_ARG=$2 ;;
      esac
      shift 2 ;;
    --k8s-namespace=*) K8S_NAMESPACE=${1#*=}; K8S_NAMESPACE_SET=true; shift ;;
    --cert-dir=*)      CERT_DIR_ARG=${1#*=}; shift ;;
    --cert-name=*)     CERT_NAME_ARG=${1#*=}; shift ;;
    *) echo "Error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
  esac
done

# The namespace ends up in YAML, so hold it to a Kubernetes DNS-1123 label.
valid_k8s_namespace() {
  [[ "$1" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#1} -le 63 ]]
}
if ! valid_k8s_namespace "$K8S_NAMESPACE"; then
  echo "Error: invalid --k8s-namespace '$K8S_NAMESPACE' (lowercase letters, digits and '-', at most 63 characters)" >&2
  exit 2
fi

# Require python3 up front — used for API response parsing and JSON config edits
if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required"
  exit 1
fi

# Temp-file cleanup registry (runs on any script exit path)
_temp_files=()
cleanup_temps() {
  [[ ${#_temp_files[@]} -eq 0 ]] && return
  local f
  for f in "${_temp_files[@]}"; do
    [[ -n "$f" ]] && rm -rf "$f" 2>/dev/null || true
  done
}
register_temp() {
  _temp_files+=("$1")
}
trap cleanup_temps EXIT

# Pick the user's login-shell rc file. We rely on $SHELL (set by login) rather than
# `ps -p $$`, since the running process is always bash here (the script's shebang) and tells
# us nothing about the user's actual shell. macOS default since Catalina is zsh.
get_shell(){
    local login_shell="${SHELL##*/}"
    case "$login_shell" in
        zsh)
            # .zshenv is sourced for every zsh invocation (including non-interactive ones,
            # scripts, and GUI-launched terminals) — the right place for CA trust.
            SHELL_CONFIG="$HOME/.zshenv"
            ;;
        bash)
            # macOS reads ~/.bash_profile on login; most Linux distros source ~/.bashrc for
            # interactive shells (login-shell propagation comes via ~/.bash_profile/~/.profile).
            if [[ "$IS_MAC" == true ]]; then
                SHELL_CONFIG="$HOME/.bash_profile"
            else
                SHELL_CONFIG="$HOME/.bashrc"
            fi
            ;;
        *)
            # Unknown shell — default to .profile, which most POSIX shells read.
            SHELL_CONFIG="$HOME/.profile"
            ;;
    esac
    echo "Login shell: $login_shell  ->  using $SHELL_CONFIG"
}
get_shell

# --- Platform-specific paths ---
if [[ "$IS_MAC" == true ]]; then
  NS_CLIENT_CERT_DIR="/Library/Application Support/Netskope/STAgent/data"
  STORAGE_EXPLORER_CERTS_DIR="$HOME/Library/Application Support/StorageExplorer/certs"
  VSCODE_ROOT="$HOME/Library/Application Support"
  VSCODE_ENV_KEY="terminal.integrated.env.osx"
else
  NS_CLIENT_CERT_DIR="/opt/netskope/stagent/data"
  STORAGE_EXPLORER_CERTS_DIR="$HOME/.config/StorageExplorer/certs"
  VSCODE_ROOT="$HOME/.config"
  VSCODE_ENV_KEY="terminal.integrated.env.linux"
fi

# Get Netskope tenant name. --non-interactive reuses an existing bundle instead of building
# one, so there is nothing to fetch and no tenant is needed.
if [[ "$NON_INTERACTIVE" == true ]]; then
  tenantName=""
else
  read -p "Please provide full Netskope tenant name (ex: tenant-name.goskope.com): " tenantName
  if [[ -z "$tenantName" ]]; then
    echo "Error: Tenant name cannot be empty"
    exit 1
  fi

  # Validate tenant name format (basic check)
  if [[ ! "$tenantName" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "Error: Invalid tenant name format"
    exit 1
  fi
fi

NETSKOPE_CERT_API="https://$tenantName$NETSKOPE_CERT_API_PATH"

# Set Certificate bundle name and location (--cert-name / --cert-dir replace the prompts)
if [[ -n "$CERT_NAME_ARG" || "$NON_INTERACTIVE" == true ]]; then
  certName=${CERT_NAME_ARG:-netskope-cert-bundle.pem}
else
  read -p "Please provide certificate bundle name [netskope-cert-bundle.pem]: " certName
  certName=${certName:-netskope-cert-bundle.pem}
fi
if [[ -n "$CERT_DIR_ARG" || "$NON_INTERACTIVE" == true ]]; then
  certDir=${CERT_DIR_ARG:-~/netskope}
else
  read -p "Please provide certificate bundle location [~/netskope]: " certDir
  certDir=${certDir:-~/netskope}
fi

# Expand tilde properly
certDir="${certDir/#\~/$HOME}"

if [[ "$NON_INTERACTIVE" == true && ! -f "$certDir/$certName" ]]; then
  echo "Error: --non-interactive reuses an existing bundle, but $certDir/$certName does not exist" >&2
  echo "       Run the script once interactively to build it." >&2
  exit 1
fi

if [ ! -d "$certDir" ]; then
  echo "$certDir does not exist."
  echo "creating $certDir"
  mkdir -p "$certDir"
fi

# Silent-deployment script lives alongside the bundle, not in CWD
CONFIGURED_TOOLS_FILE="$certDir/configured_tools.sh"
REPLAY_FILE="$CONFIGURED_TOOLS_FILE"
if [[ "$NON_INTERACTIVE" == true && -f "$REPLAY_FILE" ]]; then
  # A replay re-applies the configuration but must not rewrite the replay script: re-runs skip
  # exports that are already set in the current shell, so a fresh file would lose those lines.
  # Record into a scratch file instead and leave the existing replay script untouched.
  CONFIGURED_TOOLS_FILE=$(mktemp)
  register_temp "$CONFIGURED_TOOLS_FILE"
fi

# Netskope-only certs, split out of the full bundle. Container trust stores already ship the
# Mozilla roots, so what they need is just the Netskope CA chain — and OS trust-store tools
# (update-ca-certificates / update-ca-trust) only pick up files with a .crt extension.
NETSKOPE_ONLY_CRT="$certDir/netskope-ca.crt"
DOCKER_ASSET_DIR="$certDir/docker"

# Check for local Netskope client certificates
NS_CA_CERT="$NS_CLIENT_CERT_DIR/nscacert.pem"
NS_TENANT_CERT="$NS_CLIENT_CERT_DIR/nstenantcert.pem"
use_local_certs=false

if [[ -f "$NS_CA_CERT" && -f "$NS_TENANT_CERT" && "$NON_INTERACTIVE" != true ]]; then
  say_section "Local Netskope client certificates detected"
  echo "  CA Certificate (nscacert.pem):"
  openssl x509 -in "$NS_CA_CERT" -noout -subject 2>/dev/null | sed 's/^/    /'
  echo "  Tenant Certificate (nstenantcert.pem):"
  openssl x509 -in "$NS_TENANT_CERT" -noout -subject 2>/dev/null | sed 's/^/    /'
  echo
  read -p "Use these local certificates instead of the API? (Y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    use_local_certs=true
  fi
fi

# Get API token for certificate retrieval (only needed if not using local certs)
api_token=""
if [[ "$use_local_certs" == false && "$NON_INTERACTIVE" != true ]]; then
  if [[ -n "${NETSKOPE_API_TOKEN:-}" ]]; then
    echo
    echo "Found NETSKOPE_API_TOKEN environment variable."
    echo "Token: ${NETSKOPE_API_TOKEN:0:8}..."
    read -p "Use this token? (Y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
      api_token="$NETSKOPE_API_TOKEN"
    fi
  fi

  if [[ -z "$api_token" ]]; then
    echo
    read -rsp "Please provide the Netskope API Bearer token: " api_token
    echo
    if [[ -z "$api_token" ]]; then
      echo "Error: API token cannot be empty"
      exit 1
    fi
  fi
fi

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Download a public file with TLS verification first, falling back to an insecure fetch only
# if verification fails. The Mozilla root bundle seeds the entire trust store, so an
# unvalidated fetch is an injection vector; verification succeeds whenever the host is NOT
# behind Netskope inspection. (Behind inspection the resigned cert isn't trusted yet — the
# very thing we're installing — so the fallback is unavoidable there.)
download_verified() {
  local url=$1 out=$2
  if curl --connect-timeout "$CURL_TIMEOUT" --max-time "$CURL_MAX_TIME" \
       --fail --silent --show-error "$url" -o "$out" 2>/dev/null; then
    return 0
  fi
  say_warn "Verified download failed (likely TLS inspection); retrying without verification"
  curl -k --connect-timeout "$CURL_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    --fail --silent --show-error "$url" -o "$out"
}

# Function to create or update certificate bundle
create_cert_bundle() {
  say_section "Building certificate bundle"
  local temp_file cert_file
  temp_file=$(mktemp)
  register_temp "$temp_file"
  local bundle_file="$certDir/$certName"

  if [[ "$use_local_certs" == true ]]; then
    # Use local Netskope client certificates
    echo "Using local Netskope client certificates..."
    cat "$NS_TENANT_CERT" > "$bundle_file"
    cat "$NS_CA_CERT" >> "$bundle_file"
    cat "$NS_TENANT_CERT" "$NS_CA_CERT" > "$NETSKOPE_ONLY_CRT"
    chmod 644 "$NETSKOPE_ONLY_CRT"
    say_ok "Netskope certificates added from local client"
  else
    # Download tenant CA certificates via API. The Bearer token is passed through a curl
    # --config file (mode 600 via mktemp) rather than on argv, so it never appears in `ps`
    # output on multi-user hosts.
    echo "Fetching Netskope tenant CA certificates from API..."
    local http_code api_cfg
    api_cfg=$(mktemp)
    register_temp "$api_cfg"
    printf 'header = "Authorization: Bearer %s"\n' "$api_token" > "$api_cfg"
    http_code=$(curl -k --connect-timeout "$CURL_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --silent --show-error --write-out '%{http_code}' \
      -X 'GET' \
      "$NETSKOPE_CERT_API" \
      -H 'accept: application/json' \
      --config "$api_cfg" \
      -o "$temp_file") || true

    if [[ "$http_code" -ne 200 ]]; then
      echo "Error: Failed to retrieve certificates from API (HTTP status: $http_code)"
      if [[ -s "$temp_file" ]]; then
        echo "Response: $(cat "$temp_file")"
      fi
      exit 1
    fi

    # Extract PEM certificates from JSON response
    cert_file=$(mktemp)
    register_temp "$cert_file"
    TEMP_FILE="$temp_file" python3 -c "
import json, os, sys

temp_file = os.environ['TEMP_FILE']

try:
    with open(temp_file, 'r') as f:
        data = json.load(f)

    certs = data.get('certificates', [])
    if not certs:
        print('Error: No certificates found in API response', file=sys.stderr)
        sys.exit(1)

    for cert in certs:
        # Include the subordinate/tenant CA certificate
        pem = cert.get('certificate', '')
        if pem:
            print(pem)
        # Include the issuer (root CA) certificate
        issuer = cert.get('issuer', '')
        if issuer:
            print(issuer)

except (json.JSONDecodeError, KeyError) as e:
    print(f'Error: Failed to parse API response: {e}', file=sys.stderr)
    sys.exit(1)
" > "$cert_file" || { echo "Error: Failed to extract certificates from API response"; exit 1; }

    if [ ! -s "$cert_file" ]; then
      echo "Error: No PEM certificates extracted from API response"
      exit 1
    fi

    say_ok "Netskope certificates retrieved successfully"

    # Write Netskope certs to bundle
    cp "$cert_file" "$bundle_file"
    cp "$cert_file" "$NETSKOPE_ONLY_CRT"
    chmod 644 "$NETSKOPE_ONLY_CRT"
  fi

  # Download Mozilla CA bundle (verify-first), sanity-check size, then append
  echo "Downloading Mozilla CA bundle..."
  local moz_temp moz_size
  moz_temp=$(mktemp)
  register_temp "$moz_temp"
  if ! download_verified "$MOZILLA_BUNDLE_URL" "$moz_temp"; then
    say_warn "Failed to download Mozilla CA bundle"
    exit 1
  fi
  moz_size=$(wc -c < "$moz_temp" | tr -d ' ')
  if [[ "$moz_size" -lt "$MOZILLA_MIN_BYTES" ]]; then
    say_warn "Mozilla CA bundle download looks truncated ($moz_size bytes) — aborting"
    exit 1
  fi
  cat "$moz_temp" >> "$bundle_file"

  # Verify final bundle is not empty
  if [ ! -s "$bundle_file" ]; then
    say_warn "Certificate bundle is empty"
    exit 1
  fi

  say_ok "Certificate bundle written: $bundle_file"
}

if [ -f "$certDir/$certName" ]; then
  echo "$certName already exists in $certDir."
  if [[ "$NON_INTERACTIVE" == true ]]; then
    REPLY=n
  else
    read -p "Recreate Certificate Bundle? (y/N) " -n 1 -r
    echo
  fi
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    create_cert_bundle
  else
    say_skip "Reusing existing bundle"
  fi
else
  create_cert_bundle
fi

# Function to add export to shell config files
add_export_to_shell() {
  local env_var=$1
  local value=$2
  local export_line="export $env_var=\"$value\""

  # Check if already exists in shell config
  if ! grep -Fxq "$export_line" "$SHELL_CONFIG" 2>/dev/null; then
    # Ensure file ends with a newline before appending so the new line doesn't get
    # concatenated onto whatever was on the last line.
    if [[ -f "$SHELL_CONFIG" ]] && [[ -n "$(tail -c 1 "$SHELL_CONFIG" 2>/dev/null)" ]]; then
      printf '\n' >> "$SHELL_CONFIG"
    fi
    echo "$export_line" >> "$SHELL_CONFIG"
  fi

  # Always add to silent-deployment script
  echo "$export_line" >> "$CONFIGURED_TOOLS_FILE"
}

# Function to configure a tool with the certificate bundle
configure_tool() {
  local tool_name=$1
  local env_var=$2
  local check_command=$3
  local post_command=$4

  if ! command_exists "$check_command"; then
    say_skip "$tool_name not installed"
    return
  fi

  if [[ -n "$env_var" ]]; then
    local cert_path="$certDir/$certName"
    # ${!env_var} only reflects the current shell; add_export_to_shell dedupes against the
    # shell-config file, so re-running is safe either way.
    if [[ -n "${!env_var:-}" && "${!env_var}" == "$cert_path" ]] \
       && grep -Fxq "export $env_var=\"$cert_path\"" "$SHELL_CONFIG" 2>/dev/null; then
      say_skip "$tool_name already configured ($env_var)"
    else
      add_export_to_shell "$env_var" "$cert_path"
      say_ok "$tool_name configured ($env_var)"
    fi
  fi

  if [[ -n "$post_command" ]]; then
    if eval "$post_command" >/dev/null 2>&1; then
      echo "$post_command" >> "$CONFIGURED_TOOLS_FILE"
      [[ -z "$env_var" ]] && say_ok "$tool_name configured"
    else
      say_warn "$tool_name post-configuration failed"
    fi
  fi
}

# Initialize silent-deployment script (intended to be sourced, not executed, so export lines
# take effect — but also marked executable so post-commands still run if invoked directly).
{
  echo '#!/bin/bash'
  echo '# Silent deployment for configured tools — source this file to apply exports.'
} > "$CONFIGURED_TOOLS_FILE"
chmod +x "$CONFIGURED_TOOLS_FILE"

# Configure tools
say_section "Configuring CLIs (env-var based)"
configure_tool "OpenSSL" "SSL_CERT_FILE" "openssl" ""
configure_tool "cURL" "CURL_CA_BUNDLE" "curl" ""
configure_tool "Python Requests Library" "REQUESTS_CA_BUNDLE" "python3" ""
configure_tool "AWS CLI" "AWS_CA_BUNDLE" "aws" ""
configure_tool "NodeJS" "NODE_EXTRA_CA_CERTS" "node" ""
# Ruby honors SSL_CERT_FILE (already set by OpenSSL entry above; this is a no-op on re-run)
configure_tool "Ruby" "SSL_CERT_FILE" "ruby" ""
# Azure CLI honors REQUESTS_CA_BUNDLE per Microsoft docs (already set above — safe no-op)
configure_tool "Azure CLI" "REQUESTS_CA_BUNDLE" "az" ""
configure_tool "Python PIP" "PIP_CERT" "pip3" ""
configure_tool "Oracle Cloud CLI" "OCI_CLI_CA_BUNDLE" "oci" ""
configure_tool "Cargo Package Manager" "CARGO_HTTP_CAINFO" "cargo" ""
configure_tool "Claude CLI" "NODE_EXTRA_CA_CERTS" "claude" ""

# Netskope CLI (ntsk) — set ALL of these. Empirically, ntsk hits raw ssl/urllib code paths
# that only honor SSL_CERT_FILE, even though its docs imply NETSKOPE_CA_BUNDLE is enough. On
# a host without openssl/curl/python on PATH, none of those vars get set elsewhere and ntsk
# fails with TLS errors.
if command_exists "ntsk"; then
  cert_path="$certDir/$certName"
  ntsk_changed=0
  for v in NETSKOPE_CA_BUNDLE SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE; do
    if grep -Fxq "export $v=\"$cert_path\"" "$SHELL_CONFIG" 2>/dev/null; then
      :
    else
      add_export_to_shell "$v" "$cert_path"
      ntsk_changed=1
    fi
  done
  if [[ $ntsk_changed -eq 1 ]]; then
    say_ok "Netskope CLI configured (NETSKOPE_CA_BUNDLE + SSL_CERT_FILE + REQUESTS_CA_BUNDLE + CURL_CA_BUNDLE)"
  else
    say_skip "Netskope CLI already configured"
  fi
else
  say_skip "Netskope CLI not installed"
fi

say_section "Configuring CLIs (native config)"
configure_tool "Git" "GIT_SSL_CAINFO" "git" ""
configure_tool "Google Cloud CLI" "" "gcloud" "gcloud config set core/custom_ca_certs_file \"$certDir/$certName\""
configure_tool "NodeJS Package Manager (NPM)" "" "npm" "npm config set cafile \"$certDir/$certName\""
configure_tool "PHP Composer" "" "composer" "composer config --global cafile \"$certDir/$certName\""
configure_tool "Yarn" "" "yarnpkg" "yarnpkg config set httpsCaFilePath \"$certDir/$certName\""

say_section "Configuring Docker"

# Docker containers do not inherit the host trust store — each image carries its own. The
# Netskope guidance (Confluence "Install the Netskope Certificates on the Docker machines
# that require Internet access") covers three deployment styles: patch a running container,
# bake the CA into an image via Dockerfile, or gate it on a build arg for compose. We can't
# know which one a given project uses, so we emit ready-to-use assets for all three and
# optionally patch the containers running right now.
#
# Note also that the OS trust store alone is not enough: Node, Python requests, pip, Cargo
# and Git each carry their own CA list, so the generated assets set the matching env vars too.
write_docker_assets() {
  mkdir -p "$DOCKER_ASSET_DIR"

  # The CA that goes *into* containers. Prefer the Netskope-only chain; fall back to the full
  # bundle when the user reused an existing bundle built before this script wrote the split.
  local ca_source="$NETSKOPE_ONLY_CRT"
  if [[ ! -s "$NETSKOPE_ONLY_CRT" ]]; then
    ca_source="$certDir/$certName"
    say_warn "netskope-ca.crt not found — using the full bundle (includes Mozilla roots)"
    echo "         Recreate the bundle to get a Netskope-only netskope-ca.crt."
  fi
  cp "$ca_source" "$DOCKER_ASSET_DIR/netskope-ca.crt"
  chmod 644 "$DOCKER_ASSET_DIR/netskope-ca.crt"

  cat > "$DOCKER_ASSET_DIR/Dockerfile.snippet" <<'EOF'
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
EOF

  cat > "$DOCKER_ASSET_DIR/Dockerfile.example" <<'EOF'
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
EOF

  cat > "$DOCKER_ASSET_DIR/Dockerfile.build-arg" <<'EOF'
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
EOF

  cat > "$DOCKER_ASSET_DIR/docker-compose.netskope.yml" <<'EOF'
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
EOF

  cat > "$DOCKER_ASSET_DIR/netskope.env" <<'EOF'
# Copy to ".env" next to your docker-compose file to enable CA installation at build time.
BUILD_ENV=development
EOF

  # Runtime injector for already-running containers. Self-locating so it keeps working after
  # the docker/ directory is copied to another machine.
  cat > "$DOCKER_ASSET_DIR/install-netskope-ca-in-container.sh" <<'EOF'
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
EOF
  chmod +x "$DOCKER_ASSET_DIR/install-netskope-ca-in-container.sh"

  cat > "$DOCKER_ASSET_DIR/trust-netskope-ca-in-docker-daemon.sh" <<'EOF'
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
EOF
  chmod +x "$DOCKER_ASSET_DIR/trust-netskope-ca-in-docker-daemon.sh"

  cat > "$DOCKER_ASSET_DIR/README.md" <<'EOF'
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
EOF
}

if command_exists docker; then
  write_docker_assets
  say_ok "Docker build assets written: $DOCKER_ASSET_DIR"

  # `docker ps` fails when the daemon is not running (Docker Desktop stopped, no socket
  # permission); the assets above are still useful, so treat it as a soft skip.
  if [[ "$NON_INTERACTIVE" == true ]]; then
    say_skip "Running containers left unchanged (non-interactive)"
  elif running_containers=$(docker ps --format '{{.Names}}' 2>/dev/null) && [[ -n "$running_containers" ]]; then
    echo "  Running containers:"
    echo "$running_containers" | sed 's/^/    /'
    read -p "  Install the Netskope CA into these running containers now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      "$DOCKER_ASSET_DIR/install-netskope-ca-in-container.sh" | sed 's/^/  /'
      say_warn "Container changes are lost on recreate — bake the CA in via Dockerfile.snippet"
    else
      say_skip "Running containers left unchanged"
    fi
  else
    say_skip "No running containers to patch (or the Docker daemon is not reachable)"
  fi

  {
    echo "# Netskope Docker assets: $DOCKER_ASSET_DIR (see its README.md)"
    echo "# Patch running containers: \"$DOCKER_ASSET_DIR/install-netskope-ca-in-container.sh\""
  } >> "$CONFIGURED_TOOLS_FILE"
else
  say_skip "Docker not installed"
fi

say_section "Configuring applications"

# Azure Storage Explorer
if [ -d "$STORAGE_EXPLORER_CERTS_DIR" ]; then
  storage_explorer_cert="$STORAGE_EXPLORER_CERTS_DIR/$certName"
  if [ -f "$storage_explorer_cert" ] && cmp -s "$certDir/$certName" "$storage_explorer_cert" 2>/dev/null; then
    say_skip "Azure Storage Explorer already configured"
  else
    cp "$certDir/$certName" "$STORAGE_EXPLORER_CERTS_DIR/"
    say_ok "Azure Storage Explorer configured"
    echo "cp \"$certDir/$certName\" \"$STORAGE_EXPLORER_CERTS_DIR/\"" >> "$CONFIGURED_TOOLS_FILE"
  fi
else
  say_skip "Azure Storage Explorer not installed"
fi

# Claude Desktop
# Detect-only: `env` at the top level of claude_desktop_config.json is not a recognized field
# (per-server env lives under mcpServers.<name>.env), so we no longer write it. Claude Desktop
# is Electron and reads NODE_EXTRA_CA_CERTS from the user environment at launch.
if [[ "$IS_MAC" == true ]]; then
  if [ -d "/Applications/Claude.app" ]; then
    say_ok "Claude Desktop detected (NODE_EXTRA_CA_CERTS already exported via shell config)"
    say_warn "macOS GUI apps do not inherit shell env vars. If needed, run:"
    echo "         launchctl setenv NODE_EXTRA_CA_CERTS \"$certDir/$certName\""
    echo "         then restart Claude Desktop."
  else
    say_skip "Claude Desktop not installed"
  fi
else
  if command_exists claude-desktop || [ -f "/usr/bin/claude-desktop" ] || [ -f "/opt/Claude/claude-desktop" ]; then
    say_ok "Claude Desktop detected (NODE_EXTRA_CA_CERTS already exported via shell config)"
    say_warn "Ensure NODE_EXTRA_CA_CERTS is in the environment used to launch GUI apps,"
    echo "         then restart Claude Desktop."
  else
    say_skip "Claude Desktop not installed"
  fi
fi

# Configure VS Code variants
configure_vscode_variant() {
  local variant_name=$1
  local settings_file=$2
  local exit_code had_comments

  if [ -f "$settings_file" ]; then
    cert_path="$certDir/$certName"

    # Note whether the original had JSONC comments — the python rewrite below (json.dump)
    # cannot preserve them, so we warn the user when they'll be lost.
    had_comments=0
    if grep -Eq '^[[:space:]]*//' "$settings_file" 2>/dev/null || grep -q '/\*' "$settings_file" 2>/dev/null; then
      had_comments=1
    fi

    # Backup existing settings
    cp "$settings_file" "${settings_file}.backup"

    CONFIG_PATH="$settings_file" CERT_PATH="$cert_path" VSCODE_ENV_KEY="$VSCODE_ENV_KEY" python3 -c "
import json, os, re, sys

config_path = os.environ['CONFIG_PATH']
cert_path = os.environ['CERT_PATH']
env_key = os.environ['VSCODE_ENV_KEY']

def strip_jsonc(s):
    # String-aware: do not touch // or /* inside string literals (e.g. https:// URLs).
    out, i, n, in_string = [], 0, len(s), False
    while i < n:
        c = s[i]
        if in_string:
            out.append(c)
            if c == '\\\\' and i + 1 < n:
                out.append(s[i+1]); i += 2; continue
            if c == '\"': in_string = False
            i += 1
        elif c == '\"':
            in_string = True; out.append(c); i += 1
        elif c == '/' and i + 1 < n and s[i+1] == '/':
            while i < n and s[i] != '\n': i += 1
        elif c == '/' and i + 1 < n and s[i+1] == '*':
            i += 2
            while i + 1 < n and not (s[i] == '*' and s[i+1] == '/'): i += 1
            i += 2
        else:
            out.append(c); i += 1
    return re.sub(r',\s*([}\]])', r'\1', ''.join(out))

try:
    with open(config_path, 'r') as f:
        content = f.read()

    settings = json.loads(strip_jsonc(content) or '{}')

    # Check if NODE_EXTRA_CA_CERTS is already set in terminal env
    terminal_env = settings.get(env_key, {})
    if terminal_env.get('NODE_EXTRA_CA_CERTS') == cert_path:
        sys.exit(2)

    # Set NODE_EXTRA_CA_CERTS in the integrated terminal environment
    if env_key not in settings:
        settings[env_key] = {}
    settings[env_key]['NODE_EXTRA_CA_CERTS'] = cert_path

    with open(config_path, 'w') as f:
        json.dump(settings, f, indent=2)

    sys.exit(0)
except Exception as e:
    print(f'Error updating {config_path}: {e}', file=sys.stderr)
    sys.exit(1)
" && exit_code=0 || exit_code=$?

    if [ "$exit_code" -eq 0 ]; then
      say_ok "$variant_name configured (NODE_EXTRA_CA_CERTS in integrated terminal)"
      if [ "$had_comments" -eq 1 ]; then
        say_warn "  Comments in $variant_name settings.json were not preserved on rewrite."
      fi
    elif [ "$exit_code" -eq 2 ]; then
      say_skip "$variant_name already configured"
    elif [ "$exit_code" -eq 1 ]; then
      # Restore backup on failure
      mv "${settings_file}.backup" "$settings_file" 2>/dev/null || true
      say_warn "Failed to configure $variant_name"
    fi

    # Clean up backup
    rm -f "${settings_file}.backup"
  else
    say_skip "$variant_name not installed"
  fi
}

configure_vscode_variant "VS Code" "$VSCODE_ROOT/Code/User/settings.json"
configure_vscode_variant "VS Code Insiders" "$VSCODE_ROOT/Code - Insiders/User/settings.json"
configure_vscode_variant "Cursor" "$VSCODE_ROOT/Cursor/User/settings.json"

echo
printf '%s============================================================%s\n' "$C_CYAN" "$C_RESET"
printf '%s Configuration complete.%s\n' "$C_CYAN" "$C_RESET"
echo "   Bundle:           $certDir/$certName"
echo "   Replay script:    $REPLAY_FILE"
echo "   Shell config:     $SHELL_CONFIG"
if [ -d "$DOCKER_ASSET_DIR" ]; then echo "   Docker assets:    $DOCKER_ASSET_DIR"; fi
echo
echo "   Open a new terminal, or run: source $SHELL_CONFIG"
echo "   For silent deployment elsewhere: source $REPLAY_FILE"
printf '%s============================================================%s\n' "$C_CYAN" "$C_RESET"
