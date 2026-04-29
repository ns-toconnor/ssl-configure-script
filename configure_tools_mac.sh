#!/bin/bash
## This tool will try to detect common cli tools and will configure the Netskope SSL certificate bundle.
## Uses the Netskope API to retrieve tenant CA certificates instead of the org key method.

# Enable strict error handling
set -euo pipefail

# Constants
CURL_TIMEOUT=30
CURL_MAX_TIME=60
NETSKOPE_CERT_API_PATH="/api/v2/services/certs/subordinates?purpose=tenant_ca"

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

# Check which shell environment is used (zsh or bash)
get_shell(){
    local running_shell
    running_shell=$(ps -p $$ -o comm= 2>/dev/null || echo "${SHELL##*/}")
    echo "Shell used is $running_shell"
    # Note: .zshenv is sourced for every zsh invocation (including scripts),
    # which is what we want for tool CA trust but can affect non-interactive shells.
    if [[ "$running_shell" == *"bash"* ]] || [[ "${SHELL}" == *"bash"* ]]; then
        SHELL_CONFIG="$HOME/.bash_profile"
    else
        SHELL_CONFIG="$HOME/.zshenv"
    fi
}
get_shell

# Get Netskope tenant name
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

NETSKOPE_CERT_API="https://$tenantName$NETSKOPE_CERT_API_PATH"

# Set Certificate bundle name and location
read -p "Please provide certificate bundle name [netskope-cert-bundle.pem]: " certName
certName=${certName:-netskope-cert-bundle.pem}
read -p "Please provide certificate bundle location [~/netskope]: " certDir
certDir=${certDir:-~/netskope}

# Expand tilde properly
certDir="${certDir/#\~/$HOME}"

if [ ! -d "$certDir" ]; then
  echo "$certDir does not exist."
  echo "creating $certDir"
  mkdir -p "$certDir"
fi

# Silent-deployment script lives alongside the bundle, not in CWD
CONFIGURED_TOOLS_FILE="$certDir/configured_tools.sh"

# Check for local Netskope client certificates
NS_CLIENT_CERT_DIR="/Library/Application Support/Netskope/STAgent/data"
NS_CA_CERT="$NS_CLIENT_CERT_DIR/nscacert.pem"
NS_TENANT_CERT="$NS_CLIENT_CERT_DIR/nstenantcert.pem"
use_local_certs=false

if [[ -f "$NS_CA_CERT" && -f "$NS_TENANT_CERT" ]]; then
  echo
  echo "Netskope client is installed. Found local certificates:"
  echo
  echo "CA Certificate (nscacert.pem):"
  openssl x509 -in "$NS_CA_CERT" -noout -subject 2>/dev/null | sed 's/^/  /'
  echo
  echo "Tenant Certificate (nstenantcert.pem):"
  openssl x509 -in "$NS_TENANT_CERT" -noout -subject 2>/dev/null | sed 's/^/  /'
  echo
  read -p "Use these local certificates instead of the API? (Y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    use_local_certs=true
  fi
fi

# Get API token for certificate retrieval (only needed if not using local certs)
api_token=""
if [[ "$use_local_certs" == false ]]; then
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

# Function to create or update certificate bundle
create_cert_bundle() {
  echo "Creating cert bundle"
  local temp_file cert_file
  temp_file=$(mktemp)
  register_temp "$temp_file"
  local bundle_file="$certDir/$certName"

  if [[ "$use_local_certs" == true ]]; then
    # Use local Netskope client certificates
    echo "Using local Netskope client certificates..."
    cat "$NS_TENANT_CERT" > "$bundle_file"
    cat "$NS_CA_CERT" >> "$bundle_file"
    echo "Netskope certificates added from local client"
  else
    # Download tenant CA certificates via API
    echo "Fetching Netskope tenant CA certificates..."
    local http_code
    http_code=$(curl -k --connect-timeout "$CURL_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --silent --show-error --write-out '%{http_code}' \
      -X 'GET' \
      "$NETSKOPE_CERT_API" \
      -H 'accept: application/json' \
      -H "Authorization: Bearer $api_token" \
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

    echo "Netskope certificates retrieved successfully"

    # Write Netskope certs to bundle
    cp "$cert_file" "$bundle_file"
  fi

  # Download Mozilla CA bundle and append
  echo "Downloading Mozilla CA bundle..."
  if ! curl -k --connect-timeout "$CURL_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    --fail --silent --show-error "https://curl.se/ca/cacert.pem" >> "$bundle_file"; then
    echo "Error: Failed to download Mozilla CA bundle"
    exit 1
  fi

  # Verify final bundle is not empty
  if [ ! -s "$bundle_file" ]; then
    echo "Error: Certificate bundle is empty"
    exit 1
  fi

  echo "Certificate bundle created successfully: $bundle_file"
}

if [ -f "$certDir/$certName" ]; then
  echo "$certName already exists in $certDir."
  read -p "Recreate Certificate Bundle? (y/N) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    create_cert_bundle
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
    # Ensure file ends with a newline before appending so the new line doesn't
    # get concatenated onto whatever was on the last line.
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

  echo
  if command_exists "$check_command"; then
    echo "$tool_name is installed"

    # Try to show version (redirect stderr to handle tools that output version to stderr)
    "$check_command" --version 2>&1 || true

    if [[ -n "$env_var" ]]; then
      local cert_path="$certDir/$certName"
      # ${!env_var} only reflects the current shell; add_export_to_shell dedupes
      # against the shell-config file, so re-running is safe either way.
      if [[ -n "${!env_var:-}" && "${!env_var}" == "$cert_path" ]]; then
        echo "$tool_name already configured in current shell"
      else
        add_export_to_shell "$env_var" "$cert_path"
        echo "$tool_name configured"
      fi
    fi

    if [[ -n "$post_command" ]]; then
      if eval "$post_command"; then
        echo "$post_command" >> "$CONFIGURED_TOOLS_FILE"
        echo "$tool_name post-configuration completed"
      else
        echo "Warning: $tool_name post-configuration failed"
      fi
    fi
  else
    echo "$tool_name is not installed"
  fi
}

# Initialize silent-deployment script (intended to be sourced, not executed,
# so export lines take effect — but also marked executable so post-commands
# still run if invoked directly).
{
  echo '#!/bin/bash'
  echo '# Silent deployment for configured tools — source this file to apply exports.'
} > "$CONFIGURED_TOOLS_FILE"
chmod +x "$CONFIGURED_TOOLS_FILE"

# Configure tools
configure_tool "Git" "GIT_SSL_CAINFO" "git" ""
configure_tool "OpenSSL" "SSL_CERT_FILE" "openssl" ""
configure_tool "cURL" "CURL_CA_BUNDLE" "curl" ""
configure_tool "Python Requests Library" "REQUESTS_CA_BUNDLE" "python3" ""
configure_tool "AWS CLI" "AWS_CA_BUNDLE" "aws" ""
configure_tool "Google Cloud CLI" "" "gcloud" "gcloud config set core/custom_ca_certs_file \"$certDir/$certName\""
configure_tool "NodeJS Package Manager (NPM)" "" "npm" "npm config set cafile \"$certDir/$certName\""
configure_tool "NodeJS" "NODE_EXTRA_CA_CERTS" "node" ""
# Ruby honors SSL_CERT_FILE (already set by OpenSSL entry above; this is a no-op on re-run)
configure_tool "Ruby" "SSL_CERT_FILE" "ruby" ""
configure_tool "PHP Composer" "" "composer" "composer config --global cafile \"$certDir/$certName\""
# Azure CLI honors REQUESTS_CA_BUNDLE per Microsoft docs (already set above — safe no-op)
configure_tool "Azure CLI" "REQUESTS_CA_BUNDLE" "az" ""
configure_tool "Python PIP" "PIP_CERT" "pip3" ""
configure_tool "Oracle Cloud CLI" "OCI_CLI_CA_BUNDLE" "oci" ""
configure_tool "Cargo Package Manager" "CARGO_HTTP_CAINFO" "cargo" ""
configure_tool "Yarn" "" "yarnpkg" "yarnpkg config set httpsCaFilePath \"$certDir/$certName\""
configure_tool "Claude CLI" "NODE_EXTRA_CA_CERTS" "claude" ""

# Netskope CLI (ntsk) — set ALL of these. Empirically, ntsk hits raw ssl/urllib
# code paths that only honor SSL_CERT_FILE, even though its docs imply
# NETSKOPE_CA_BUNDLE is enough. On a host without openssl/curl/python on PATH,
# none of those vars get set elsewhere and ntsk fails with TLS errors.
echo
if command_exists "ntsk"; then
  echo "Netskope CLI is installed"
  ntsk --version 2>&1 || true
  cert_path="$certDir/$certName"
  for v in NETSKOPE_CA_BUNDLE SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE; do
    if [[ -n "${!v:-}" && "${!v}" == "$cert_path" ]]; then
      echo "  $v already set in current shell"
    else
      add_export_to_shell "$v" "$cert_path"
      echo "  $v configured"
    fi
  done
else
  echo "Netskope CLI is not installed"
fi

# Check if Azure Storage Explorer exists
echo
storage_explorer_certs_dir="$HOME/Library/Application Support/StorageExplorer/certs"
if [ -d "$storage_explorer_certs_dir" ]; then
  echo "Azure Storage Explorer is installed"
  storage_explorer_cert="$storage_explorer_certs_dir/$certName"
  if [ -f "$storage_explorer_cert" ] && cmp -s "$certDir/$certName" "$storage_explorer_cert" 2>/dev/null; then
    echo "Azure Storage Explorer already configured with current certificate"
  else
    cp "$certDir/$certName" "$storage_explorer_certs_dir/"
    echo "Azure Storage Explorer configured"
    echo "cp \"$certDir/$certName\" \"$storage_explorer_certs_dir/\"" >> "$CONFIGURED_TOOLS_FILE"
  fi
else
  echo "Azure Storage Explorer is not installed"
fi

# Claude Desktop
# Detect-only: `env` at the top level of claude_desktop_config.json is not a recognized
# field (per-server env lives under mcpServers.<name>.env), so we no longer write it.
# GUI apps on macOS do not inherit env vars from shell rc files; if Claude Desktop's
# bundled Node needs the CA bundle, set it via:
#   launchctl setenv NODE_EXTRA_CA_CERTS "$certDir/$certName"
echo
if [ -d "/Applications/Claude.app" ]; then
  echo "Claude Desktop is installed"
  echo "Note: macOS GUI apps do not inherit shell env vars. If needed, run:"
  echo "      launchctl setenv NODE_EXTRA_CA_CERTS \"$certDir/$certName\""
  echo "      then restart Claude Desktop."
else
  echo "Claude Desktop is not installed"
fi

# Configure VS Code variants
configure_vscode_variant() {
  local variant_name=$1
  local settings_file=$2
  local exit_code

  echo
  if [ -f "$settings_file" ]; then
    echo "$variant_name is installed"

    cert_path="$certDir/$certName"

    # Backup existing settings
    cp "$settings_file" "${settings_file}.backup"

    CONFIG_PATH="$settings_file" CERT_PATH="$cert_path" python3 -c "
import json, os, re, sys

config_path = os.environ['CONFIG_PATH']
cert_path = os.environ['CERT_PATH']

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
    terminal_env = settings.get('terminal.integrated.env.osx', {})
    if terminal_env.get('NODE_EXTRA_CA_CERTS') == cert_path:
        print(f'{config_path}: already configured')
        sys.exit(2)

    # Set NODE_EXTRA_CA_CERTS in the integrated terminal environment
    if 'terminal.integrated.env.osx' not in settings:
        settings['terminal.integrated.env.osx'] = {}
    settings['terminal.integrated.env.osx']['NODE_EXTRA_CA_CERTS'] = cert_path

    with open(config_path, 'w') as f:
        json.dump(settings, f, indent=2)

    print(f'{config_path}: configured successfully')
    sys.exit(0)
except Exception as e:
    print(f'Error updating {config_path}: {e}')
    sys.exit(1)
" && exit_code=0 || exit_code=$?

    if [ "$exit_code" -eq 0 ]; then
      echo "$variant_name configured with NODE_EXTRA_CA_CERTS in terminal environment"
    elif [ "$exit_code" -eq 1 ]; then
      # Restore backup on failure
      mv "${settings_file}.backup" "$settings_file" 2>/dev/null || true
      echo "Warning: Failed to configure $variant_name"
    fi

    # Clean up backup
    rm -f "${settings_file}.backup"

    echo "Note: Please restart $variant_name for changes to take effect"
  else
    echo "$variant_name is not installed"
  fi
}

configure_vscode_variant "VS Code" "$HOME/Library/Application Support/Code/User/settings.json"
configure_vscode_variant "VS Code Insiders" "$HOME/Library/Application Support/Code - Insiders/User/settings.json"
configure_vscode_variant "Cursor" "$HOME/Library/Application Support/Cursor/User/settings.json"

echo
echo "Configuration complete!"
echo "Please restart your terminal or run: source $SHELL_CONFIG"
echo
echo "For silent deployment on other machines, run: source $CONFIGURED_TOOLS_FILE"
