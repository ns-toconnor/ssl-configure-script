#!/usr/bin/env python3
"""Cross-platform (macOS / Linux / Windows) port of the configure_tools_* scripts.

Detects popular CLI tools and desktop apps, then configures them to use a
Netskope SSL-inspection CA bundle. The bundle is fetched either from the
Netskope API (with a Bearer token) or, when the Netskope client is installed,
from the local STAgent data directory. Stdlib only — no third-party deps.
"""
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from getpass import getpass
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"
HOME = Path.home()

CURL_TIMEOUT = 60
MOZILLA_BUNDLE_URL = "https://curl.se/ca/cacert.pem"
NETSKOPE_CERT_API_PATH = "/api/v2/services/certs/subordinates?purpose=tenant_ca"

# SSL context that skips verification — we're bootstrapping trust, so the
# TLS chain we'd need to validate against is exactly the one we're installing.
INSECURE_CTX = ssl.create_default_context()
INSECURE_CTX.check_hostname = False
INSECURE_CTX.verify_mode = ssl.CERT_NONE


def detect_shell_config():
    if IS_WINDOWS:
        return None
    running_shell = os.environ.get("SHELL", "")
    print(f"Shell used is {running_shell}")
    if "zsh" in running_shell:
        return HOME / ".zshenv"
    if IS_MAC:
        return HOME / ".bash_profile"
    return HOME / ".bashrc"


SHELL_CONFIG = detect_shell_config()

_NS_CLIENT_DIRS = {
    "Darwin": Path("/Library/Application Support/Netskope/STAgent/data"),
    "Linux": Path("/opt/netskope/stagent/data"),
    "Windows": Path(r"C:\ProgramData\Netskope\STAgent\data"),
}
NS_CLIENT_DIR = _NS_CLIENT_DIRS.get(platform.system())
NS_CA_CERT = NS_CLIENT_DIR / "nscacert.pem" if NS_CLIENT_DIR else None
NS_TENANT_CERT = NS_CLIENT_DIR / "nstenantcert.pem" if NS_CLIENT_DIR else None


def prompt(message, default):
    v = input(f"{message} [{default}]: ").strip()
    return v or default


def die(msg):
    print(f"Error: {msg}")
    sys.exit(1)


# --- Interactive prompts ---

tenant_name = input(
    "Please provide full Netskope tenant name (ex: tenant-name.goskope.com): "
).strip()
if not tenant_name:
    die("Tenant name cannot be empty")
if not re.fullmatch(r"[a-zA-Z0-9.-]+", tenant_name):
    die("Invalid tenant name format")

NETSKOPE_CERT_API = f"https://{tenant_name}{NETSKOPE_CERT_API_PATH}"

cert_name = prompt("Please provide certificate bundle name", "netskope-cert-bundle.pem")
default_dir = r"C:\netskope" if IS_WINDOWS else "~/netskope"
cert_dir = Path(os.path.expanduser(prompt("Please provide certificate bundle location", default_dir)))
cert_dir.mkdir(parents=True, exist_ok=True)

bundle_path = cert_dir / cert_name
configured_tools_file = cert_dir / ("configured_tools.bat" if IS_WINDOWS else "configured_tools.sh")

# --- Local client cert detection ---
use_local_certs = False
if NS_CA_CERT and NS_CA_CERT.exists() and NS_TENANT_CERT.exists():
    print("\nNetskope client is installed. Found local certificates:")
    if shutil.which("openssl"):
        for label, path in (("CA Certificate (nscacert.pem)", NS_CA_CERT),
                            ("Tenant Certificate (nstenantcert.pem)", NS_TENANT_CERT)):
            try:
                subj = subprocess.check_output(
                    ["openssl", "x509", "-in", str(path), "-noout", "-subject"],
                    text=True,
                ).strip()
                print(f"  {label}: {subj}")
            except (subprocess.CalledProcessError, OSError):
                pass
    if input("Use these local certificates instead of the API? (Y/n) ").strip().lower() != "n":
        use_local_certs = True

# --- API token ---
api_token = ""
if not use_local_certs:
    env_token = os.environ.get("NETSKOPE_API_TOKEN", "")
    if env_token:
        print("\nFound NETSKOPE_API_TOKEN environment variable.")
        print(f"Token: {env_token[:8]}...")
        if input("Use this token? (Y/n) ").strip().lower() != "n":
            api_token = env_token
    if not api_token:
        api_token = getpass("Please provide the Netskope API Bearer token: ").strip()
        if not api_token:
            die("API token cannot be empty")


# --- Bundle construction ---

def fetch_api_certs():
    print("Fetching Netskope tenant CA certificates...")
    req = urllib.request.Request(
        NETSKOPE_CERT_API,
        headers={"Accept": "application/json", "Authorization": f"Bearer {api_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=CURL_TIMEOUT, context=INSECURE_CTX) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace") if e.fp else ""
        print(f"Error: Failed to retrieve certificates from API (HTTP {e.code})")
        if err_body:
            print(f"Response: {err_body}")
        sys.exit(1)
    except Exception as e:
        die(f"Failed to retrieve certificates from API: {e}")

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        die(f"Failed to parse API response: {e}")

    certs = data.get("certificates") or []
    if not certs:
        die("No certificates found in API response")

    pem_chunks = []
    for c in certs:
        for key in ("certificate", "issuer"):
            pem = (c.get(key) or "").strip()
            if pem:
                pem_chunks.append(pem + "\n")
    if not pem_chunks:
        die("No PEM certificates extracted from API response")

    print("Netskope certificates retrieved successfully")
    return "".join(pem_chunks).encode()


def fetch_mozilla_bundle():
    print("Downloading Mozilla CA bundle...")
    try:
        with urllib.request.urlopen(MOZILLA_BUNDLE_URL, timeout=CURL_TIMEOUT, context=INSECURE_CTX) as resp:
            return resp.read()
    except Exception as e:
        die(f"Failed to download Mozilla CA bundle: {e}")


def build_bundle():
    print("Creating cert bundle")
    parts = []
    if use_local_certs:
        print("Using local Netskope client certificates...")
        parts.append(NS_TENANT_CERT.read_bytes())
        parts.append(NS_CA_CERT.read_bytes())
        print("Netskope certificates added from local client")
    else:
        parts.append(fetch_api_certs())
    parts.append(fetch_mozilla_bundle())

    bundle_path.write_bytes(b"".join(parts))
    if bundle_path.stat().st_size == 0:
        die("Certificate bundle is empty")
    print(f"Certificate bundle created successfully: {bundle_path}")


if bundle_path.exists():
    print(f"{cert_name} already exists in {cert_dir}.")
    if input("Recreate Certificate Bundle? (y/N) ").strip().lower() == "y":
        build_bundle()
else:
    build_bundle()

# --- Silent-deployment script initialization ---
if IS_WINDOWS:
    configured_tools_file.write_text(
        "@echo off\n:: Silent deployment for configured tools\n"
    )
else:
    configured_tools_file.write_text(
        "#!/bin/bash\n# Silent deployment for configured tools — source this file to apply exports.\n"
    )
    os.chmod(configured_tools_file, 0o755)


def append_tools_file(line):
    with open(configured_tools_file, "a") as f:
        f.write(line + "\n")


def append_shell_config(export_line):
    if not SHELL_CONFIG:
        return
    existing = SHELL_CONFIG.read_text() if SHELL_CONFIG.exists() else ""
    if export_line in existing.splitlines():
        return
    prefix = "\n" if existing and not existing.endswith("\n") else ""
    with open(SHELL_CONFIG, "a") as f:
        f.write(prefix + export_line + "\n")


def set_env_var(env_var, value):
    if IS_WINDOWS:
        subprocess.run(["setx", env_var, value], check=False, stdout=subprocess.DEVNULL)
        append_tools_file(f'setx {env_var} "{value}"')
    else:
        line = f'export {env_var}="{value}"'
        append_shell_config(line)
        append_tools_file(line)


def command_exists(cmd):
    return shutil.which(cmd) is not None


def configure_tool(tool_name, env_var, check_command, post_command=None):
    print()
    if not command_exists(check_command):
        print(f"{tool_name} is not installed")
        return
    print(f"{tool_name} is installed")
    try:
        subprocess.run([check_command, "--version"], stderr=subprocess.STDOUT, check=False)
    except OSError:
        pass

    cert_path = str(bundle_path)
    if env_var:
        if os.environ.get(env_var) == cert_path:
            print(f"{tool_name} already configured in current shell")
        else:
            set_env_var(env_var, cert_path)
            print(f"{tool_name} configured")

    if post_command:
        try:
            subprocess.run(post_command, shell=True, check=True)
            append_tools_file(post_command)
            print(f"{tool_name} post-configuration completed")
        except subprocess.CalledProcessError:
            print(f"Warning: {tool_name} post-configuration failed")


bundle_arg = str(bundle_path)

# Git: Windows uses `git config`; Unix uses GIT_SSL_CAINFO (matches shell scripts).
if IS_WINDOWS:
    configure_tool("Git", None, "git", f'git config --global http.sslCAInfo "{bundle_arg}"')
else:
    configure_tool("Git", "GIT_SSL_CAINFO", "git")
configure_tool("OpenSSL", "SSL_CERT_FILE", "openssl")
configure_tool("cURL", "CURL_CA_BUNDLE", "curl")
configure_tool("Python Requests Library", "REQUESTS_CA_BUNDLE", "python3")
configure_tool("AWS CLI", "AWS_CA_BUNDLE", "aws")
configure_tool("Google Cloud CLI", None, "gcloud",
               f'gcloud config set core/custom_ca_certs_file "{bundle_arg}"')
configure_tool("NodeJS Package Manager (NPM)", None, "npm",
               f'npm config set cafile "{bundle_arg}"')
configure_tool("NodeJS", "NODE_EXTRA_CA_CERTS", "node")
# Ruby honors SSL_CERT_FILE (already set by OpenSSL entry — no-op on re-run)
configure_tool("Ruby", "SSL_CERT_FILE", "ruby")
configure_tool("PHP Composer", None, "composer",
               f'composer config --global cafile "{bundle_arg}"')
# Azure CLI honors REQUESTS_CA_BUNDLE (same var as Python Requests — safe no-op)
configure_tool("Azure CLI", "REQUESTS_CA_BUNDLE", "az")
configure_tool("Python PIP", "PIP_CERT", "pip3")
configure_tool("Oracle Cloud CLI", "OCI_CLI_CA_BUNDLE", "oci")
configure_tool("Cargo Package Manager", "CARGO_HTTP_CAINFO", "cargo")
configure_tool("Yarn", None, "yarnpkg",
               f'yarnpkg config set httpsCaFilePath "{bundle_arg}"')
configure_tool("Claude CLI", "NODE_EXTRA_CA_CERTS", "claude")

# --- Azure Storage Explorer ---
print()
if IS_MAC:
    se_dir = HOME / "Library/Application Support/StorageExplorer/certs"
elif IS_LINUX:
    se_dir = HOME / ".config/StorageExplorer/certs"
else:
    local_appdata = Path(os.environ.get("LOCALAPPDATA", ""))
    se_dir = local_appdata / "Programs/Microsoft Azure Storage Explorer/certs"

if se_dir.is_dir():
    print("Azure Storage Explorer is installed")
    target = se_dir / cert_name
    if target.exists() and target.read_bytes() == bundle_path.read_bytes():
        print("Azure Storage Explorer already configured with current certificate")
    else:
        shutil.copy2(bundle_path, se_dir)
        print("Azure Storage Explorer configured")
        if IS_WINDOWS:
            append_tools_file(f'copy /y "{bundle_path}" "{se_dir}\\"')
        else:
            append_tools_file(f'cp "{bundle_path}" "{se_dir}/"')
else:
    print("Azure Storage Explorer is not installed")


# --- Claude Desktop ---
def patch_json_config(path, env_key):
    """Patch a JSON config file so `env_key -> NODE_EXTRA_CA_CERTS` points at the bundle.
    Returns 'already', 'configured', or raises on hard failure."""
    content = path.read_text() or "{}"
    if env_key is None:
        # Claude Desktop: env lives at top level
        data = json.loads(content)
        existing = data.get("env", {}).get("NODE_EXTRA_CA_CERTS")
        if existing == str(bundle_path):
            return "already"
        data.setdefault("env", {})["NODE_EXTRA_CA_CERTS"] = str(bundle_path)
    else:
        # VS Code: strip JSONC comments first
        stripped = re.sub(r"//.*?$", "", content, flags=re.MULTILINE)
        stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.DOTALL)
        stripped = re.sub(r",\s*([}\]])", r"\1", stripped)
        data = json.loads(stripped or "{}")
        if data.get(env_key, {}).get("NODE_EXTRA_CA_CERTS") == str(bundle_path):
            return "already"
        data.setdefault(env_key, {})["NODE_EXTRA_CA_CERTS"] = str(bundle_path)
    path.write_text(json.dumps(data, indent=2))
    return "configured"


print()
if IS_MAC:
    claude_config = HOME / "Library/Application Support/Claude/claude_desktop_config.json"
    claude_installed = Path("/Applications/Claude.app").is_dir()
elif IS_LINUX:
    claude_config = HOME / ".config/Claude/claude_desktop_config.json"
    claude_installed = (
        command_exists("claude-desktop")
        or Path("/usr/bin/claude-desktop").is_file()
        or Path("/opt/Claude/claude-desktop").is_file()
    )
else:
    appdata = Path(os.environ.get("APPDATA", ""))
    local_appdata = Path(os.environ.get("LOCALAPPDATA", ""))
    program_files = Path(os.environ.get("ProgramFiles", ""))
    claude_config = appdata / "Claude/claude_desktop_config.json"
    claude_installed = any(
        p.exists() for p in (
            local_appdata / "Programs/claude-desktop/Claude.exe",
            program_files / "Claude/Claude.exe",
            local_appdata / "Claude/Claude.exe",
        )
    )

if claude_installed:
    print("Claude Desktop is installed")
    claude_config.parent.mkdir(parents=True, exist_ok=True)
    if not claude_config.exists():
        claude_config.write_text("{}")

    backup = claude_config.with_suffix(claude_config.suffix + ".backup")
    shutil.copy2(claude_config, backup)
    try:
        result = patch_json_config(claude_config, env_key=None)
        if result == "already":
            print("Claude Desktop already configured")
        else:
            print("Claude Desktop configured")
            marker = ("echo Claude Desktop configured with NODE_EXTRA_CA_CERTS"
                      if IS_WINDOWS else
                      "echo 'Claude Desktop configured with NODE_EXTRA_CA_CERTS'")
            append_tools_file(marker)
    except Exception as e:
        shutil.copy2(backup, claude_config)
        print(f"Warning: Failed to configure Claude Desktop: {e}")
    finally:
        try:
            backup.unlink()
        except OSError:
            pass
    print("Note: Please restart Claude Desktop for changes to take effect")
else:
    print("Claude Desktop is not installed")


# --- VS Code variants ---
VSCODE_ENV_KEY = {
    "Darwin": "terminal.integrated.env.osx",
    "Linux": "terminal.integrated.env.linux",
    "Windows": "terminal.integrated.env.windows",
}[platform.system()]


def configure_vscode_variant(name, settings_file):
    print()
    if not settings_file.is_file():
        print(f"{name} is not installed")
        return
    print(f"{name} is installed")
    backup = settings_file.with_suffix(settings_file.suffix + ".backup")
    shutil.copy2(settings_file, backup)
    try:
        result = patch_json_config(settings_file, env_key=VSCODE_ENV_KEY)
        if result == "already":
            print(f"{name}: already configured")
        else:
            print(f"{name} configured with NODE_EXTRA_CA_CERTS in terminal environment")
    except Exception as e:
        shutil.copy2(backup, settings_file)
        print(f"Warning: Failed to configure {name}: {e}")
    finally:
        try:
            backup.unlink()
        except OSError:
            pass
    print(f"Note: Please restart {name} for changes to take effect")


if IS_MAC:
    vscode_root = HOME / "Library/Application Support"
elif IS_LINUX:
    vscode_root = HOME / ".config"
else:
    vscode_root = Path(os.environ.get("APPDATA", ""))

configure_vscode_variant("VS Code", vscode_root / "Code/User/settings.json")
configure_vscode_variant("VS Code Insiders", vscode_root / "Code - Insiders/User/settings.json")
configure_vscode_variant("Cursor", vscode_root / "Cursor/User/settings.json")


# --- Final summary ---
print()
print("Configuration complete!")
if SHELL_CONFIG:
    print(f"Please restart your terminal or run: source {SHELL_CONFIG}")
else:
    print("Note: setx changes take effect in NEW console windows (not this one).")
print()
if IS_WINDOWS:
    print(f'For silent deployment on other machines, run: "{configured_tools_file}"')
else:
    print(f"For silent deployment on other machines, run: source {configured_tools_file}")
