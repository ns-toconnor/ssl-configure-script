#!/usr/bin/env python3
"""Cross-platform (macOS / Linux / Windows) port of the configure_tools_* scripts.

Detects popular CLI tools and desktop apps, then configures them to use a
Netskope SSL-inspection CA bundle. The bundle is fetched either from the
Netskope API (with a Bearer token) or, when the Netskope client is installed,
from the local STAgent data directory. Stdlib only — no third-party deps.
"""
import argparse
import atexit
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
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
# cacert.pem is ~230 KB; anything well below that is a captive-portal/proxy error page,
# not the real bundle. Guards against silently writing junk into the trust store.
MOZILLA_MIN_BYTES = 50000
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


SHELL_CONFIG = None  # set by main(): detect_shell_config() prints

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
    # Verify the TLS chain first — this download seeds the entire root trust store, so an
    # unvalidated fetch is an injection vector. Verification succeeds whenever the host is
    # NOT behind Netskope inspection; only then fall back to insecure (behind inspection the
    # resigned cert isn't trusted yet — the very thing we're installing).
    body = None
    try:
        with urllib.request.urlopen(MOZILLA_BUNDLE_URL, timeout=CURL_TIMEOUT) as resp:
            body = resp.read()
    except Exception:
        print("  Verified download failed (likely TLS inspection); retrying without verification.")
        try:
            with urllib.request.urlopen(MOZILLA_BUNDLE_URL, timeout=CURL_TIMEOUT, context=INSECURE_CTX) as resp:
                body = resp.read()
        except Exception as e:
            die(f"Failed to download Mozilla CA bundle: {e}")
    if len(body) < MOZILLA_MIN_BYTES:
        die(f"Mozilla CA bundle download looks truncated ({len(body)} bytes) — aborting")
    return body


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

    # Everything gathered so far is Netskope-only; keep a copy before the Mozilla roots land.
    netskope_ca_path.write_bytes(b"".join(parts))
    os.chmod(netskope_ca_path, 0o644)

    parts.append(fetch_mozilla_bundle())

    bundle_path.write_bytes(b"".join(parts))
    if bundle_path.stat().st_size == 0:
        die("Certificate bundle is empty")
    print(f"Certificate bundle created successfully: {bundle_path}")


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


# --- Docker -----------------------------------------------------------------
# Containers carry their own trust store, so nothing configured above reaches them. The
# Netskope guidance ("Install the Netskope Certificates on the Docker machines that require
# Internet access") covers three deployment styles — patch a running container, bake the CA
# into an image, or gate it on a build arg for compose — and we can't know which one a given
# project uses, so emit ready-to-use assets for all three.
#
# The OS trust store alone is also not enough: Node, Python requests, pip, Cargo and Git each
# carry their own CA list, hence the ENV block in the generated Dockerfiles.

DOCKERFILE_SNIPPET = """\
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
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/netskope-ca.crt \\
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \\
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \\
    CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt
# On RHEL-family images the merged bundle lives at /etc/pki/tls/certs/ca-bundle.crt -
# substitute that path above, and point NODE_EXTRA_CA_CERTS at the anchors copy.
# ---------------------------------------------------------------------------
"""

DOCKERFILE_EXAMPLE = """\
# Standalone example: Debian/Ubuntu base image that trusts the Netskope CA.
# Build from this directory so netskope-ca.crt is in the build context:
#   docker build -f Dockerfile.example -t ubuntu-netskope .
FROM ubuntu

RUN apt-get update -y \\
 && apt-get install -y --no-install-recommends ca-certificates curl wget \\
 && rm -rf /var/lib/apt/lists/*

# Install the Netskope CA into the OS trust store
COPY netskope-ca.crt /usr/local/share/ca-certificates/netskope-ca.crt
RUN chmod 644 /usr/local/share/ca-certificates/netskope-ca.crt && update-ca-certificates

# Runtimes that ignore the OS trust store
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/netskope-ca.crt \\
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \\
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \\
    CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt

# Verify at build time (optional): RUN curl -fsS https://www.google.com -o /dev/null
"""

DOCKERFILE_BUILD_ARG = """\
# Conditional variant for Dockerfiles shared across environments: the CA is installed only
# when BUILD_ENV=development, so images built in CI (no SSL inspection) stay untouched.
#   docker build --build-arg BUILD_ENV=development -f Dockerfile.build-arg -t myimage .
FROM ubuntu

RUN apt-get update -y \\
 && apt-get install -y --no-install-recommends ca-certificates curl wget \\
 && rm -rf /var/lib/apt/lists/*

ARG BUILD_ENV
ARG CERT_DIR=/usr/local/share/ca-certificates
ENV BUILD_ENV=$BUILD_ENV

COPY netskope-ca.crt /tmp/netskope-ca.crt
RUN if [ "$BUILD_ENV" = "development" ]; then \\
        cp /tmp/netskope-ca.crt "$CERT_DIR/netskope-ca.crt" && \\
        chmod 644 "$CERT_DIR/netskope-ca.crt" && \\
        update-ca-certificates; \\
    fi; \\
    rm -f /tmp/netskope-ca.crt

# Harmless when the CA was not installed - these paths exist in any ca-certificates image.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \\
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \\
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
"""

DOCKER_COMPOSE = """\
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
"""

DOCKER_ENV = """\
# Copy to ".env" next to your docker-compose file to enable CA installation at build time.
BUILD_ENV=development
"""

DOCKER_README = """\
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
"""

DOCKER_INJECTOR_SH = """\
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
    if docker cp "$ca" "$c:$dir/netskope-ca.crt" >/dev/null 2>&1 \\
       && docker exec "$c" chmod 644 "$dir/netskope-ca.crt" >/dev/null 2>&1 \\
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
  elif docker cp "$ca" "$c:/tmp/netskope-ca.crt" >/dev/null 2>&1 \\
       && docker exec "$c" sh -c "echo '' >> $bundle && echo '$marker' >> $bundle && cat /tmp/netskope-ca.crt >> $bundle && rm -f /tmp/netskope-ca.crt" >/dev/null 2>&1; then
    echo "[ok]   $c: Netskope CA appended to $bundle"
  else
    echo "[warn] $c: failed to install the Netskope CA"
  fi
done
"""

DOCKER_DAEMON_SH = """\
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
"""

DOCKER_INJECTOR_PS1 = """\
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
"""

# Fallback for minimal images with no anchors directory: the merged bundle every OpenSSL
# build reads, plus a marker line that makes re-runs idempotent (text outside the
# BEGIN/END CERTIFICATE delimiters is ignored by OpenSSL).
CONTAINER_MERGED_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
CONTAINER_CA_MARKER = "# Netskope CA (install-netskope-ca-in-container)"

# Ordered so the first directory that exists wins.
CONTAINER_TRUST_LAYOUTS = (
    ("/usr/local/share/ca-certificates", "update-ca-certificates"),
    ("/etc/pki/ca-trust/source/anchors", "update-ca-trust extract"),
    ("/etc/pki/trust/anchors", "update-ca-certificates"),
)


def write_asset(path, text, executable=False):
    """Write with LF endings — these files are consumed inside Linux containers, where the
    CRLF that text mode would produce on Windows breaks shebangs and RUN lines."""
    with open(path, "w", newline="\n") as f:
        f.write(text)
    if executable and not IS_WINDOWS:
        os.chmod(path, 0o755)


def write_docker_assets():
    docker_dir.mkdir(parents=True, exist_ok=True)

    # The CA that goes *into* containers. Prefer the Netskope-only chain; fall back to the
    # full bundle when the user reused a bundle built before this split existed.
    ca_source = netskope_ca_path
    if not (netskope_ca_path.exists() and netskope_ca_path.stat().st_size):
        ca_source = bundle_path
        print("  Warning: netskope-ca.crt not found — using the full bundle (includes Mozilla roots).")
        print("           Recreate the bundle to get a Netskope-only netskope-ca.crt.")
    shutil.copy2(ca_source, docker_dir / "netskope-ca.crt")

    write_asset(docker_dir / "Dockerfile.snippet", DOCKERFILE_SNIPPET)
    write_asset(docker_dir / "Dockerfile.example", DOCKERFILE_EXAMPLE)
    write_asset(docker_dir / "Dockerfile.build-arg", DOCKERFILE_BUILD_ARG)
    write_asset(docker_dir / "docker-compose.netskope.yml", DOCKER_COMPOSE)
    write_asset(docker_dir / "netskope.env", DOCKER_ENV)
    write_asset(docker_dir / "README.md", DOCKER_README)
    write_asset(docker_dir / "install-netskope-ca-in-container.sh", DOCKER_INJECTOR_SH, executable=True)
    write_asset(docker_dir / "trust-netskope-ca-in-docker-daemon.sh", DOCKER_DAEMON_SH, executable=True)
    if IS_WINDOWS:
        write_asset(docker_dir / "install-netskope-ca-in-container.ps1", DOCKER_INJECTOR_PS1)


def running_containers():
    """Names of running containers, or [] when the daemon is unreachable."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    return [n for n in out.stdout.splitlines() if n.strip()]


def install_ca_in_container(name, ca_file):
    def run(args):
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=120
        ).returncode == 0

    layout = next(
        ((d, u) for d, u in CONTAINER_TRUST_LAYOUTS if run(["exec", name, "test", "-d", d])),
        None,
    )
    if layout is not None:
        trust_dir, update_cmd = layout
        target = f"{trust_dir}/netskope-ca.crt"
        ok = (
            run(["cp", str(ca_file), f"{name}:{target}"])
            and run(["exec", name, "chmod", "644", target])
            and run(["exec", name, "sh", "-c", update_cmd])
        )
        print(f"  [ok]   {name}: Netskope CA installed ({trust_dir})" if ok
              else f"  [warn] {name}: failed to install the Netskope CA")
        return

    # Minimal images (most Alpine-based ones) ship the merged bundle but no anchors directory
    # and no update-ca-certificates. Appending to the bundle is what OpenSSL and cURL read.
    if not run(["exec", name, "test", "-f", CONTAINER_MERGED_BUNDLE]):
        print(f"  [skip] {name}: no CA trust store found (install the ca-certificates package)")
    elif run(["exec", name, "grep", "-qF", CONTAINER_CA_MARKER, CONTAINER_MERGED_BUNDLE]):
        print(f"  [ok]   {name}: Netskope CA already present in {CONTAINER_MERGED_BUNDLE}")
    elif run(["cp", str(ca_file), f"{name}:/tmp/netskope-ca.crt"]) and run([
        "exec", name, "sh", "-c",
        f"echo '' >> {CONTAINER_MERGED_BUNDLE}"
        f" && echo '{CONTAINER_CA_MARKER}' >> {CONTAINER_MERGED_BUNDLE}"
        f" && cat /tmp/netskope-ca.crt >> {CONTAINER_MERGED_BUNDLE}"
        f" && rm -f /tmp/netskope-ca.crt",
    ]):
        print(f"  [ok]   {name}: Netskope CA appended to {CONTAINER_MERGED_BUNDLE}")
    else:
        print(f"  [warn] {name}: failed to install the Netskope CA")



# --- Kubernetes -------------------------------------------------------------
# Pods use their image's trust store, and nodes pull images with their own containerd, so
# neither is reached by the host configuration above. Unlike the Docker assets these are
# opt-in: pass --k8s, or answer y at the prompt when kubectl is installed.
#
# <cert dir>/k8s/ gets a ConfigMap carrying the CA, an example Deployment that mounts it, an
# optional trust-manager Bundle and a README. The full bundle is ~220 KB, so the ConfigMap
# must not be applied client-side - see the comment at the top of configmap.yaml.

K8S_CONFIGMAP_HEAD = """\
# Netskope CA trust for Kubernetes workloads, generated by the ssl-configure scripts.
#
# Two keys, for two kinds of client:
#   @@BUNDLE@@
#       Netskope CA chain + Mozilla roots. For the variables that REPLACE a client's default
#       store (REQUESTS_CA_BUNDLE, SSL_CERT_FILE, CURL_CA_BUNDLE, ...).
#   netskope-ca.crt
#       Netskope CA chain only. For NODE_EXTRA_CA_CERTS, which ADDS to Node's built-in CAs.
#
# NOTE: the full bundle is about 220 KB. Client-side "kubectl apply" stores the whole object in
# the kubectl.kubernetes.io/last-applied-configuration annotation, which is limited to 262144
# bytes, so it fails for this ConfigMap. Use one of:
#   kubectl apply --server-side -f configmap.yaml
#   kubectl create -f configmap.yaml        (kubectl replace -f configmap.yaml to update)
apiVersion: v1
kind: ConfigMap
metadata:
  name: netskope-ca
  namespace: @@NAMESPACE@@
data:
"""

K8S_DEPLOYMENT = """\
# Example Deployment that trusts the Netskope CA through the "netskope-ca" ConfigMap
# (configmap.yaml). Apply the ConfigMap first, then adapt this to your own workload.
#
# The ConfigMap is mounted read-only at /etc/netskope. Do not mount it over /etc/ssl/certs, and
# do not use subPath: subPath mounts never pick up ConfigMap updates.
#
# Java does not read any of these variables and needs its own truststore. .NET on Linux reads
# only SSL_CERT_FILE and SSL_CERT_DIR. Other runtimes may need their own setup.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netskope-ca-example
  namespace: @@NAMESPACE@@
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netskope-ca-example
  template:
    metadata:
      labels:
        app: netskope-ca-example
    spec:
      containers:
        - name: app
          image: ubuntu:24.04 # replace with your own image
          command: ["sleep", "infinity"]
          env:
            # Adds to Node's built-in CAs, so the Netskope chain alone is enough.
            - name: NODE_EXTRA_CA_CERTS
              value: /etc/netskope/netskope-ca.crt
            # These REPLACE the default store, so they must point at the full bundle, which
            # includes the Mozilla roots.
            - name: REQUESTS_CA_BUNDLE
              value: /etc/netskope/@@BUNDLE@@
            - name: PIP_CERT
              value: /etc/netskope/@@BUNDLE@@
            - name: SSL_CERT_FILE
              value: /etc/netskope/@@BUNDLE@@
            - name: CURL_CA_BUNDLE
              value: /etc/netskope/@@BUNDLE@@
            - name: GIT_SSL_CAINFO
              value: /etc/netskope/@@BUNDLE@@
            - name: CARGO_HTTP_CAINFO
              value: /etc/netskope/@@BUNDLE@@
            - name: AWS_CA_BUNDLE
              value: /etc/netskope/@@BUNDLE@@
          volumeMounts:
            - name: netskope-ca
              mountPath: /etc/netskope
              readOnly: true
      volumes:
        - name: netskope-ca
          configMap:
            name: netskope-ca
"""

K8S_TRUST_MANAGER_HEAD = """\
# Optional: only for clusters that run cert-manager's trust-manager
# (https://cert-manager.io/docs/trust/trust-manager/). Use this INSTEAD of configmap.yaml, not
# alongside it: both produce a ConfigMap named "netskope-ca".
#
# trust-manager reads the source ConfigMap below (it must live in trust-manager's trust
# namespace, "cert-manager" by default) and writes one merged bundle, the default public CAs
# plus the Netskope chain, into a ConfigMap named "netskope-ca" in every namespace labelled
# netskope-ca=enabled:
#   kubectl label namespace @@NAMESPACE@@ netskope-ca=enabled
#
# With this route the merged bundle already contains the Netskope chain, so EVERY variable in
# deployment-example.yaml, including NODE_EXTRA_CA_CERTS, points at /etc/netskope/ca-bundle.pem.
#
# useDefaultCAs needs trust-manager's default CA package to be enabled. Unlike configmap.yaml
# this file is small, so plain "kubectl apply -f trust-manager-bundle.yaml" works.
apiVersion: v1
kind: ConfigMap
metadata:
  name: netskope-ca-source
  namespace: cert-manager
data:
"""

K8S_TRUST_MANAGER_TAIL = """\
---
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: netskope-ca
spec:
  sources:
    - useDefaultCAs: true
    - configMap:
        name: netskope-ca-source
        key: netskope-ca.crt
  target:
    configMap:
      key: ca-bundle.pem
    namespaceSelector:
      matchLabels:
        netskope-ca: enabled
"""

K8S_README = """\
# Netskope certificates for Kubernetes

Pods use the trust store of their own image, so the host configuration does not reach them.
There is no Netskope Client on cluster nodes either, which is why these files carry the CA
instead. Pick whichever of these matches how the cluster is run:

| File | Use |
| --- | --- |
| `configmap.yaml` | ConfigMap `netskope-ca` holding the full bundle and the Netskope-only chain |
| `deployment-example.yaml` | Example Deployment that mounts the ConfigMap and points the CA variables at it |
| `trust-manager-bundle.yaml` | Optional: the same result through cert-manager's trust-manager |
| `trust-netskope-ca-on-node.sh` | Make the node's containerd trust the CA (image pulls) |
| `netskope-ca.crt` | The Netskope CA chain only - used by the node script |

To rebuild these files from the existing bundle without any prompts, run `regenerate.sh` in
this directory if there is one (macOS / Linux / Python), or `configured_tools.ps1 -K8s` on
Windows PowerShell.

## Two separate problems

Pod trust and node trust fail independently, and fixing one does not fix the other:

- **The pods** need the CA in the trust store, or the CA variables, of the workload itself.
  That is what `configmap.yaml` and `deployment-example.yaml` provide. A pod without it fails
  its own HTTPS calls.
- **The nodes** pull images with the node's containerd, which does its own TLS to the
  registry. A node without the CA leaves pods in `ErrImagePull` / `ImagePullBackOff` with
  `x509: certificate signed by unknown authority` before any container exists.
  `trust-netskope-ca-on-node.sh` (Linux, needs `sudo`) fixes this two ways: with no
  arguments it installs into the node's OS trust store, which covers every registry but
  restarts containerd; given registry names it writes
  `/etc/containerd/certs.d/<registry>/hosts.toml`, which takes effect on the next pull with
  no restart but only for those registries, and only if containerd's `config_path` points at
  that directory. On EKS, GKE and AKS a manual run is lost when nodes are replaced, so put
  it in node bootstrap or a privileged DaemonSet instead. k3s and RKE2 embed their own
  containerd: restart the k3s / rke2 service rather than `containerd`.

## Pods

- **Baking beats mounting.** Putting the CA into the image (see `Dockerfile.snippet` in the
  `docker/` directory) works wherever the image runs and needs no per-workload wiring.
  Mount the ConfigMap for images you cannot rebuild.
- **Apply the ConfigMap with `kubectl apply --server-side -f configmap.yaml` or
  `kubectl create -f configmap.yaml`.** The full bundle is about 220 KB, and client-side
  `kubectl apply` copies the whole object into the `last-applied-configuration` annotation,
  which is limited to 262144 bytes.
- **Mount it read-only at `/etc/netskope`.** Do not mount over `/etc/ssl/certs`, and do not
  use `subPath`: subPath mounts never pick up ConfigMap updates.
- **Pick the right file for each variable.** `NODE_EXTRA_CA_CERTS` adds to Node's built-in
  CAs, so it takes `netskope-ca.crt`. `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`,
  `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO` and `AWS_CA_BUNDLE` replace the
  default store, so they must point at the full bundle, which includes the Mozilla roots.
- **Java and .NET.** Java reads none of these variables and needs a truststore of its own.
  .NET on Linux reads only `SSL_CERT_FILE` and `SSL_CERT_DIR`.

## trust-manager

If the cluster already runs cert-manager's trust-manager, `trust-manager-bundle.yaml` lets it
build the merged bundle (default public CAs plus the Netskope chain) and publish it as a
ConfigMap in every namespace labelled `netskope-ca=enabled`. Use it instead of
`configmap.yaml`. The merged bundle already contains the Netskope chain, so every variable,
including `NODE_EXTRA_CA_CERTS`, points at `/etc/netskope/ca-bundle.pem`.

## Rotating the CA

1. Re-run the script to rebuild the bundle.
2. Re-apply the ConfigMap: `kubectl apply --server-side -f configmap.yaml` (with
   trust-manager, re-apply `trust-manager-bundle.yaml`).
3. Restart the workloads: `kubectl rollout restart deployment/<name> -n <namespace>`. Most
   applications read their CAs once at startup, so a changed file is not enough.
4. On nodes that trust the CA, re-run `trust-netskope-ca-on-node.sh`.

## Verify

```
kubectl exec -n <namespace> deploy/netskope-ca-example -- sh -c 'ls -l /etc/netskope; env | grep -E "CA|CERT"'
```
"""

K8S_REGENERATE_SH = """\
#!/bin/sh
## Rebuilds the files in this directory from the existing bundle, without prompting for the
## tenant or API token (@@SCRIPT@@ --non-interactive). That also re-applies the
## tool configuration, which is idempotent. Extra options are passed through, e.g.
##   ./regenerate.sh --k8s-namespace other-namespace
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent=$(dirname -- "$here")
script="$parent/@@SCRIPT@@"
[ -f "$script" ] || { echo "Error: $script not found - keep this directory next to the bundle" >&2; exit 1; }
exec python3 "$script" --k8s --non-interactive --cert-dir "$parent" --cert-name '@@BUNDLE@@' --k8s-namespace '@@NAMESPACE@@' "$@"
"""

K8S_REGENERATE_BAT = """\
@echo off
:: Rebuilds the files in this directory from the existing bundle, without prompting for the
:: tenant or API token (@@SCRIPT@@ --non-interactive). That also re-applies the
:: tool configuration, which is idempotent. Extra options are passed through, e.g.
::   regenerate.bat --k8s-namespace other-namespace
setlocal
for %%I in ("%~dp0..") do set "PARENT=%%~fI"
set "SCRIPT=%PARENT%\\@@SCRIPT@@"
if not exist "%SCRIPT%" echo Error: %SCRIPT% not found - keep this directory next to the bundle & exit /b 1
"@@PYTHON@@" "%SCRIPT%" --k8s --non-interactive --cert-dir "%PARENT%" --cert-name "@@BUNDLE@@" --k8s-namespace "@@NAMESPACE@@" %*
exit /b %ERRORLEVEL%
"""


def k8s_render(template):
    """Fill in the namespace and bundle name of a template."""
    return template.replace("@@NAMESPACE@@", k8s_namespace).replace("@@BUNDLE@@", bundle_path.name)


def k8s_yaml_block(path):
    """Indent a PEM file for embedding as a YAML block scalar: CRs dropped, trailing blank
    lines dropped, four-space indent, empty lines left empty."""
    lines = path.read_bytes().decode("ascii").replace("\r", "").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    return "".join(("    " + line if line else "") + "\n" for line in lines)


def write_k8s_assets():
    """Write <cert dir>/k8s/. Returns False when the assets had to be skipped."""
    name = bundle_path.name
    # The bundle name becomes a ConfigMap key and appears in file paths inside pods.
    if not re.fullmatch(r"[-._a-zA-Z0-9]+", name) or name == "netskope-ca.crt":
        print(f"  Warning: bundle name '{name}' cannot be used as a ConfigMap key (letters, digits, "
              "'-', '_' and '.' only, and not netskope-ca.crt) - skipping Kubernetes assets")
        return False

    # The CA that goes *into* the cluster. Prefer the Netskope-only chain; fall back to the full
    # bundle when the user reused a bundle built before this split existed.
    ca_source = netskope_ca_path
    if not (netskope_ca_path.exists() and netskope_ca_path.stat().st_size):
        ca_source = bundle_path
        print("  Warning: netskope-ca.crt not found — using the full bundle (includes Mozilla roots).")
        print("           Recreate the bundle to get a Netskope-only netskope-ca.crt.")
    # These assets promise ASCII, so refuse anything but printable ASCII and whitespace.
    for source in (bundle_path, ca_source):
        if re.search(rb"[^\x09-\x0d\x20-\x7e]", source.read_bytes()):
            print(f"  Warning: {source} contains non-ASCII bytes - skipping Kubernetes assets")
            return False

    k8s_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ca_source, k8s_dir / "netskope-ca.crt")

    # A ConfigMap is limited to 1 MiB (the two keys together).
    total = bundle_path.stat().st_size + (k8s_dir / "netskope-ca.crt").stat().st_size
    if total > 1000000:
        print(f"  Warning: the ConfigMap data is {total} bytes; Kubernetes rejects ConfigMaps over 1 MiB")

    ca_block = k8s_yaml_block(k8s_dir / "netskope-ca.crt")
    write_asset(k8s_dir / "configmap.yaml",
                k8s_render(K8S_CONFIGMAP_HEAD) + f"  {name}: |\n" + k8s_yaml_block(bundle_path)
                + "  netskope-ca.crt: |\n" + ca_block)
    write_asset(k8s_dir / "deployment-example.yaml", k8s_render(K8S_DEPLOYMENT))
    write_asset(k8s_dir / "trust-manager-bundle.yaml",
                k8s_render(K8S_TRUST_MANAGER_HEAD) + "  netskope-ca.crt: |\n" + ca_block
                + k8s_render(K8S_TRUST_MANAGER_TAIL))
    write_asset(k8s_dir / "README.md", k8s_render(K8S_README))

    # Rebuilding later without prompts (for example after the CA rotates): copy this script next
    # to the bundle and write a wrapper that runs it with --non-interactive.
    script = globals().get("__file__")
    if not script:
        print("  Warning: could not locate this script to copy next to the bundle - "
              "regenerate script not written")
        return True
    script = Path(script).resolve()
    script_copy = bundle_path.parent / script.name
    if not (script_copy.exists() and script_copy.samefile(script)):
        shutil.copy2(script, script_copy)
    if IS_WINDOWS:
        wrapper = K8S_REGENERATE_BAT.replace("@@SCRIPT@@", script.name).replace("@@PYTHON@@", sys.executable)
        # A .bat is read by cmd.exe, so unlike the other assets it gets CRLF endings.
        with open(k8s_dir / "regenerate.bat", "w", newline="\r\n") as f:
            f.write(k8s_render(wrapper))
    else:
        write_asset(k8s_dir / "regenerate.sh",
                    k8s_render(K8S_REGENERATE_SH.replace("@@SCRIPT@@", script.name)), executable=True)
    return True


# --- Claude Desktop ---
def strip_jsonc(s):
    """Strip // and /* */ comments from JSONC, ignoring text inside string literals.
    A naive regex (//.*?$) corrupts strings like "https://example.com"."""
    out = []
    i, n = 0, len(s)
    in_string = False
    while i < n:
        c = s[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif c == "/" and i + 1 < n and s[i + 1] == "/":
            while i < n and s[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and s[i + 1] == "*":
            i += 2
            while i + 1 < n and not (s[i] == "*" and s[i + 1] == "/"):
                i += 1
            i += 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))


def patch_vscode_settings(path, env_key):
    """Set env_key -> NODE_EXTRA_CA_CERTS in a VS Code settings.json (JSONC).
    Returns (status, had_comments) where status is 'already' or 'configured'.
    had_comments flags that the rewrite (json.dump) dropped JSONC comments."""
    content = path.read_text() or "{}"
    # Comment detection is for a user-facing warning only — the write below cannot preserve
    # JSONC comments. Mirror the PowerShell heuristic: a line-comment at line start or a block
    # comment anywhere. Strings containing "//" (e.g. URLs) won't match the line-start anchor.
    had_comments = bool(re.search(r"(?m)^\s*//", content)) or "/*" in content
    data = json.loads(strip_jsonc(content) or "{}")
    if data.get(env_key, {}).get("NODE_EXTRA_CA_CERTS") == str(bundle_path):
        return "already", had_comments
    data.setdefault(env_key, {})["NODE_EXTRA_CA_CERTS"] = str(bundle_path)
    path.write_text(json.dumps(data, indent=2))
    return "configured", had_comments


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
        result, had_comments = patch_vscode_settings(settings_file, env_key=VSCODE_ENV_KEY)
        if result == "already":
            print(f"{name}: already configured")
        else:
            print(f"{name} configured with NODE_EXTRA_CA_CERTS in terminal environment")
            if had_comments:
                print(f"  Note: comments in {name} settings.json were not preserved on rewrite.")
    except Exception as e:
        shutil.copy2(backup, settings_file)
        print(f"Warning: Failed to configure {name}: {e}")
    finally:
        try:
            backup.unlink()
        except OSError:
            pass
    print(f"Note: Please restart {name} for changes to take effect")


def valid_k8s_namespace(name):
    """A Kubernetes DNS-1123 label. The namespace ends up in YAML, so hold it to one."""
    return len(name) <= 63 and re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", name) is not None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Configure CLI tools and apps to trust a Netskope SSL-inspection CA bundle. "
                    "With no options the script asks for everything it needs.",
        allow_abbrev=False,
    )
    parser.add_argument("--k8s", action="store_true",
                        help="also write Kubernetes CA assets to <cert dir>/k8s/")
    parser.add_argument("--k8s-namespace", metavar="NAME", default=None,
                        help="namespace used in the Kubernetes manifests (default: default)")
    parser.add_argument("--cert-dir", metavar="DIR", help="bundle directory (skips that prompt)")
    parser.add_argument("--cert-name", metavar="NAME", help="bundle filename (skips that prompt)")
    parser.add_argument("--non-interactive", action="store_true",
                        help="never prompt: reuse the existing bundle in --cert-dir/--cert-name, so "
                             "no tenant name or API token is needed. The tool configuration is "
                             "re-applied (it is idempotent) and the existing configured_tools "
                             "script is left as it is. Fails if the bundle does not exist yet.")
    args = parser.parse_args()
    args.k8s_namespace_set = args.k8s_namespace is not None
    if not args.k8s_namespace_set:
        args.k8s_namespace = "default"
    elif not valid_k8s_namespace(args.k8s_namespace):
        parser.error(f"invalid --k8s-namespace {args.k8s_namespace!r} "
                     "(lowercase letters, digits and '-', at most 63 characters)")
    return args


def main():
    global NETSKOPE_CERT_API, SHELL_CONFIG, bundle_path, configured_tools_file, netskope_ca_path
    global docker_dir, k8s_dir, k8s_namespace, use_local_certs, api_token

    args = parse_args()
    SHELL_CONFIG = detect_shell_config()  # prints which shell was detected, so not at import time

    # --- Interactive prompts ---

    # --non-interactive reuses an existing bundle instead of building one, so there is nothing
    # to fetch and no tenant is needed.
    tenant_name = ""
    if not args.non_interactive:
        tenant_name = input(
            "Please provide full Netskope tenant name (ex: tenant-name.goskope.com): "
        ).strip()
        if not tenant_name:
            die("Tenant name cannot be empty")
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", tenant_name):
            die("Invalid tenant name format")

    NETSKOPE_CERT_API = f"https://{tenant_name}{NETSKOPE_CERT_API_PATH}"

    # --cert-name / --cert-dir (and --non-interactive) replace the matching prompt
    if args.cert_name or args.non_interactive:
        cert_name = args.cert_name or "netskope-cert-bundle.pem"
    else:
        cert_name = prompt("Please provide certificate bundle name", "netskope-cert-bundle.pem")
    default_dir = r"C:\netskope" if IS_WINDOWS else "~/netskope"
    if args.cert_dir or args.non_interactive:
        cert_dir = Path(os.path.expanduser(args.cert_dir or default_dir))
    else:
        cert_dir = Path(os.path.expanduser(prompt("Please provide certificate bundle location", default_dir)))
    if args.non_interactive and not (cert_dir / cert_name).exists():
        die(f"--non-interactive reuses an existing bundle, but {cert_dir / cert_name} does not exist\n"
            "       Run the script once interactively to build it.")
    cert_dir.mkdir(parents=True, exist_ok=True)

    bundle_path = cert_dir / cert_name
    configured_tools_file = cert_dir / ("configured_tools.bat" if IS_WINDOWS else "configured_tools.sh")

    # Netskope-only certs, split out of the full bundle. Container trust stores already ship the
    # Mozilla roots, so what they need is just the Netskope CA chain — and OS trust-store tools
    # (update-ca-certificates / update-ca-trust) only pick up files with a .crt extension.
    netskope_ca_path = cert_dir / "netskope-ca.crt"
    docker_dir = cert_dir / "docker"
    k8s_dir = cert_dir / "k8s"

    # --- Local client cert detection ---
    use_local_certs = False
    if NS_CA_CERT and NS_CA_CERT.exists() and NS_TENANT_CERT.exists() and not args.non_interactive:
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
    if not use_local_certs and not args.non_interactive:
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

    if bundle_path.exists():
        print(f"{cert_name} already exists in {cert_dir}.")
        if not args.non_interactive and input("Recreate Certificate Bundle? (y/N) ").strip().lower() == "y":
            build_bundle()
    else:
        build_bundle()

    # --- Silent-deployment script initialization ---
    replay_file = configured_tools_file
    if args.non_interactive and replay_file.exists():
        # A replay re-applies the configuration but must not rewrite the replay script: re-runs
        # skip exports that are already set in the current shell, so a fresh file would lose
        # those lines. Record into a scratch file instead and leave the existing script as it is.
        scratch = tempfile.NamedTemporaryFile(prefix="configured_tools_", delete=False)
        scratch.close()
        atexit.register(os.unlink, scratch.name)
        configured_tools_file = Path(scratch.name)
    if IS_WINDOWS:
        configured_tools_file.write_text(
            "@echo off\n:: Silent deployment for configured tools\n"
        )
    else:
        configured_tools_file.write_text(
            "#!/bin/bash\n# Silent deployment for configured tools — source this file to apply exports.\n"
        )
        os.chmod(configured_tools_file, 0o755)

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

    # Netskope CLI (ntsk) — set ALL of these. Empirically, ntsk hits raw ssl/urllib
    # code paths that only honor SSL_CERT_FILE, even though its docs imply
    # NETSKOPE_CA_BUNDLE is enough. On a host without openssl/curl/python on PATH,
    # none of those vars get set elsewhere and ntsk fails with TLS errors.
    print()
    if not command_exists("ntsk"):
        print("Netskope CLI is not installed")
    else:
        print("Netskope CLI is installed")
        cert_path = str(bundle_path)
        for v in ("NETSKOPE_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            if os.environ.get(v) == cert_path:
                print(f"  {v} already set in current shell")
            else:
                set_env_var(v, cert_path)
                print(f"  {v} configured")

    print()
    if not command_exists("docker"):
        print("Docker is not installed")
    else:
        print("Docker is installed")
        write_docker_assets()
        print(f"Docker build assets written: {docker_dir}")

        containers = running_containers()
        if not containers:
            print("No running containers to patch (or the Docker daemon is not reachable)")
        elif args.non_interactive:
            print("Running containers left unchanged (non-interactive)")
        else:
            print("Running containers:")
            for c in containers:
                print(f"  {c}")
            if input("Install the Netskope CA into these running containers now? (y/N) ").strip().lower() == "y":
                for c in containers:
                    install_ca_in_container(c, docker_dir / "netskope-ca.crt")
                print("Note: container changes are lost on recreate — bake the CA in via Dockerfile.snippet")
            else:
                print("Running containers left unchanged")

        injector = "install-netskope-ca-in-container.ps1" if IS_WINDOWS else "install-netskope-ca-in-container.sh"
        comment = "::" if IS_WINDOWS else "#"
        append_tools_file(f"{comment} Netskope Docker assets: {docker_dir} (see its README.md)")
        append_tools_file(f"{comment} Patch running containers: {docker_dir / injector}")

    # --- Kubernetes ---
    k8s_failed = False
    k8s_namespace = args.k8s_namespace
    # Say nothing unless Kubernetes was asked for or kubectl suggests the offer, so a run
    # without --k8s on a machine without kubectl prints exactly what it always did.
    if args.k8s or command_exists("kubectl"):
        print()
        if not args.k8s and not args.non_interactive:
            print("kubectl is installed")
            if input(f"Generate Kubernetes CA assets in {k8s_dir}? (y/N) ").strip().lower() == "y":
                args.k8s = True
                if not args.k8s_namespace_set:
                    k8s_namespace = prompt("Kubernetes namespace", k8s_namespace)
                    if not valid_k8s_namespace(k8s_namespace):
                        die(f"invalid namespace {k8s_namespace!r} (lowercase letters, digits and '-', "
                            "at most 63 characters)")
        if args.k8s:
            if write_k8s_assets():
                print(f"Kubernetes assets written: {k8s_dir} (namespace: {k8s_namespace})")
            else:
                k8s_failed = True
        else:
            print("Kubernetes assets not generated (pass --k8s to generate them)")


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

    # Detect-only: `env` at the top level of claude_desktop_config.json is not a recognized
    # field (per-server env lives under mcpServers.<name>.env). Claude Desktop is Electron
    # and reads NODE_EXTRA_CA_CERTS from the user environment at launch — covered by setx
    # on Windows and by shell-rc exports for terminal-launched apps elsewhere.
    if claude_installed:
        print("Claude Desktop is installed")
        if IS_MAC:
            print("Note: macOS GUI apps do not inherit shell env vars. If needed, run:")
            print(f'      launchctl setenv NODE_EXTRA_CA_CERTS "{bundle_path}"')
        print("      then restart Claude Desktop.")
    else:
        print("Claude Desktop is not installed")

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
        print(f'For silent deployment on other machines, run: "{replay_file}"')
    else:
        print(f"For silent deployment on other machines, run: source {replay_file}")

    if k8s_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
