# ssl-configure-scripts

Cross-platform scripts that detect popular CLI tools, libraries, and desktop apps and point them at a Netskope SSL-inspection certificate bundle.

> **Origin:** Based on [duduke/ssl-configure-scripts](https://github.com/duduke/ssl-configure-scripts). This fork adds coverage for additional dev tools and switches certificate retrieval to work with **Netskope Secure Enrollment** (tenant API + local STAgent certs) instead of the legacy org-key flow.

> **Disclaimer:** These scripts are based on publicly available Netskope and individual CLI/tool vendor documentation. They are **not** an official Netskope product and are **not supported by Netskope**. Use at your own risk.

Each script:

1. Builds a CA bundle at `<certDir>/<certName>` containing the Netskope tenant CA + the Mozilla root bundle (from `curl.se`).
2. Detects which supported tools are installed.
3. For each tool, sets the appropriate env var or runs the tool's config command.
4. Writes a replay script (`configured_tools.sh` / `configured_tools.bat`) alongside the bundle for silent deployment to other machines.

## Scripts

| Platform | Script | Cert source |
| --- | --- | --- |
| macOS | [configure_tools_mac.sh](configure_tools_mac.sh) | Netskope API (Bearer token) or local STAgent certs |
| Linux | [configure_tools_linux.sh](configure_tools_linux.sh) | Netskope API (Bearer token) or local STAgent certs |
| Windows | [configure_tools_windows.cmd](configure_tools_windows.cmd) | Netskope API (Bearer token) or local STAgent certs |
| Any (Python) | [universal_configure_tools.py](universal_configure_tools.py) | Netskope API (Bearer token) or local STAgent certs |

If the Netskope client is installed locally, the script will offer to use `nscacert.pem` / `nstenantcert.pem` directly instead of calling the API. Otherwise you need a tenant **Bearer token** with permission to read `/api/v2/services/certs/subordinates`.

## Prerequisites

- `python3` on PATH (used to parse the API response and edit JSON configs)
- `curl` and `openssl`
- Windows: PowerShell (ships with Windows 10+) — used to read the token without echoing it

## Usage

### macOS

```bash
chmod +x configure_tools_mac.sh
./configure_tools_mac.sh
```

### Linux

```bash
chmod +x configure_tools_linux.sh
./configure_tools_linux.sh
```

### Windows

```cmd
configure_tools_windows.cmd
```

### Prompts

Each script asks for:

- **Tenant name** — e.g. `tenant-name.goskope.com`
- **Bundle filename** — default `netskope-cert-bundle.pem`
- **Bundle directory** — default `~/netskope` (Unix) or `C:\netskope` (Windows)
- **API Bearer token** — skipped if a local Netskope STAgent install is detected and accepted, or if `NETSKOPE_API_TOKEN` is set in the environment

### Silent re-deployment

Each run emits a replay script next to the bundle:

- **macOS / Linux**: `source <certDir>/configured_tools.sh` — must be sourced so `export` lines persist.
- **Windows**: run `<certDir>\configured_tools.bat` — executes `setx` and tool-config commands.

Copy the bundle and the replay script to another machine to reproduce the same configuration without re-prompting.

## Tools configured

Where a tool honors an environment variable, the script exports it in the user's shell config (`~/.bash_profile`, `~/.bashrc`, `~/.zshenv`) or via `setx` on Windows. Where the tool has a native config command, the script runs it directly.

| Tool | How it's configured |
| --- | --- |
| Git | `git config --global http.sslCAInfo` (Windows) / `GIT_SSL_CAINFO` env var (Unix) |
| OpenSSL | `SSL_CERT_FILE` env var |
| cURL | `CURL_CA_BUNDLE` env var |
| Python Requests / Azure CLI | `REQUESTS_CA_BUNDLE` env var |
| Python pip | `PIP_CERT` env var |
| AWS CLI | `AWS_CA_BUNDLE` env var |
| Google Cloud CLI | `gcloud config set core/custom_ca_certs_file` |
| Node.js | `NODE_EXTRA_CA_CERTS` env var |
| npm | `npm config set cafile` |
| Yarn | `yarn config set httpsCaFilePath` |
| Claude CLI | `NODE_EXTRA_CA_CERTS` env var |
| Netskope CLI (`ntsk` / `netskope`) | `NETSKOPE_CA_BUNDLE` env var |
| Ruby | `SSL_CERT_FILE` env var |
| PHP Composer | `composer config --global cafile` |
| Oracle Cloud CLI | `OCI_CLI_CA_BUNDLE` env var |
| Cargo (Rust) | `CARGO_HTTP_CAINFO` env var |
| Azure Storage Explorer | Copies bundle into the app's `certs/` directory |
| Claude Desktop | Adds `NODE_EXTRA_CA_CERTS` to `claude_desktop_config.json` (`env` key) |
| VS Code / VS Code Insiders / Cursor | Adds `NODE_EXTRA_CA_CERTS` to `terminal.integrated.env.*` in `settings.json` |

Note: Go (`crypto/x509`) picks up `SSL_CERT_FILE` automatically — it's already set by the OpenSSL entry, so there's no separate Go step.

## Notes

- **New shells only** — `setx` (Windows) and shell-config exports take effect in new terminal sessions, not the one that ran the script.
- **Restart GUI apps** — Claude Desktop, VS Code variants, and Azure Storage Explorer need to be restarted after configuration.
- **Backup on edit** — JSON configs (Claude Desktop, VS Code) are backed up to `<file>.backup` during the edit and restored automatically if the script's Python patch fails.
- **`REQUESTS_CA_BUNDLE` is shared** — Python Requests and Azure CLI both read it, so setting it once configures both.

### Python (any platform)

```bash
python3 universal_configure_tools.py
```

Stdlib only — no `pip install` needed.

## Other files

- [check_ssl.js](check_ssl.js) — quick Node.js probe for verifying a TLS endpoint after configuration.
