# ssl-configure-scripts

Cross-platform scripts that detect popular CLI tools, libraries, and desktop apps and point them at a Netskope SSL-inspection certificate bundle.

> **Origin:** Based on [duduke/ssl-configure-scripts](https://github.com/duduke/ssl-configure-scripts). This fork adds coverage for additional dev tools and switches certificate retrieval to work with **Netskope Secure Enrollment** (tenant API + local STAgent certs) instead of the legacy org-key flow.

> **Disclaimer:** These scripts are based on publicly available Netskope and individual CLI/tool vendor documentation. They are **not** an official Netskope product and are **not supported by Netskope**. Use at your own risk.

Each script:

1. Builds a CA bundle at `<certDir>/<certName>` containing the Netskope tenant CA + the Mozilla root bundle (from `curl.se`), plus `<certDir>/netskope-ca.crt` holding just the Netskope chain.
2. Detects which supported tools are installed.
3. For each tool, sets the appropriate env var or runs the tool's config command.
4. If Docker is present, writes ready-to-use container assets to `<certDir>/docker/` (see [Docker](#docker)).
5. With `--k8s` (or when you accept the offer because `kubectl` is present), writes Kubernetes assets to `<certDir>/k8s/` (see [Kubernetes](#kubernetes)).
6. Writes a replay script (`configured_tools.sh` / `configured_tools.bat`) alongside the bundle for silent deployment to other machines.

## Scripts

| Platform | Script | Cert source |
| --- | --- | --- |
| macOS / Linux | [configure_tools_unix.sh](configure_tools_unix.sh) | Netskope API (Bearer token) or local STAgent certs |
| Windows | [configure_tools_windows.cmd](configure_tools_windows.cmd) (launcher) + [configure_tools_windows.ps1](configure_tools_windows.ps1) | Netskope API (Bearer token) or local STAgent certs |
| Any (Python) | [universal_configure_tools.py](universal_configure_tools.py) | Netskope API (Bearer token) or local STAgent certs |

`configure_tools_unix.sh` auto-detects macOS vs Linux (via `uname`) and adjusts the shell rc file, STAgent cert path, and app config locations accordingly — it replaces the former separate `configure_tools_mac.sh` / `configure_tools_linux.sh`.

If the Netskope client is installed locally, the script will offer to use `nscacert.pem` / `nstenantcert.pem` directly instead of calling the API. Otherwise you need a tenant **Bearer token** with permission to read `/api/v2/services/certs/subordinates`.

## Prerequisites

- **macOS / Linux**: `python3`, `curl`, and `openssl` on PATH
- **Windows**: PowerShell 5.1 (ships with Windows 10+) or PowerShell 7+ (`pwsh`). The Windows path is implemented entirely in PowerShell — no `python3` or `curl` required. The `.cmd` file is a thin launcher that forwards to `configure_tools_windows.ps1`.

## Usage

### macOS / Linux

```bash
chmod +x configure_tools_unix.sh
./configure_tools_unix.sh
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

### Options

| macOS / Linux / Python | Windows | Effect |
| --- | --- | --- |
| `--k8s` | `-K8s` | Also write Kubernetes assets to `<certDir>/k8s/` (see [Kubernetes](#kubernetes)) |
| `--k8s-namespace NAME` | `-K8sNamespace NAME` | Namespace used in the Kubernetes manifests (default `default`) |
| `--cert-dir DIR` | `-CertDir DIR` | Bundle directory — skips that prompt |
| `--cert-name NAME` | `-CertName NAME` | Bundle filename — skips that prompt |
| `--non-interactive` | `-NonInteractive` | Never prompt. Reuses the existing bundle (no tenant name or API token needed) and fails if there is none |

With no options every script asks the same questions as before; the one addition is the Kubernetes offer (default: no) when `kubectl` is on PATH. `--non-interactive` re-applies the whole tool configuration (it is idempotent), not just the Kubernetes assets, and leaves running containers unpatched. The macOS / Linux and Python scripts also leave an existing `configured_tools.sh` / `.bat` untouched in this mode.

### Silent re-deployment

Each run emits a replay script next to the bundle:

- **macOS / Linux**: `source <certDir>/configured_tools.sh` — must be sourced so `export` lines persist.
- **Windows**: run `<certDir>\configured_tools.ps1` — re-invokes `configure_tools_windows.ps1` with `-NonInteractive` against the existing bundle (no tenant prompt, no API token required). The main `.ps1` is copied next to the bundle so the deploy folder is self-contained; copy the bundle, `configure_tools_windows.ps1`, and `configured_tools.ps1` to another machine and run the replay script.

Copy the bundle and the replay script to another machine to reproduce the same configuration without re-prompting.

To rebuild the Kubernetes assets from an existing bundle without prompts, run `<certDir>/k8s/regenerate.sh` (macOS / Linux / Python; `regenerate.bat` for Python on Windows) or, on Windows PowerShell, `<certDir>\configured_tools.ps1 -K8s`. These re-run the script with `--non-interactive`, so the tool configuration is re-applied too.

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
| Netskope CLI (`ntsk` / `netskope`) | `NETSKOPE_CA_BUNDLE` + `SSL_CERT_FILE` + `REQUESTS_CA_BUNDLE` + `CURL_CA_BUNDLE` env vars (ntsk hits raw ssl/urllib paths, so all four are needed when openssl/curl/python aren't on PATH) |
| Ruby | `SSL_CERT_FILE` env var |
| PHP Composer | `composer config --global cafile` |
| Oracle Cloud CLI | `OCI_CLI_CA_BUNDLE` env var |
| Cargo (Rust) | `CARGO_HTTP_CAINFO` env var |
| Azure Storage Explorer | Copies bundle into the app's `certs/` directory |
| Claude Desktop | Detect-only — Electron reads `NODE_EXTRA_CA_CERTS` from the user environment at launch (set by `setx` on Windows; macOS GUI apps may need `launchctl setenv`) |
| VS Code / VS Code Insiders / Cursor | Adds `NODE_EXTRA_CA_CERTS` to `terminal.integrated.env.*` in `settings.json` |
| Docker | Generates container CA assets in `<certDir>/docker/` and can patch running containers (see [Docker](#docker)) |
| Kubernetes | Opt-in (`--k8s`): generates a ConfigMap, example Deployment, trust-manager Bundle and a containerd trust script in `<certDir>/k8s/` (see [Kubernetes](#kubernetes)) |

Note: Go (`crypto/x509`) picks up `SSL_CERT_FILE` automatically — it's already set by the OpenSSL entry, so there's no separate Go step.

## Docker

Containers ship their own trust store, so none of the host configuration above reaches them — a container behind SSL inspection fails every HTTPS call until the Netskope CA is installed *inside* it. When `docker` is on PATH, each script writes a self-contained `<certDir>/docker/` directory:

| File | Use |
| --- | --- |
| `netskope-ca.crt` | The Netskope CA chain only (no Mozilla roots) — must be in the build context |
| `Dockerfile.snippet` | Lines to paste into an existing Dockerfile |
| `Dockerfile.example` | Standalone Debian/Ubuntu image that trusts the CA |
| `Dockerfile.build-arg` | Installs the CA only when built with `--build-arg BUILD_ENV=development` |
| `docker-compose.netskope.yml` + `netskope.env` | Compose wiring for the build-arg variant |
| `install-netskope-ca-in-container.sh` / `.ps1` | Patches containers that are already running |
| `trust-netskope-ca-in-docker-daemon.sh` | Makes the Docker **daemon** trust the CA (pulls, pushes, builds) |
| `README.md` | The same guidance, next to the files |

The script also offers to run the injector against the containers running at that moment.

### Two separate problems

The daemon and the containers fail independently, and fixing one does not fix the other:

- **The daemon** does its own TLS to the registry, so `docker pull` can fail with `x509: certificate signed by unknown authority` before any container exists. `trust-netskope-ca-in-docker-daemon.sh` (Linux, needs `sudo`) fixes this two ways: with no arguments it installs into the host OS trust store, which covers every registry including Docker Hub but needs a daemon restart; given registry names it writes `/etc/docker/certs.d/<registry>/ca.crt`, which takes effect on the next pull with no restart but only for those registries. Docker Desktop on macOS/Windows uses neither path — add the CA to the host keychain or Windows certificate store and restart Docker Desktop.
- **The containers** need the CA in their own trust store, which is what the Dockerfile assets and the injector handle.

- **Baking beats patching.** `docker cp` into a running container is undone the moment the container is recreated; the Dockerfile route survives.
- **Trust-store layout is detected per container** — `/usr/local/share/ca-certificates` + `update-ca-certificates` (Debian/Ubuntu/Alpine), `/etc/pki/ca-trust/source/anchors` + `update-ca-trust` (RHEL family), or `/etc/pki/trust/anchors` (SUSE). Minimal images that ship the merged bundle but no `update-ca-certificates` (most Alpine-based ones) get the CA appended to `/etc/ssl/certs/ca-certificates.crt` instead, marked so re-runs are idempotent.
- **The OS trust store is not sufficient on its own.** Node, Python `requests`, pip, Cargo and Git each carry their own CA list, so the generated Dockerfiles also set `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO` and `CARGO_HTTP_CAINFO`. (Verified: Node rejects a Netskope-signed cert with `UNABLE_TO_VERIFY_LEAF_SIGNATURE` even after `update-ca-certificates`, and accepts it once `NODE_EXTRA_CA_CERTS` is set.)
- **`.crt`, not `.pem`** — `update-ca-certificates` only picks up files with a `.crt` extension, which is why the container copy is named `netskope-ca.crt`.
- Generated assets are ASCII with LF line endings and no BOM, so they work unchanged when the bundle is produced on Windows and consumed in a Linux container.

## Kubernetes

Pods use their image's trust store and nodes pull images with their own containerd, so neither is reached by the host configuration above — and cluster nodes have no Netskope Client. A cluster behind SSL inspection needs the Netskope CA delivered explicitly. This is opt-in: pass `--k8s` (`-K8s` on Windows), or answer yes when the script offers it because `kubectl` is on PATH. `--k8s-namespace NAME` (`-K8sNamespace`) sets the namespace used in the manifests (default `default`). The script writes a self-contained `<certDir>/k8s/` directory:

| File | Use |
| --- | --- |
| `configmap.yaml` | ConfigMap `netskope-ca` holding the full bundle (under its real filename) and `netskope-ca.crt` (the Netskope chain only) |
| `deployment-example.yaml` | Example Deployment that mounts the ConfigMap read-only at `/etc/netskope` and sets the CA variables |
| `trust-manager-bundle.yaml` | Optional: the same result through cert-manager's trust-manager |
| `trust-netskope-ca-on-node.sh` | Makes a node's **containerd** trust the CA (image pulls) |
| `netskope-ca.crt` | The Netskope CA chain only — used by the node script |
| `regenerate.sh` / `regenerate.bat` | Rebuild this directory from the existing bundle without prompts (macOS / Linux / Python; `.bat` for Python on Windows). On Windows PowerShell run `configured_tools.ps1 -K8s` instead |
| `README.md` | The same guidance, next to the files |

### Two separate problems

Pod trust and node trust fail independently, and fixing one does not fix the other:

- **The pods** need the CA in the workload's own trust store or CA variables — that is what `configmap.yaml` and `deployment-example.yaml` provide. A pod without it fails its own HTTPS calls.
- **The nodes** pull images with the node's containerd, which does its own TLS to the registry, so a node without the CA leaves pods in `ImagePullBackOff` with `x509: certificate signed by unknown authority` before any container exists. `trust-netskope-ca-on-node.sh` (Linux, needs `sudo`) fixes this two ways: with no arguments it installs into the node's OS trust store, which covers every registry but restarts containerd; given registry names it writes `/etc/containerd/certs.d/<registry>/hosts.toml`, which takes effect on the next pull with no restart but only for those registries, and only if containerd's `config_path` points at that directory. On EKS, GKE and AKS a manual run is lost when nodes are replaced — put it in node bootstrap or a privileged DaemonSet.

- **Baking beats mounting.** Putting the CA into the image (`Dockerfile.snippet` in the `docker/` directory) works wherever the image runs and needs no per-workload wiring; mount the ConfigMap for images you cannot rebuild.
- **Apply the ConfigMap server-side.** The full bundle is about 220 KB, and client-side `kubectl apply` copies the whole object into the `last-applied-configuration` annotation, which is limited to 262144 bytes. Use `kubectl apply --server-side -f configmap.yaml` or `kubectl create -f configmap.yaml`.
- **Mount read-only at `/etc/netskope`** — not over `/etc/ssl/certs`, and without `subPath`, which never picks up ConfigMap updates.
- **Each variable points at the right file.** `NODE_EXTRA_CA_CERTS` *adds* to Node's built-in CAs, so it takes `netskope-ca.crt`. `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO` and `AWS_CA_BUNDLE` *replace* the default store, so they must point at the full bundle, which includes the Mozilla roots. Java reads none of these and needs its own truststore; .NET on Linux reads only `SSL_CERT_FILE` and `SSL_CERT_DIR`.
- **Rotating the CA:** re-run the script, re-apply the ConfigMap, then `kubectl rollout restart` the workloads — most applications read their CAs once at startup.

## Notes

- **New shells only** — `setx` (Windows) and shell-config exports take effect in new terminal sessions, not the one that ran the script.
- **Restart GUI apps** — Claude Desktop, VS Code variants, and Azure Storage Explorer need to be restarted after configuration.
- **Backup on edit** — JSON configs (VS Code variants) are backed up to `<file>.backup` during the edit and restored automatically if the patch fails. The JSONC parser is string-aware on **read** (it won't choke on `//` inside `https://` URLs), but the **write** is a plain JSON re-serialization — any `//` or `/* */` comments in your `settings.json` are not preserved. The scripts print a warning when they drop comments.
- **Trust-store download is verified first** — the Mozilla root bundle (`curl.se/ca/cacert.pem`) is fetched with TLS verification enabled and only falls back to an unverified fetch if that fails (i.e. when the host is behind Netskope inspection and the resigned cert isn't trusted yet). A size sanity-check rejects truncated/captive-portal responses before they reach the bundle.
- **API token stays off the process table** — the Unix script passes the Bearer token to `curl` via a mode-600 `--config` file rather than on the command line, so it isn't visible in `ps` on multi-user hosts.
- **`REQUESTS_CA_BUNDLE` is shared** — Python Requests and Azure CLI both read it, so setting it once configures both.

### Python (any platform)

```bash
python3 universal_configure_tools.py
```

Stdlib only — no `pip install` needed.

## Other files

- [check_ssl.js](check_ssl.js) — Node.js probe for verifying a TLS endpoint after configuration. Prints the presented certificate chain (leaf → root) and whether Node's active trust store (system roots + `NODE_EXTRA_CA_CERTS`) validated it. Usage: `node check_ssl.js [host[:port]] [path]` — exits non-zero if the chain didn't validate.
