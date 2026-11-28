# Offline Lookups & Local MCP Server

## Resumable Offline Hash Dump Downloader

For air-gapped environments, high-scale Active Directory audits, or zero-latency local checks, `pwned offline download` fetches the complete Pwned Passwords corpus (`00000`–`FFFFF`, 1,048,576 prefixes).

By default, the CLI writes a **per-prefix range directory** (`00000.txt`–`FFFFF.txt`, `SUFFIX:COUNT` lines) alongside a `.pwned-index.json` ETag index for incremental `HTTP 304` refreshes and direct interoperability with the official Have I Been Pwned CLI (`hibp password download`). Pass `--single` / `-s` to merge all prefixes into one sorted `<HASH>:<COUNT>\r\n` file.

```bash
# Default: download full SHA-1 per-prefix range directory (00000.txt–FFFFF.txt + .pwned-index.json)
pwned offline download /data/pwned-sha1 --parallelism 32

# Re-run later to refresh only changed ranges via saved ETags (HTTP 304)
pwned offline download /data/pwned-sha1

# Ignore saved ETags and force a full rebuild of the directory and index
pwned offline download /data/pwned-sha1 --force-refresh

# Download NTLM corpus into a single merged sorted file
pwned offline download /data/pwned-passwords-ntlm.txt \
  --single \
  --mode ntlm \
  --concurrency 32 \
  --etag-cache /data/pwned-ntlm-etags.json \
  --overwrite
```

| Option | Default | Description |
|---|---|---|
| `-s`, `--single` | `False` | Write one merged sorted `HASH:COUNT` file instead of a per-prefix range directory (`00000.txt`–`FFFFF.txt`) |
| `--mode [sha1\|ntlm]` | `sha1` | Hash algorithm mode: `sha1` or `ntlm` |
| `-n`, `--ntlm` | `False` | Download NTLM hashes (`?mode=ntlm`) instead of SHA-1 (overrides `--mode`) |
| `--concurrency`, `--parallelism`, `-p INT` | `32` | Number of workers in the bounded async download pool |
| `--resume / --no-resume` | `True` | Resume an interrupted download by reusing existing files/shards and saved ETags |
| `--etag-cache FILE` | `None` | Custom JSON file storing ETags for conditional `If-None-Match` / `HTTP 304` refreshes (defaults to `<OUTPUT>/.pwned-index.json` in directory mode) |
| `--max-retries INT` | `None` | Maximum retry attempts per prefix on transient errors (omit for unlimited retries; `0` to disable) |
| `-o`, `--overwrite` | `False` | Permit replacing an existing single `OUTPUT` file or a non-empty directory without a saved index |
| `--force-refresh` | `False` | Ignore cached shards and saved ETags, forcing a full re-download and rebuilding the ETag index |

How it works:
- **Per-prefix directory mode (CLI default):** Atomically writes flat `00000.txt`–`FFFFF.txt` range files directly under `OUTPUT` and checkpoints hash mode (`sha1`/`ntlm`) plus prefix ETags in `.pwned-index.json` (or `--etag-cache`), directly compatible with `hibp password download`. Subsequent runs send `If-None-Match` so unchanged ranges return `HTTP 304 Not Modified` without re-reading cached files from disk. Mixing SHA-1 and NTLM modes against an indexed directory is rejected unless rebuilding with `--force-refresh` or `--no-resume`. Pass `--overwrite` / `-o` to write into a non-empty directory that has no saved index.
- **Single-file mode (`--single` / `-s`):** Atomically stages partial prefixes in 256 buckets under `.<output>.part/<00..FF>/<PREFIX>.txt` so filesystems (APFS/NTFS/ext4) never hold 1M staging files in a single directory, then merges shards in strict hexadecimal order (with zero-count entries stripped) into a temp file and atomically swaps it into `OUTPUT` via `os.replace()`. Pass `--overwrite` / `-o` when replacing an existing single file.
- **Bounded worker pool & TTY progress:** Uses a fixed-size async worker pool (`--concurrency` / `--parallelism` / `-p`) to keep memory flat across all 1,048,576 prefixes while reporting live progress to `stderr` when attached to a TTY (so `--json`/`--format` stdout stays clean).
- **Download statistics (`DownloadStats`):** Both CLI output and `download_offline_db()` return a `DownloadStats` model with `prefixes_total`, `prefixes_downloaded`, `prefixes_cached`, `hashes_written` (hashes written during that run), `elapsed_seconds`, `ranges_per_second`, `output_path`, `ntlm`, and `directory`.

## Offline Lookups (`--offline-db` & `OfflinePasswordsClient`)

`--offline-db PATH` (on `pwned password`, `pwned audit`, `pwned serve`, and `pwned mcp`) and `OfflinePasswordsClient` accept either a **per-prefix range directory** (`O(1)` direct prefix lookup) or a **single sorted dump file** (`O(log N)` binary search):

### CLI Usage

```bash
# Query a per-prefix range directory (O(1) lookup)
pwned password --offline-db /data/pwned-sha1 --stdin
pwned audit ntds.pwdump --source pwdump --offline-db /data/pwned-ntlm --check-reuse

# Query a single merged sorted dump file (O(log N) binary search)
pwned password --offline-db /data/pwned-passwords-sha1.txt --stdin
pwned audit ntds.pwdump --source pwdump --offline-db /data/pwned-passwords-ntlm.txt --check-reuse
```

### Python Usage (`OfflinePasswordsClient`)

```python
from pathlib import Path
from pwned import OfflinePasswordsClient

# O(1) direct prefix lookup against a per-prefix range directory (00000.txt–FFFFF.txt)
with OfflinePasswordsClient(Path("/data/pwned-sha1")) as dir_client:
    assert dir_client.is_directory is True
    count = dir_client.check_password("password")

# O(log N) binary search against a single sorted dump file (HASH:COUNT)
with OfflinePasswordsClient(Path("/data/pwned-passwords-ntlm.txt"), ntlm=True) as file_client:
    assert file_client.is_directory is False
    compromised = file_client.is_hash_pwned("8846F7EAEE8FB117AD06BDD830B7586C")
```

## Self-Hosted *k*-Anonymity HTTP Server & Caching Proxy (`pwned serve`)

`pwned serve` runs a zero-dependency, drop-in HTTP server compatible with `https://api.pwnedpasswords.com/range/{prefix}` for air-gapped networks, internal authentication services, and high-QPS validation backends.

### CLI Usage

```bash
# Air-gapped / self-hosted mode backed by an offline range directory or single sorted dump
pwned serve --offline-db /data/pwned-sha1 --host 127.0.0.1 --port 8080

# Serve an NTLM offline dump
pwned serve --offline-db /data/pwned-ntlm --ntlm --host 0.0.0.0 --port 8080

# Upstream caching proxy mode (caches range buckets locally via global --cache)
pwned --cache serve --port 8080
```

| Option | Default | Description |
|---|---|---|
| `--host TEXT` | `127.0.0.1` | Bind address for the HTTP server |
| `--port INT` | `8080` | Listening TCP port (`0` selects an ephemeral port) |
| `--offline-db PATH` | `None` | Local HIBP sorted dump file or per-prefix range directory (`00000.txt`–`FFFFF.txt`); disables upstream network calls when set |
| `--mode [sha1\|ntlm]` | `sha1` | Offline database hash mode (`sha1` or `ntlm`; proxy mode serves both dynamically) |
| `-n`, `--ntlm` | `False` | Serve an NTLM `--offline-db` (overrides `--mode`) |
| `--pad / --no-pad` | `True` | Request `Add-Padding: true` on upstream HIBP proxy fetches |
| `--metrics / --no-metrics` | `True` | Expose Prometheus metrics on `GET /metrics` (returns `404` when disabled) |
| `--access-log` | `False` | Emit HTTP request access logs to `stderr` |

### HTTP Endpoints

- **`GET /range/<5-hex>`** — Returns sorted `SUFFIX:COUNT\r\n` lines with `Cache-Control: public, max-age=3600`:
  - Supports optional `?mode=sha1|ntlm` (defaults to `sha1`; offline mode enforces the configured DB mode and returns `400` on mismatch).
  - Supports the `Add-Padding: true` request header by deterministically padding responses to 800–1,000 lines with `0`-count suffixes and echoing `Add-Padding: true`.
  - Returns `400 Bad Request` on invalid prefixes/modes, `502 Bad Gateway` on upstream proxy errors, and `405 Method Not Allowed` (`Allow: GET`) on non-`GET` methods.
- **`GET /healthz`** — Returns `200 OK` JSON (`ServerHealth`): `{"status": "ok", "backend": "offline" | "proxy", "mode": "sha1" | "ntlm" | "auto", "uptime_seconds": ...}`.
- **`GET /metrics`** — Returns `200 OK` (`text/plain; version=0.0.4; charset=utf-8`) in Prometheus text exposition format (`pwned_range_requests_total`, `pwned_range_padded_responses_total`, `pwned_range_errors_total`, `pwned_range_upstream_errors_total`, and `pwned_server_uptime_seconds`), or `404 Not Found` when `--no-metrics` is set.

### Python Usage (`PwnedRangeServer` & `create_range_server`)

```python
from pathlib import Path
from pwned import PwnedRangeServer, ResponseCache, create_range_server

# Offline directory or single-file range server
with PwnedRangeServer(
    offline_db=Path("/data/pwned-sha1"),
    host="127.0.0.1",
    port=8080,
) as server:
    print(server.url, server.health())
    server.serve_forever()

# Upstream caching proxy via factory helper
with create_range_server(port=8080, cache=ResponseCache()) as proxy_server:
    proxy_server.serve_forever()
```

## Local Privacy-First Stdio MCP Server (`pwned mcp`)

Have I Been Pwned offers an [official remote MCP server](https://haveibeenpwned.com/Docs/MCP) (`https://haveibeenpwned.com/mcp`) for general breach intelligence. `pwned mcp` complements it with a **built-in, zero-dependency local JSON-RPC 2.0 stdio MCP server** specifically for workflows where plaintext passwords, password-manager files, or local baselines must never leave your machine.

### Client Configuration

Add `pwned mcp` to any MCP-compatible AI client (Claude Desktop, Cursor, Antigravity, etc.). `--offline-db` accepts either a per-prefix range directory (`00000.txt`–`FFFFF.txt`) or a single sorted dump file:

```json
{
  "mcpServers": {
    "pwned-local": {
      "command": "pwned",
      "args": ["mcp", "--offline-db", "/path/to/pwned-passwords-sha1.txt", "--cache"]
    }
  }
}
```

Or run zero-install via `uvx`:

```json
{
  "mcpServers": {
    "pwned-local": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/domfahey/pwned.git", "pwned", "mcp", "--cache"]
    }
  }
}
```

### Exposed Local Tools

| Tool | Purpose | Privacy Guardrails |
|---|---|---|
| `check_password_hash` | Check a pre-computed 40-char SHA-1 or 32-char NTLM hash against `--offline-db` or online *k*-anonymity (`--cache` supported) | Accepts **hashes only** — never accepts plaintext passwords |
| `audit_vault` | Audit local plaintext vault exports, `pwdump` files, live `pass`/`gopass` stores, or unlocked `bitwarden-cli`/`1password-cli` vaults (`check_reuse`, `check_strength`, `check_ad_hygiene`, `exclude_machines`, `custom_wordlist_path`, `check_breaches`, `threshold`) | Returns sanitized findings/risk scores only (zero plaintext passwords); **rejects** `keepass` and `bitwarden-encrypted-json` so master passwords are never passed through an AI prompt |
| `diff_baseline` | Diff two local JSON snapshot files (`breaches`, `domain`, `search`, `account_batch`) | 100% local file comparison |
| `lookup_breach` | Look up public HIBP breach metadata by name or filtered list (with optional local `--cache`) | Public read-only catalog |
| `check_account_range` | Check an email address via HIBP's 6-char SHA-1 *k*-anonymity range API | Uses locally configured HIBP API key; never sends plaintext email to HIBP |

### Protocol Details

- Transport: newline-delimited JSON-RPC 2.0 over `stdin`/`stdout` (`protocolVersion: "2024-11-05"`).
- Supported methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
- Programmatic usage: import `MCPServer` and `serve_stdio` directly from `pwned`.
