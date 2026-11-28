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

## Compact Offline Hash Indexes (`pwned offline compact` & `build-bloom`)

Once you have a local range directory or sorted text dump, `pwned` can compile it into two memory-mapped binary formats for faster lookups and dramatically smaller storage footprints:

| Format | Magic | Size vs. ASCII | Lookup | Exact Counts | `pwned serve` Support |
|---|---|---|---|---|---|
| Compact binary index (`compact`) | `PWNB` | ~50% smaller | `O(1)` prefix jump (`1,048,576` prefixes) + mmap binary search | Yes | Yes |
| Bloom filter (`bloom`) | `PWNL` | Sub-1 GB RAM/mmap | `O(k)` mmap bitset probes (zero false negatives) | No (`1` or `0`) | No (rejected) |

### Fixed-Width Compact Binary Index (`pwned offline compact`)

`pwned offline compact SOURCE OUTPUT` compiles a per-prefix range directory (`00000.txt`–`FFFFF.txt`) or sorted single-file text dump into a single memory-mapped `PWNB` binary file with an `O(1)` 1,048,576-prefix jump table and fixed-width sorted records (24 bytes/record for SHA-1; 20 bytes/record for NTLM). Exact breach prevalence counts are preserved (zero-count entries omitted) at ~50% of the ASCII dump size, and the index is supported across `OfflinePasswordsClient`, `pwned password --offline-db`, `pwned audit --offline-db`, `pwned serve --offline-db`, `pwned mcp --offline-db`, and `pwned doctor --offline-db`.

```bash
# Compile a SHA-1 range directory or sorted text dump into a compact binary index
pwned offline compact /data/pwned-sha1 /data/pwned-sha1.pwnb --overwrite

# Compile an NTLM dump explicitly
pwned offline compact /data/pwned-passwords-ntlm.txt /data/pwned-ntlm.pwnb --mode ntlm -o
```

| Option | Default | Description |
|---|---|---|
| `--mode [sha1\|ntlm]` | Auto-detected | Hash algorithm mode (`sha1` or `ntlm`); auto-detected from `SOURCE` if omitted |
| `-n`, `--ntlm` | `False` | Compile as NTLM hashes (overrides `--mode`) |
| `-o`, `--overwrite` | `False` | Replace an existing `OUTPUT` file atomically |

### Mmap-able Bloom Filter (`pwned offline build-bloom`)

`pwned offline build-bloom SOURCE OUTPUT` compiles a compact binary index (fastest single-pass build), per-prefix range directory, or text dump into a memory-mapped `PWNL` probabilistic Bloom filter. At the default `--fpr 0.01` (1% false-positive rate), the entire HIBP corpus fits in a sub-1 GB RAM/mmap-resident file suitable for containers and CI runners with **zero false negatives** (`lookup_hash` returns `1` for a possible match or `0` for guaranteed absence).

!!! note "Bloom filter limitations"
    Bloom filters are probabilistic presence-only filters: they do **not** store exact breach counts (`lookup_hash` returns `1` or `0`, so `--threshold > 1` will never match) and they **cannot** enumerate suffix lists for `/range/<prefix>`. Bloom filters work with `OfflinePasswordsClient`, `pwned password --offline-db`, `pwned audit --offline-db`, `pwned mcp --offline-db`, and `pwned doctor --offline-db`, and are rejected by `pwned serve --offline-db`.

```bash
# Build a sub-1 GB Bloom filter from a compact index (or directory/text dump)
pwned offline build-bloom /data/pwned-sha1.pwnb /data/pwned-sha1.bloom --fpr 0.01 --overwrite

# Build an NTLM Bloom filter with an explicit item-count hint (avoids counting pass on text/dir)
pwned offline build-bloom /data/pwned-ntlm /data/pwned-ntlm.bloom \
  --ntlm \
  --fpr 0.001 \
  --expected-items 900000000 \
  --overwrite
```

| Option | Default | Description |
|---|---|---|
| `--mode [sha1\|ntlm]` | Auto-detected | Hash algorithm mode (`sha1` or `ntlm`); auto-detected from `SOURCE` if omitted |
| `-n`, `--ntlm` | `False` | Build an NTLM Bloom filter (overrides `--mode`) |
| `--fpr FLOAT` | `0.01` | Target false-positive rate (strictly between `0` and `1`) |
| `--expected-items INT` | Auto-counted | Optional expected item count to size the bitset in a single pass |
| `-o`, `--overwrite` | `False` | Replace an existing `OUTPUT` file atomically |

### Python Usage (`build_compact_index`, `build_bloom_filter` & `OfflinePasswordsClient.format`)

```python
from pathlib import Path
from pwned import OfflinePasswordsClient, build_bloom_filter, build_compact_index

compact_stats = build_compact_index(
    Path("/data/pwned-sha1"),
    Path("/data/pwned-sha1.pwnb"),
    overwrite=True,
)
bloom_stats = build_bloom_filter(
    Path("/data/pwned-sha1.pwnb"),
    Path("/data/pwned-sha1.bloom"),
    false_positive_rate=0.01,
    overwrite=True,
)
print(compact_stats.record_count, bloom_stats.bit_count, bloom_stats.num_hashes)

with OfflinePasswordsClient(Path("/data/pwned-sha1.pwnb")) as compact_client:
    assert compact_client.format == "compact"
    exact_count = compact_client.check_password("password")

with OfflinePasswordsClient(Path("/data/pwned-sha1.bloom")) as bloom_client:
    assert bloom_client.format == "bloom"
    probably_pwned = bloom_client.check_password("password")  # 1 or 0
```

## Offline Lookups (`--offline-db` & `OfflinePasswordsClient`)

`--offline-db PATH` (on `pwned password`, `pwned audit`, `pwned serve`, `pwned mcp`, and `pwned doctor`) and `OfflinePasswordsClient` transparently auto-detect all four offline storage formats:

- **Per-prefix range directory** (`format == "directory"`): `O(1)` direct prefix lookup over `00000.txt`–`FFFFF.txt`.
- **Compact binary index (`PWNB`)** (`format == "compact"`): `O(1)` prefix jump table + mmap binary search with exact counts.
- **Bloom filter (`PWNL`)** (`format == "bloom"`): sub-1 GB mmap presence filter returning `1`/`0` (supported by lookup commands and `doctor`; rejected by `pwned serve`).
- **Single sorted text dump** (`format == "text"`): `O(log N)` binary search over `HASH:COUNT` lines.

### CLI Usage

```bash
# Query a per-prefix range directory (O(1) lookup)
pwned password --offline-db /data/pwned-sha1 --stdin
pwned audit ntds.pwdump --source pwdump --offline-db /data/pwned-ntlm --check-reuse

# Query a compact binary index (PWNB) or mmap-able Bloom filter (PWNL)
pwned password --offline-db /data/pwned-sha1.pwnb --stdin
pwned audit vault.json --source bitwarden-json --offline-db /data/pwned-sha1.bloom
pwned doctor --offline-db /data/pwned-sha1.pwnb --no-network

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
    assert dir_client.format == "directory"
    assert dir_client.is_directory is True
    count = dir_client.check_password("password")

# Memory-mapped O(1) prefix jump lookup against a compact binary index (PWNB)
with OfflinePasswordsClient(Path("/data/pwned-sha1.pwnb")) as compact_client:
    assert compact_client.format == "compact"
    count = compact_client.check_password("password")

# O(log N) binary search against a single sorted dump file (HASH:COUNT)
with OfflinePasswordsClient(Path("/data/pwned-passwords-ntlm.txt"), ntlm=True) as file_client:
    assert file_client.format == "text"
    compromised = file_client.is_hash_pwned("8846F7EAEE8FB117AD06BDD830B7586C")
```

## Self-Hosted *k*-Anonymity HTTP Server & Caching Proxy (`pwned serve`)

`pwned serve` runs a zero-dependency, drop-in HTTP server compatible with `https://api.pwnedpasswords.com/range/{prefix}` for air-gapped networks, internal authentication services, and high-QPS validation backends.

### CLI Usage

```bash
# Air-gapped / self-hosted mode backed by a compact binary index (PWNB), range directory, or sorted dump
pwned serve --offline-db /data/pwned-sha1.pwnb --host 127.0.0.1 --port 8080

# Serve an NTLM offline dump
pwned serve --offline-db /data/pwned-ntlm --ntlm --host 0.0.0.0 --port 8080

# Upstream caching proxy mode (caches range buckets locally via global --cache)
pwned --cache serve --port 8080
```

| Option | Default | Description |
|---|---|---|
| `--host TEXT` | `127.0.0.1` | Bind address for the HTTP server |
| `--port INT` | `8080` | Listening TCP port (`0` selects an ephemeral port) |
| `--offline-db PATH` | `None` | Local HIBP compact binary index (`PWNB`), per-prefix range directory (`00000.txt`–`FFFFF.txt`), or sorted text dump; disables upstream network calls when set (Bloom filters are rejected because they cannot list prefix suffixes) |
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

# Offline compact index (PWNB), range directory, or single-file range server
with PwnedRangeServer(
    offline_db=Path("/data/pwned-sha1.pwnb"),
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

Add `pwned mcp` to any MCP-compatible AI client (Claude Desktop, Cursor, Antigravity, etc.). `--offline-db` accepts a per-prefix range directory (`00000.txt`–`FFFFF.txt`), compact binary index (`PWNB`), Bloom filter (`PWNL`), or single sorted dump file:

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
