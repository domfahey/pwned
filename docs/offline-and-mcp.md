# Offline Lookups & Local MCP Server

## Resumable Offline Hash Dump Downloader

For air-gapped environments, high-scale Active Directory audits, or zero-latency local checks, `pwned offline download` fetches the complete Pwned Passwords corpus (`00000`–`FFFFF`, 1,048,576 prefixes) and assembles a sorted `<HASH>:<COUNT>\r\n` file ready for `OfflinePasswordsClient`.

```bash
# Download full SHA-1 corpus (resumable by default)
pwned offline download /data/pwned-passwords-sha1.txt --concurrency 32

# Download NTLM corpus with ETag caching for incremental HTTP 304 refreshes
pwned offline download /data/pwned-passwords-ntlm.txt \
  --ntlm \
  --concurrency 32 \
  --etag-cache /data/pwned-ntlm-etags.json
```

How it works:
- **256-bucket sharded staging:** Partial prefixes are written under `.<output>.part/<00..FF>/<PREFIX>.txt` so filesystems (APFS/NTFS/ext4) never hold 1M files in a single directory.
- **Resumable & incremental:** Interrupted downloads skip already-fetched shards automatically (`--resume` default). Passing `--etag-cache <path>` preserves shards and sends `If-None-Match` on future runs so unchanged ranges return `HTTP 304 Not Modified`.
- **Atomic sorted merge:** Shards are merged in strict hexadecimal order (with zero-count entries stripped) into a temp file and atomically swapped into `OUTPUT` via `os.replace()`.
- **Direct querying:** Query the resulting file immediately with zero network traffic:
  ```bash
  pwned password --offline-db /data/pwned-passwords-sha1.txt --stdin
  pwned audit ntds.pwdump --source pwdump --offline-db /data/pwned-passwords-ntlm.txt --check-reuse
  ```

## Local Privacy-First Stdio MCP Server (`pwned mcp`)

Have I Been Pwned offers an [official remote MCP server](https://haveibeenpwned.com/Docs/MCP) (`https://haveibeenpwned.com/mcp`) for general breach intelligence. `pwned mcp` complements it with a **built-in, zero-dependency local JSON-RPC 2.0 stdio MCP server** specifically for workflows where plaintext passwords, password-manager files, or local baselines must never leave your machine.

### Client Configuration

Add `pwned mcp` to any MCP-compatible AI client (Claude Desktop, Cursor, Antigravity, etc.):

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
| `audit_vault` | Audit local plaintext vault exports, `pwdump` files, or `pass`/`gopass` stores (`check_reuse`, `check_strength`, `threshold`) | Returns sanitized findings/risk scores only (zero plaintext passwords); **rejects** `keepass` and `bitwarden-encrypted-json` so master passwords are never passed through an AI prompt |
| `diff_baseline` | Diff two local JSON snapshot files (`breaches`, `domain`, `search`, `account_batch`) | 100% local file comparison |
| `lookup_breach` | Look up public HIBP breach metadata by name or filtered list (with optional local `--cache`) | Public read-only catalog |
| `check_account_range` | Check an email address via HIBP's 6-char SHA-1 *k*-anonymity range API | Uses locally configured HIBP API key; never sends plaintext email to HIBP |

### Protocol Details

- Transport: newline-delimited JSON-RPC 2.0 over `stdin`/`stdout` (`protocolVersion: "2024-11-05"`).
- Supported methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
- Programmatic usage: import `MCPServer` and `serve_stdio` directly from `pwned`.
