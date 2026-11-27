# Vault & Active Directory Auditing

`pwned audit` checks password-manager exports, browser exports, Active Directory NTLM hash dumps, and live Unix password stores **entirely locally** using *k*-anonymity (only 5-character hash prefixes leave the machine) or an air-gapped `--offline-db` dump. Plaintext passwords are never stored in output reports, logs, or webhook payloads.

## Supported Sources (`--source`)

| Source | Format | Optional Extra | Notes |
|---|---|---|---|
| `bitwarden-json` *(default)* | Bitwarden unencrypted JSON | None | Reads login `items[].login.password` |
| `bitwarden-encrypted-json` | Bitwarden password-protected encrypted JSON | `pwned[crypto]` (`cryptography>=44.0`) | Supports both **PBKDF2-SHA256 (`kdfType=0`)** and **Argon2id (`kdfType=1`)**; prompts for export password |
| `bitwarden-csv` | Bitwarden CSV | None | `name`, `login_username`, `login_password` |
| `1password-csv` | 1Password CSV | None | `Title`/`URL`, `Username`, `Password` |
| `1password-1pux` | 1Password `.1pux` ZIP archive | None | Reads `export.data` across accounts and vaults |
| `lastpass-csv` | LastPass CSV | None | `name`/`url`, `username`, `password` |
| `dashlane-csv` | Dashlane `credentials.csv` | None | `title`/`domain`/`url`, `username`/`login`/`username2`, `password` |
| `protonpass-csv` | Proton Pass CSV | None | `name`/`url`, `username`/`email`, `password` |
| `chrome-csv` | Google Chrome / Edge CSV | None | `name`/`url`, `username`, `password` |
| `firefox-csv` | Mozilla Firefox CSV | None | `url`, `username`, `password` |
| `apple-csv` | Apple Passwords / Safari CSV | None | `Title`/`URL`, `Username`, `Password` |
| `csv` | Generic CSV | None | Case-insensitive `name`/`title`, `username`/`email`, `password` |
| `keepass` | KeePass `.kdbx` | `pwned[keepass]` | Prompts for master password |
| `pwdump` | Impacket `secretsdump.py` / NTDS / `pwdump` | None | Parses `[domain\]user:RID:LM:NT:::` lines directly without plaintext passwords; auto-enables `--ntlm` |
| `pass` | Unix `pass` store | None (`pass` CLI on `PATH`) | Reads entries in memory (`PATH` optional; defaults to `$PASSWORD_STORE_DIR` or `~/.password-store`) |
| `gopass` | `gopass` store | None (`gopass` CLI on `PATH`) | Lists via `gopass ls --flat` and reads in memory (`PATH` optional) |

## Common Examples

### Bitwarden Encrypted JSON (PBKDF2 or Argon2id) with Reuse & Strength Checks
```bash
pwned audit vault-encrypted.json \
  --source bitwarden-encrypted-json \
  --check-reuse \
  --check-strength \
  --cache \
  --format html > vault-audit.html
```

### Active Directory `secretsdump.py` / `pwdump` Audit (Air-Gapped)
Check corporate NTLM hashes against a local NTLM Pwned Passwords dump and identify accounts sharing the same password hash (`--check-reuse`):

```bash
pwned audit ntds.pwdump \
  --source pwdump \
  --offline-db /data/pwned-passwords-ntlm.txt \
  --check-reuse \
  --format markdown
```

Notes for `pwdump` mode:
- `--ntlm` is automatically enabled.
- Entries are checked via `check_hash()` directly; no plaintext passwords are required or emitted.
- `--check-reuse` groups domain accounts sharing identical NTLM hashes without revealing the hashes.
- `--check-strength` skips irreversible hashes (character entropy cannot be measured on hashes).

### Live Unix `pass` / `gopass` Store Audit (Zero Plaintext Exports)
```bash
pwned audit --source pass --check-reuse --check-strength --fail-if-pwned
pwned audit ~/.my-pass-store --source pass --format table
pwned audit --source gopass --check-reuse
```

## Reuse Detection & Strength Scoring

- **`--check-reuse`:** Groups duplicate passwords (or duplicate NTLM hashes for `pwdump`) across vault entries into `reused_groups`, sorted by reuse count and breach prevalence.
- **`--check-strength`:** Evaluates each plaintext entry with a built-in zero-dependency heuristic scorer (length `< 8` / `< 12`, character class diversity, Shannon entropy, repeated characters, keyboard/sequential runs, and username/title overlap) producing a `0..4` score and actionable reasons. When the optional `pwned[strength]` extra (`zxcvbn`) is installed, scores and feedback are automatically enhanced with `zxcvbn`.
- **Vault Risk Score (`risk_score`):** When `--check-strength` is enabled, `AuditSummary` includes a `0..100` composite risk score weighting compromised (`60%`), reused (`25%`), and weak (`15%`) entries.

## Performance & Privacy Tips

- Use `--cache` during online audits to cache 5-character `/range/{prefix}` buckets locally across repeated runs.
- Tune `--concurrency` (default `10`) for large vaults.
- Response padding (`Add-Padding: true`) is **enabled by default** on `pwned audit` via `--pad/--no-pad` (disable only if needed via `--no-pad`).
- Delete any plaintext CSV/JSON vault exports immediately after auditing; prefer `bitwarden-encrypted-json`, `keepass`, `pass`, `gopass`, or `pwdump` whenever possible.
