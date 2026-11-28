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
Check corporate NTLM hashes against a local NTLM Pwned Passwords dump, detect shared hashes (`--check-reuse`), flag Active Directory credential hygiene issues (`--check-ad-hygiene`), exclude `$` computer accounts (`--exclude-machines`), and screen against a company-specific banned dictionary (`--custom-wordlist`):

```bash
pwned audit ntds.pwdump \
  --source pwdump \
  --offline-db /data/pwned-passwords-ntlm.txt \
  --exclude-machines \
  --check-reuse \
  --check-ad-hygiene \
  --custom-wordlist banned-org-passwords.txt \
  --format markdown \
  --fail-if-pwned
```

Notes for `pwdump` mode:
- `--ntlm` is automatically enabled.
- Entries are checked via `check_hash()` directly; no plaintext passwords are required or emitted.
- `--check-reuse` groups domain accounts sharing identical NTLM hashes without revealing the hashes.
- `--check-strength` skips irreversible hashes (character entropy cannot be measured on hashes).
- `--exclude-machines` filters Active Directory computer/trust accounts whose username ends with `$` (e.g., `DC01$`, `WS-001$`).

### Active Directory Hygiene Checks (`--check-ad-hygiene`)
When `--check-ad-hygiene` (or `check_ad_hygiene=True` in Python/MCP) is enabled, `AuditSummary.ad_findings` reports:
- **`empty_ntlm`** — Accounts storing the empty-password NTLM hash (`31D6CFE0D16AE931B73C59D7E0C089C0`).
- **`lm_hash_present`** — `pwdump` records storing a non-empty legacy LM hash (LM field present and not `AAD3B435B51404EEAAD3B435B51404EE`).
- **`username_as_password`** — Accounts whose password matches their `SamAccountName` (or computer name without `$`, or UPN local-part before `@`) across exact, lowercase, uppercase, capitalized, and title-case variants (checked locally via MD4/SHA-1 for pre-hashed entries and case-insensitively for plaintext vaults).

### Custom Organizational Wordlist (`--custom-wordlist FILE`)
Screen both plaintext password-manager vaults and pre-hashed `pwdump` / SHA-1 audits against an internal banned dictionary (company brand names, seasonal patterns, default onboarding passwords):

```bash
pwned audit vault.json \
  --source bitwarden-json \
  --custom-wordlist banned-org-passwords.txt \
  --format sarif \
  --fail-if-pwned
```

- Reads UTF-8 (including UTF-8 BOM) newline-delimited files, skipping blank lines and `#` comment lines.
- Reports matches in `AuditSummary.wordlist_findings` (`wordlist_matches` count) without emitting plaintext passwords or matched wordlist terms:
  - Plaintext vaults report `exact` and full `casefold()` `case_insensitive` matches.
  - Pre-hashed `pwdump` / SHA-1 dumps cannot be case-folded directly, so they report exact digest matches (`exact`) and common capitalization variants (`lower`, `upper`, `capitalize`, `title`) explicitly as `case_variant` — list any custom mixed-case organizational variants directly in your wordlist file for guaranteed hash coverage.
- For `--format sarif`, emits `HIBP005` (`ADCredentialHygiene`) and `HIBP006` (`BannedWordlistPassword`) alongside `HIBP002` (`CompromisedPassword`).
- With `--fail-if-pwned`, exits with code `8` if compromised entries, AD hygiene findings, or custom wordlist matches are found.

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
