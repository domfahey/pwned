# Have I Been Pwned API v3 Coverage

`pwned` implements **100% of the official [Have I Been Pwned API v3](https://haveibeenpwned.com/API/v3) specification** (all **21 / 21** REST endpoints across `https://haveibeenpwned.com/api/v3` and `https://api.pwnedpasswords.com`), including all documented query parameters, request headers, response model fields, error body formats, and integration test accounts.

## Endpoint Coverage Matrix (21 / 21)

| Area | Plan Tier | Official Endpoint | Query Params / Headers / Body | Python Client (`HIBPClient` / `AsyncHIBPClient`) | CLI Command |
|---|---|---|---|---|---|
| **Email Search** | Core / Pro / High RPM | `GET /breachedAccount/{email}` | `truncateResponse`, `domain`, `includeUnverified` | `get_account_breaches()` | `pwned account` (`ba`) |
| **Email Search** | Pro / High RPM | `GET /breachedAccount/range/{prefix}` | 6-char SHA-1 *k*-anonymity (trimmed + lowercased) | `get_account_range()`, `check_account_range()` | `pwned account-range` (`bar`) |
| **Domain Verification** | Pro | `POST /domainVerification/generateDnsToken` | `{"DomainName"}` | `generate_dns_token()` | `pwned domain-verify dns-token` |
| **Domain Verification** | Pro | `POST /domainVerification/verifyDnsToken` | `{"DomainName"}` | `verify_dns_token()` | `pwned domain-verify dns-check` |
| **Domain Verification** | Pro | `POST /domainVerification/generateMetaTag` | `{"DomainName"}` | `generate_meta_tag()` | `pwned domain-verify meta-tag` |
| **Domain Verification** | Pro | `POST /domainVerification/verifyMetaTag` | `{"DomainName"}` (+ 404 JSON detail parsing) | `verify_meta_tag()` | `pwned domain-verify meta-check` |
| **Domain Verification** | Pro | `POST /domainVerification/sendEmail` | `{"DomainName", "EmailAlias"}` (`admin`, `hostmaster`, `info`, `security`, `webmaster`) | `send_verification_email()` | `pwned domain-verify email` |
| **Domain Search** | Core / Pro | `GET /breachedDomain/{domain}` | URL-encoded domain | `get_domain_breaches()` | `pwned domain` (`bd`) |
| **Domain Search** | Core / Pro | `GET /subscribedDomains` | — | `get_subscribed_domains()` | `pwned subscribed-domains [list]` (`sd`) |
| **Domain Search** | Pro | `DELETE /subscribedDomains/{domain}` | URL-encoded domain (idempotent HTTP 200) | `remove_subscribed_domain()` | `pwned subscribed-domains remove` (`sd remove`) |
| **Breaches** | Free | `GET /breaches` | `domain`, `isSpamList`, `includeUnverified` | `get_breaches()` | `pwned breaches` |
| **Breaches** | Free | `GET /breach/{name}` | URL-encoded breach name | `get_breach()` | `pwned breach` |
| **Breaches** | Free | `GET /latestBreach` | — | `get_latest_breach()` | `pwned latest-breach` (`lb`) |
| **Data Classes** | Free | `GET /dataClasses` | — | `get_data_classes()` | `pwned dataclasses` (`dc`) |
| **Data Classes** | Free | `GET /dataClasses/descriptions` | — | `get_data_class_descriptions()` | `pwned dataclasses --descriptions` |
| **Stealer Logs** | Pro | `GET /stealerLogsByEmail/{email}` | URL-encoded email | `get_stealer_logs_by_email()` | `pwned stealer email` |
| **Stealer Logs** | Pro | `GET /stealerLogsByWebsiteDomain/{domain}` | URL-encoded website domain | `get_stealer_logs_by_website_domain()` | `pwned stealer website` |
| **Stealer Logs** | Pro | `GET /stealerLogsByEmailDomain/{domain}` | URL-encoded email domain | `get_stealer_logs_by_email_domain()` | `pwned stealer domain` |
| **Pastes** | Core / Pro / High RPM | `GET /pasteAccount/{email}` | URL-encoded email | `get_pastes()` | `pwned pastes` (`pa`) |
| **Subscription** | Core / Pro / High RPM | `GET /subscription/status` | — | `get_subscription_status()` | `pwned subscription` |
| **Pwned Passwords** | Free | `GET https://api.pwnedpasswords.com/range/{prefix}` | 5-char SHA-1/NTLM, `?mode=ntlm`, `Add-Padding: true`, count-`0` padding discard | `PwnedPasswordsClient` / `AsyncPwnedPasswordsClient` | `pwned password` (`pw`), `pwned offline download` |

> **Note:** File-upload domain verification is browser-dashboard-only in Have I Been Pwned; no REST API endpoint exists for it.

## Response Model Parity (`src/pwned/models.py`)

All 8 official API response models use strict frozen Pydantic v2 schemas with exact PascalCase/camelCase field aliases preserved on serialization (`by_alias=True`):

| Model | Documented Fields Covered | Notable Fields |
|---|---|---|
| `Breach` | **20 / 20** | Includes `IsMalware`, `IsStealerLog`, `IsSubscriptionFree`, `Attribution`, `DisclosureUrl` |
| `Paste` | **5 / 5** | `Source`, `Id`, `Title`, `Date`, `EmailCount` |
| `Subscription` | **11 / 11** | Includes `MaxBreachedDomains`, `IncludesBulkDomainAdd`, `IncludesAutoSubdomainVerification`, `IncludesCustomerDomains`, `IncludesKAnon` |
| `SubscribedDomain` | **5 / 5** | `DomainName`, `PwnCount`, `PwnCountExcludingSpamLists`, `PwnCountExcludingSpamListsAtLastSubscriptionRenewal`, `NextSubscriptionRenewal` |
| `DataClassDescription` | **2 / 2** | `name`, `description` |
| `BreachedAccountRangeResult` | **2 / 2** | `hashSuffix`, `websites` |
| `DnsToken` | **1 / 1** | `txtRecordValue` |
| `MetaTag` | **1 / 1** | `metaTag` |

## Protocol, Error Handling & Compliance

- **Authentication & Headers:** Sends `hibp-api-key` on authenticated calls and `User-Agent` (default `pwned-cli`) on all requests.
- **Rate Limiting (`429`):** Automatically retries up to `max_retries` (configurable, including `0`) honoring clamped `Retry-After` headers with optional jitter (`retry_jitter`) and exposing raw `RateLimitError.retry_after`. Batch account lookups support automatic subscription RPM detection.
- **Error Body Parsing:** Inspects `Content-Type` and status codes across `400`, `401`, `403`, `404`, and `5xx`, extracting sanitized messages from JSON objects (`{"message": ...}`), JSON strings, and `text/plain` responses (e.g. API key format diagnostics on `401` and `verifyMetaTag` diagnostics on `404`) while suppressing HTML/XML/binary Cloudflare error pages.
- **Caching & Conditional Requests:** Optional XDG TTL caching (`--cache`) for public endpoints and Pwned Passwords range prefixes, plus `If-None-Match` / `ETag` (`HTTP 304`) support in `pwned offline download`.
- **Integration Test Accounts:** All **16 / 16** official `hibp-integration-tests.com` test aliases are covered in `tests/integration/test_e2e.py` using the documented HIBP test API key (`00000000000000000000000000000000`).
- **Licensing & Attribution:** Breach and paste data is attributed to [Have I Been Pwned](https://haveibeenpwned.com/) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) in `README.md` and standalone HTML reports.
