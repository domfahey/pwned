# Have I Been Pwned - API Documentation

The API allows the list of pwned accounts (email addresses, usernames and phone numbers) to be quickly searched via a RESTful service.

## Index

- [Overview](#overview)
- [Authorisation](#authorisation)
- [Test API Key](#test-api-key)
- [Specifying the API version](#specifying-the-api-version)
- [Specifying the user agent](#specifying-the-user-agent)
- [Breaches](#breaches)
- [Stealer Logs](#stealer-logs)
- [Pastes](#pastes)
- [Subscription](#subscription)
- [Pwned Passwords](#pwned-passwords)
- [HTTPS](#https)
- [Response codes](#response-codes)
- [Test accounts](#test-accounts)
- [CORS](#cross-origin-resource-sharing-cors)
- [Rate limiting](#rate-limiting)
- [Abuse](#abuse)
- [Acceptable use](#acceptable-use)
- [License](#license)

## Overview

You're reading about v3 of the API which is presently the current version and contains breaking changes over previous versions for searching breaches and pastes via email address.

## Authorisation

Authorisation is required for all APIs that enable searching HIBP by email address or domain, namely retrieving all breaches for an account, retrieving all pastes for an account, retrieving all breached email addresses for a domain and retrieving all stealer log domains for a breached email addresses. There is no authorisation required for the free Pwned Passwords API. An HIBP subscription key is required to make an authorised call and can be obtained on the API key page. The key is then passed in a "hibp-api-key" header:

```
GET https://haveibeenpwned.com/api/v3/{service}/{parameter}
hibp-api-key: [your key]
```

Semantic HTTP response codes are used to indicate the result of the API call:

| Code | Description |
|------|-------------|
| 401  | Unauthorised — the API key provided was not valid |

Additional information may be present in the response body when an API call fails, for example:

- Access denied due to missing hibp-api-key.
- Access denied due to improperly formed hibp-api-key.
- Access denied due to invalid hibp-api-key.

HIBP API keys must be 32-character hexadecimal strings. Keys undergo an initial format check, followed by validation to confirm their authenticity before any processing occurs.

## Test API Key

Where supported, a test API key can be used instead of a paid subscription. Test keys provide limited access (typically to test accounts) and may be any value that conforms to the required key format. For example:

```
GET https://haveibeenpwned.com/api/v3/{service}/{parameter}
hibp-api-key: 00000000000000000000000000000000
```

## Specifying the API version

Version 3 of the API is consumable only by specifying the API version in the URL. All API endpoints are requested with the following pattern:

```
GET https://haveibeenpwned.com/api/v3/{service}/{parameter}
```

## Specifying the user agent

Each request to the API must be accompanied by a user agent request header. Typically this should be the name of the app consuming the service. A missing user agent will result in an HTTP 403 response. A valid request would look like:

```
GET https://haveibeenpwned.com/api/v3/{service}/{parameter}
user-agent: [your app name]
```

The user agent should accurately describe the nature of the API consumer such that it can be clearly identified in the request. Not doing so may result in the request being blocked.

## Breaches

### Getting all breaches for an account

The most common use of the API is to return a list of all breaches a particular account has been involved in. The API takes a single parameter which is the account to be searched for. The account is not case-sensitive and will be trimmed of leading or trailing white spaces. The account should always be URL encoded. This is an authenticated API and an HIBP API key must be passed with the request.

```
GET https://haveibeenpwned.com/api/v3/breachedaccount/{account}
hibp-api-key: [your key]
```

If the account is found in a breach, an HTTP 200 response is returned. By default, only the name of the breach is returned rather than the complete breach data, thus reducing the response body size by approximately 98% compared to returning the full breach model.

```json
[
  {
    "Name": "Adobe"
  },
  {
    "Name": "Gawker"
  },
  {
    "Name": "Stratfor"
  }
]
```

The name can then be used to either retrieve a single breach or it can be found in the list of all breaches in the system. If you'd like complete breach data returned in the API call, a non-truncated response can be specified via query string parameter:

| Parameter | Example | Description |
|-----------|---------|-------------|
| truncateResponse | `?truncateResponse=false` | Returns the full breach model. |

Which returns the complete model for each breach:

```json
[
  {
    "Name": "Adobe",
    "Title": "Adobe",
    "Domain": "adobe.com",
    "BreachDate": "2013-10-04",
    "AddedDate": "2013-12-04T00:00:00Z",
    "ModifiedDate": "2022-05-15T23:52:49Z",
    "PwnCount": 152445165,
    "Description": "In October 2013, 153 million Adobe accounts were breached...",
    "LogoPath": "Adobe.png",
    "DataClasses": [
      "Email addresses",
      "Password hints",
      "Passwords",
      "Usernames"
    ],
    "IsVerified": true,
    "IsFabricated": false,
    "IsSensitive": false,
    "IsRetired": false,
    "IsSpamList": false,
    "IsMalware": false,
    "IsStealerLog": false,
    "IsSubscriptionFree": false
  }
]
```

The result set can also be filtered by passing one of the following query strings:

| Parameter | Example | Description |
|-----------|---------|-------------|
| domain | `?Domain=adobe.com` | Filters the result set to only breaches against the domain specified. It is possible that one site (and consequently domain), is compromised on multiple occasions. |

Note: the public API will not return accounts from any breaches flagged as sensitive or retired. By default, the API will return breaches flagged as unverified, however these can be excluded by using the following parameter:

| Parameter | Example | Description |
|-----------|---------|-------------|
| IncludeUnverified | `?IncludeUnverified=false` | Returns breaches that have been flagged as "unverified". By default, both verified and unverified breaches are returned when performing a search. |

If the account is not found in a breach, an HTTP 404 response will be returned.

This API supports test API keys that can be used to query any email address on the test accounts domain. For example:

```
GET https://haveibeenpwned.com/api/v3/breachedaccount/account-exists%40hibp-integration-tests.com
hibp-api-key: 00000000000000000000000000000000

GET https://haveibeenpwned.com/api/v3/breachedaccount/spam-list-only%40hibp-integration-tests.com
hibp-api-key: 00000000000000000000000000000000

GET https://haveibeenpwned.com/api/v3/breachedaccount/stealer-log%40hibp-integration-tests.com
hibp-api-key: 00000000000000000000000000000000
```

### Getting all breached email addresses for a domain

All email addresses on a given domain and the breaches they've appeared in can be returned via the domain search API. Only domains that have been successfully added to the domain search dashboard after verifying control can be searched. The API takes a single parameter which is the domain to be searched for and is an authenticated API requiring an HIBP API key.

```
GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}
hibp-api-key: [your key]
```

If one or more results are found, an HTTP 200 response is returned. For each breached email address on the domain, only the alias is returned along with each breach it has appeared in.

```json
{
  "alias1": [
   "Adobe"
  ],
  "alias2": [
    "Adobe",
    "Gawker",
    "Stratfor"
  ],
  "alias3": [
    "AshleyMadison"
  ]
}
```

In the above example, if the domain searched for is example.com then 3 email addresses have been found:

- alias1@example.com is in the Adobe data breach
- alias2@example.com is in the Adobe, Gawker and Stratfor data breaches
- alias3@example.com is in the Ashley Madison data breach

If the domain does not have any email addresses in any breaches, an HTTP 404 response will be returned.

Note: the domain search API will return sensitive data breaches as it can only be called after demonstrating control of the domain.

### Getting all subscribed domains

Domains that have been successfully added to the domain search dashboard after verifying control are returned via this API. This is an authenticated API requiring an HIBP API key which will then return all domains associated with that key.

```
GET https://haveibeenpwned.com/api/v3/subscribeddomains
```

The API returns a list of subscribed domains including the following attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| DomainName | string | The full domain name that has been successfully verified. |
| PwnCount | integer | The total number of breached email addresses found on the domain at last search (will be null if no searches yet performed). |
| PwnCountExcludingSpamLists | integer | The number of breached email addresses found on the domain at last search, excluding any breaches flagged as a spam list (will be null if no searches yet performed). |
| PwnCountExcludingSpamListsAtLastSubscriptionRenewal | integer | The total number of breached email addresses found on the domain when the current subscription was taken out (will be null if no searches yet performed). |
| NextSubscriptionRenewal | datetime | The date and time the current subscription ends in ISO 8601 format. |

### Getting all breached sites in the system

A "breach" is an instance of a system having been compromised by an attacker and the data disclosed. For example, Adobe was a breach, Gawker was a breach etc.

```
GET https://haveibeenpwned.com/api/v3/breaches
```

The result set can also be filtered by passing one of the following query strings:

| Parameter | Example | Description |
|-----------|---------|-------------|
| Domain | `?Domain=adobe.com` | Filters the result set to only breaches against the domain specified. |
| IsSpamList | `?IsSpamList=true` | Filters the result set to only breaches that either are or are not flagged as a spam list. |

### Getting a single breached site by name

Sometimes just a single breach is required and this can be retrieved by the breach "Name". This is the stable value which may or may not be the same as the breach "Title", which can change.

```
GET https://haveibeenpwned.com/api/v3/breach/{name}
```

### Getting the most recently added breach

This API returns the most recently added breach based on the "AddedDate" attribute of the breach model.

```
GET https://haveibeenpwned.com/api/v3/latestbreach
```

### Getting all data classes in the system

A "data class" is an attribute of a record compromised in a breach. The values returned by this service are ordered alphabetically in a string array.

```
GET https://haveibeenpwned.com/api/v3/dataclasses
```

### The breach model

Each breach contains a number of attributes describing the incident. In the future, these attributes may expand without the API being versioned.

| Attribute | Type | Description |
|-----------|------|-------------|
| Name | string | A Pascal-cased name representing the breach which is unique across all other breaches. This value never changes and may be used to name dependent assets (such as images) but should not be shown directly to end users (see the "Title" attribute instead). |
| Title | string | A descriptive title for the breach suitable for displaying to end users. It's unique across all breaches but individual values may change in the future. |
| Domain | string | The domain of the primary website the breach occurred on. |
| BreachDate | date | The date (with no time) the breach originally occurred on in ISO 8601 format. |
| AddedDate | datetime | The date and time (precision to the minute) the breach was added to the system in ISO 8601 format. |
| ModifiedDate | datetime | The date and time (precision to the minute) the breach was modified in ISO 8601 format. |
| PwnCount | integer | The total number of accounts loaded into the system. |
| Description | string | Contains an overview of the breach represented in HTML markup. |
| DataClasses | string[] | Describes the nature of the data compromised in the breach. |
| IsVerified | boolean | Indicates that the breach is considered unverified. |
| IsFabricated | boolean | Indicates that the breach is considered fabricated. |
| IsSensitive | boolean | Indicates if the breach is considered sensitive. |
| IsRetired | boolean | Indicates if the breach has been retired. |
| IsSpamList | boolean | Indicates if the breach is considered a spam list. |
| IsMalware | boolean | Indicates if the breach is sourced from malware. |
| IsSubscriptionFree | boolean | Indicates if the breach is subscription-free. |
| IsStealerLog | boolean | Indicates if the breach is sourced from stealer logs. |
| LogoPath | string | A URI that specifies where a logo for the breached service can be found. Logos are always in PNG format. |
| Attribution | string | Sometimes requested by the party that provides the data to HIBP. |

### Sample breach response

```json
[
  {
    "Name": "Adobe",
    "Title": "Adobe",
    "Domain": "adobe.com",
    "BreachDate": "2013-10-04",
    "AddedDate": "2013-12-04T00:00Z",
    "ModifiedDate": "2022-05-15T23:52Z",
    "PwnCount": 152445165,
    "Description": "In October 2013, 153 million Adobe accounts were breached with each containing an internal ID, username, email, <em>encrypted</em> password and a password hint in plain text. The password cryptography was poorly done and many were quickly resolved back to plain text. The unencrypted hints also <a href=\"http://www.troyhunt.com/2013/11/adobe-credentials-and-serious.html\" target=\"_blank\" rel=\"noopener\">disclosed much about the passwords</a> adding further to the risk that hundreds of millions of Adobe customers already faced.",
    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
    "IsVerified": true,
    "IsFabricated": false,
    "IsSensitive": false,
    "IsRetired": false,
    "IsSpamList": false,
    "IsMalware": false,
    "IsSubscriptionFree": false,
    "LogoPath": "Adobe.png",
    "Attribution": null
  },
  {
    "Name": "BattlefieldHeroes",
    "Title": "Battlefield Heroes",
    "Domain": "battlefieldheroes.com",
    "BreachDate": "2011-06-26",
    "AddedDate": "2014-01-23T13:10Z",
    "ModifiedDate": "2014-01-23T13:10Z",
    "PwnCount": 530270,
    "Description": "In June 2011 as part of a final breached data dump, the hacker collective \"LulzSec\" <a href=\"http://www.rockpapershotgun.com/2011/06/26/lulzsec-over-release-battlefield-heroes-data\" target=\"_blank\" rel=\"noopener\">obtained and released over half a million usernames and passwords from the game Battlefield Heroes</a>. The passwords were stored as MD5 hashes with no salt and many were easily converted back to their plain text versions.",
    "DataClasses": ["Passwords", "Usernames"],
    "IsVerified": true,
    "IsFabricated": false,
    "IsSensitive": false,
    "IsRetired": false,
    "IsSpamList": false,
    "IsMalware": false,
    "IsSubscriptionFree": false,
    "LogoPath": "BattlefieldHeroes.png",
    "Attribution": null
  }
]
```

## Stealer Logs

### Overview

Stealer logs typically appear as a combination of website address, email address and password. For example:

```
https://netflix.com/login:jane@gmail.com:P@ssw0rd
https://netflix.com/login:andy@gmail.com:abc123
https://spotify.com/auth:jane@gmail.com:qwerty
https://spotify.com/auth:max@yahoo.com:baseball
```

The nomenclature used to describe the four attributes the HIBP APIs deal with:

| Component | Example |
|-----------|---------|
| Website Domain | netflix.com |
| Email Alias | jane |
| Email Domain | gmail.com |
| Email Address | jane@gmail.com |

HIBP stores the website domain alongside the email addresses. The logs are then searchable in 3 different ways:

1. **By email address**: searching for jane@gmail.com would return netflix.com and spotify.com
2. **By email address domain**: searching for gmail.com would return both Jane and Andy's email addresses along with the domains of the websites they appeared against
3. **By website domain**: searching for netflix.com would return both Jane and Andy's email addresses

Each search can only be performed against domains that have been successfully added to the domain search dashboard after verifying control.

All stealer log APIs require a Pwned 5 subscription or higher, regardless of domain size.

Note: there are no API endpoints that return the password for a user. Passwords are independently searchable via the Pwned Passwords service.

### Getting all stealer log domains for an email address

This search is based on the full email address captured by an info stealer as the owner authenticated to a website.

```
GET https://haveibeenpwned.com/api/v3/stealerlogsbyemail/{email address}
hibp-api-key: [your key]
```

Response:

```json
[
  "netflix.com",
  "spotify.com"
]
```

If no stealer log entries are present for the address, the response will return HTTP 404.

### Getting all stealer log email addresses for a website domain

This search is by the domain of the website URLs that appear in stealer logs.

```
GET https://haveibeenpwned.com/api/v3/stealerlogsbywebsitedomain/{domain}
hibp-api-key: [your key]
```

Response:

```json
[
  "andy@gmail.com",
  "jane@gmail.com"
]
```

### Getting all stealer log email aliases for an email domain

This search is by the domain of the email address.

```
GET https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/{domain}
hibp-api-key: [your key]
```

Response:

```json
{
  "andy": [
    "netflix.com"
  ],
  "jane": [
    "netflix.com",
    "spotify.com"
  ]
}
```

## Pastes

### Getting all pastes for an account

The API takes a single parameter which is the email address to be searched for. The address is not case-sensitive and will be trimmed of leading or trailing white spaces. The address should always be URL encoded. This is an authenticated API and an HIBP API key must be passed with the request.

```
GET https://haveibeenpwned.com/api/v3/pasteaccount/{account}
hibp-api-key: [your key]
```

### The paste model

| Attribute | Type | Description |
|-----------|------|-------------|
| Source | string | The paste service the record was retrieved from. Current values are: Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl, PermanentOptOut, OptOut |
| Id | string | The ID of the paste as it was given at the source service. Combined with the "Source" attribute, this can be used to resolve the URL of the paste. |
| Title | string | The title of the paste as observed on the source site. This may be null. |
| Date | date | The date and time (precision to the second) that the paste was posted. May be null if no date is published. |
| EmailCount | integer | The number of emails that were found when processing the paste. |

### Sample paste response

```json
[
  {
    "Source": "Pastebin",
    "Id": "8Q0BvKD8",
    "Title": "syslog",
    "Date": "2014-03-04T19:14:54Z",
    "EmailCount": 139
  },
  {
    "Source": "Pastie",
    "Id": "7152479",
    "Date": "2013-03-28T16:51:10Z",
    "EmailCount": 30
  }
]
```

## Subscription

### Getting the subscription status

This API returns details of the current subscription and is an authenticated API requiring an HIBP API key:

```
GET https://haveibeenpwned.com/api/v3/subscription/status
```

| Attribute | Type | Description |
|-----------|------|-------------|
| SubscriptionName | string | The name representing the subscription being either "Pwned 1", "Pwned 2", "Pwned 3" or "Pwned 4". |
| Description | string | A human readable sentence explaining the scope of the subscription. |
| SubscribedUntil | datetime | The date and time the current subscription ends in ISO 8601 format. |
| Rpm | integer | The rate limit in requests per minute. |
| DomainSearchMaxBreachedAccounts | integer | The size of the largest domain the subscription can search. |
| IncludesStealerLogs | boolean | Indicates if the subscription includes access to the stealer logs APIs. |

## Pwned Passwords

### Overview

Pwned Passwords are hundreds of millions of passwords which have previously been exposed in data breaches. The data is queryable online via the Pwned Passwords webpage, accessible via the API or downloadable as an entire corpus of data that can be queried offline. The Pwned Passwords API is freely accessible without the need for a subscription and API key.

Each password is stored as both a SHA-1 and an NTLM hash of a UTF-8 encoded password. The downloadable source data delimits the hash and the password count with a colon (:) and each line with a CRLF.

### Searching by range

Pwned Passwords implements a k-Anonymity model that allows a password to be searched for by partial hash. This allows the first 5 characters of either a SHA-1 or an NTLM hash (not case-sensitive) to be passed to the API:

```
GET https://api.pwnedpasswords.com/range/{first 5 hash chars}
```

When a password hash with the same first 5 characters is found, the API will respond with an HTTP 200 and include the suffix of every hash beginning with the specified prefix, followed by a count of how many times it appears in the data set.

A sample SHA-1 response for the hash prefix "21BD1":

```
0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011053FD0102E94D6AE2F8B83D76FAF94F6:1
012A7CA357541F0AC487871FEEC1891C49C:2
0136E006E24E7D152139815FB0FC6A50B15:2
...
```

A range search typically returns approximately 800 hash suffixes. There are 1,048,576 different hash prefixes between 00000 and FFFFF (16^5) and every single one will return HTTP 200; there is no circumstance in which the API should return HTTP 404.

| Code | Body | Description |
|------|------|-------------|
| 200 | Hash suffixes counts | Ok — all password hashes beginning with the searched prefix are returned alongside prevalence counts |

### Introducing padding

Padding can be added to responses to enhance privacy. Padding is enabled by a request header and ensures that all responses contain between 800 and 1,000 results regardless of the number of hash suffixes returned.

| Header | Example | Description |
|--------|---------|-------------|
| Add-Padding | `Add-Padding: true` | Pads out responses to ensure all results contain a random number of records between 800 and 1,000. |

Note: Padded entries always have a password count of 0 and can be discarded once received.

### Incremental searching

Incremental searching involves performing a search for the password as each character is typed by the user. This may provide a 3rd party with the ability to observe the API requests and discern the original password. Waiting until the entire password is entered before checking Pwned Passwords (for example, when the blur event is raised on the password field), mitigates this risk.

### Searching for NTLM hashes

Password hashes can also be requested in NTLM form. API requests still pass the first 5 characters of the hash, but the response returns NTLM hash suffixes of 27 characters rather than SHA-1 suffixes of 35 characters.

| Parameter | Example | Description |
|-----------|---------|-------------|
| mode | `?mode=ntlm` | Returns NTLM hash suffixes. When not specified or any value other than "ntlm", the resulting hashes will be in SHA-1 form. |

### Downloading all Pwned Passwords hashes

All password hashes are available for download as either SHA-1 or NTLM so they can be used without the API dependency. The Pwned Passwords Downloader is freely available from GitHub.

## HTTPS

All API endpoints must be invoked over HTTPS. Any requests over HTTP will result in a 301 response with a redirect to the same path on the secure scheme. Only TLS versions 1.2 and 1.3 are supported.

## Response codes

| Code | Description |
|------|-------------|
| 200 | Ok — everything worked and there's a string array of pwned sites for the account |
| 400 | Bad request — the account does not comply with an acceptable format (i.e. it's an empty string) |
| 401 | Unauthorised — either no API key was provided or it wasn't valid |
| 403 | Forbidden — no user agent has been specified in the request |
| 404 | Not found — the account could not be found and has therefore not been pwned |
| 429 | Too many requests — the rate limit has been exceeded |
| 503 | Service unavailable — usually returned by Cloudflare if the underlying service is not available |

## Test accounts

Test accounts exist to demonstrate different behaviours. All accounts are on the domain "hibp-integration-tests.com".

| Alias | Description |
|-------|-------------|
| account-exists | Returns one breach and one paste. |
| multiple-breaches | Returns three breaches. |
| not-active-and-active-breach | Returns one breach being "Adobe". An inactive breach also exists. |
| not-active-breach | Returns no breaches. An inactive data breach also exists. |
| opt-out | Returns no breaches and no pastes. This account is opted-out. |
| opt-out-breach | Returns no breaches and no pastes. This account is opted-out of breaches. |
| paste-sensitive-breach | Returns no breaches and one paste. A sensitive breach exists. |
| permanent-opt-out | Returns no breaches and no pastes. This account is permanently opted-out. |
| sensitive-and-other-breaches | Returns two non-sensitive breaches and no pastes. |
| sensitive-breach | Returns no breaches and no pastes. A sensitive breach exists. |
| spam-list-only | Returns a single breach flagged as a spam list. |
| spam-list-and-others | Returns multiple breaches, one flagged as a spam list. |
| subscription-free-and-other-breaches | Returns a breach flagged as subscription-free and two other breaches. |
| stealer-log | Returns a single stealer log breach and contains a single domain in a stealer log. |
| subscription-free-breach | Returns a single breach flagged as subscription-free. |
| unverified-breach | Returns one unverified breach and no pastes. |

## Cross-origin resource sharing (CORS)

CORS is only supported for non-authenticated APIs. APIs requiring a key should not be hit directly from the client side as it exposes the secret to other users. Instead, proxy the request through your own API.

On supported APIs, CORS accepts all origins.

## Rate limiting

Requests to the breaches, pastes and stealer log APIs are rate limited. The rate limits depends on the API key you've purchased. Any request that exceeds the limit will receive an HTTP 429 "Too many requests" response with a "retry-after" response header.

A typical response looks like this:

```
HTTP/1.1 429
retry-after: 2

{
  "statusCode": 429,
  "message": "Rate limit is exceeded. Try again in 2 seconds."
}
```

There is no rate limit on the Pwned Passwords API.

## Abuse

If you want to build up a treasure trove of pwned email addresses or usernames, go and download the dumps and save yourself the hassle of trying to enumerate an API one account at a time.

## Acceptable use

The API has been designed to make it easy for people to do awesome things with it. Things that are not awesome include:

- Querying the data for purposes that are intended to cause harm to the victims of data breaches
- Anything deliberately intended to limit service availability such as denial of service attacks
- Deliberate attempts to circumvent measures designed to ensure acceptable use
- Not properly identifying the user agent
- Misrepresenting the consuming client by impersonating other user agents
- Other services designed to fraudulently represent the Have I Been Pwned name or brand
- Misrepresenting the source of the data
- Not adhering to the Creative Commons Attribution License
- Automating the consumption of other APIs not explicitly documented on this page
- Using the service in a fashion that brings Have I Been Pwned into disrepute

## License

This work is licensed under a Creative Commons Attribution 4.0 International License.

You're welcome to use the public API to build other services, but you must identify Have I Been Pwned as the source of the data. Clear and visible attribution with a link to haveibeenpwned.com should be present anywhere data from the service is used.

There is no licencing or attribution requirements on the Pwned Passwords API, although it is welcomed.
