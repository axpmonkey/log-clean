# SAS 9.4 Log Sanitization Tool — Implementation Plan

## Project brief

Build a command-line tool in Go that sanitizes SAS 9.4 support log bundles by replacing infrastructure identifiers, credentials, and PII with consistent, reversible tokens. The sanitized output is intended for feeding into AI assistants to help with root cause analysis, while the original-to-token mapping stays on the analyst's local machine for translating findings back to real values.

The codebase will live in a corporate GitLab repository. It must be well-documented, tested, and structured as a reusable library plus a thin CLI wrapper. It targets SAS 9.4 M6 and later.

## Goals and non-goals

### Goals
- Sanitize a directory of SAS 9.4 support logs (mixed formats) in a single run
- Produce consistent tokens across all files in a bundle (e.g., the same hostname always gets the same token)
- Generate a mapping file the analyst can use to reverse tokens back to real values for the duration of a support case
- Detect and replace: FQDNs, IP addresses (v4 and v6), email addresses, MAC addresses, URLs/URIs, LDAP DNs, Windows UNC paths, usernames in various forms, credentials and secrets in connection strings, API keys, OAuth tokens, JWTs, AWS/GCP keys, SSH key fragments, Kerberos principals
- Support an optional customer-supplied hostname allowlist for precise matching of bare hostnames inside paths and compound strings
- Produce an audit report flagging anything in the output that looks like residual PII
- Run in reverse mode to convert a tokenized text back to original values using the mapping file
- Build cleanly for Linux, Windows, and macOS

### Non-goals (explicit, do not implement)
- Streaming or daemon mode — this is on-demand processing of bundles
- Compressed archive support (.zip, .tar.gz, .gz) — assume the user has already extracted
- Binary file processing — skip with a warning
- SAS log line unwrapping — accept the residual miss, audit will catch obvious cases
- Postgres CSV query log parsing — out of scope; only the WIPDS log style is in scope, which is closer to standard Postgres text logs
- AIX support — Linux/Windows/macOS only
- CI/CD pipeline — local builds only for now
- Cross-bundle consistency — each bundle gets a fresh salt and independent mapping
- Permanent or long-term mapping storage — mapping is per-case, treated as ephemeral

## Critical design decisions

These are the load-bearing decisions. Implement these as written; they were chosen deliberately after weighing alternatives.

### Decision 1: Sequential, deterministic-within-run tokenization
Use sequential tokens per category (`HOST_001`, `HOST_002`, `IPV4_001`, `USER_001`, etc.) rather than hash-based tokens. The numbering is determined by first-encounter order during a pre-scan pass. This requires a two-pass architecture (scan, then replace) but produces output that is far more readable for AI assistants and humans.

The sequential numbering must be stable within a single run. To achieve this, the pre-scan pass must process files in a deterministic order (alphabetical by filename) and lines in file order.

### Decision 2: Two-pass architecture
- **Pass 1 (scan):** Walk every file, run all detectors **in the exact same strict order as Pass 2 (Decision 4), using the same span-claiming `LineState` mechanism**, and collect every unique value per category into an ordered set. Build the global mapping table. Write the mapping file to disk.
- **Pass 2 (replace):** Walk every file again, run detectors in the same order, replace each detected value with its assigned token from the mapping table. Write sanitized output. Track replacement spans per line to prevent contamination.

Pass 1 must be a faithful dry-run of Pass 2's detector walk — same ordering, same span claims, same cross-registration of embedded values (e.g. URL → host). If Pass 1 used an unordered/independent detector sweep, it could discover a different set of values than Pass 2 actually replaces (e.g. an email embedded in a URL's query string getting claimed by the email detector during scan but not during replace, or vice versa), producing inconsistent tokens or missed replacements. The two passes should literally share the same per-line detector-walk function; only what they *do* with a match (record vs. substitute) differs.

This is slower than single-pass but gives the consistency guarantees we need. Performance is acceptable for 50-100 MB bundles.

### Decision 3: Per-line span tracking to prevent token contamination
When a detector replaces text on a line, it records the character range it modified. Subsequent detectors check for overlap before replacing. This prevents a later detector from accidentally matching inside an already-emitted token. Implement this as a small `LineState` struct that tracks `[]Span{Start, End}` ranges, ordered by start position, with an `IsProtected(start, end int) bool` method.

**Partial-overlap rule:** if a detector's candidate match overlaps a claimed span at all — even partially, even just one character — the detector must skip that candidate entirely rather than attempting to match around the claimed region. Do not implement partial/sub-span matching (e.g. a URL detector trying to match the portion of a URL before and after an embedded already-claimed email). This keeps behavior deterministic and easy to reason about, at the cost of occasionally leaving a longer span unmatched when an earlier, narrower detector claimed part of it first — acceptable given detector ordering already runs broad/sensitive matches (credentials, secrets, DNs, emails, URLs) before narrower ones. `IsProtected(start, end int) bool` returns true on any overlap, not just full containment.

### Decision 4: Detector ordering, longest-match-first
Run detectors in this strict order in pass 2. Each detector respects spans claimed by earlier detectors:

0. UUID claim detector (see Decision 6) — runs before everything else, including credentials/secrets, since a UUID can appear adjacent to or inside credential-like key=value pairs (e.g. `sessionId=550e8400-e29b-41d4-a716-446655440000`) and must never be partially consumed by a later, narrower detector.
1. Credentials in connection strings (passwords always **fully redacted**, never tokenized — `SECRET_REDACTED`)
2. API keys, OAuth tokens, JWTs, AWS/GCP keys, SSH key fragments (also fully redacted)
3. LDAP Distinguished Names
4. Email addresses
5. URLs and URIs (with embedded host extraction — the URL is tokenized as a whole, but the embedded host is also added to the host mapping for cross-file consistency)
6. FQDNs (with TLD allowlist to reduce false positives)
7. IPv4 addresses (with octet validation 0-255 and version-string heuristic)
8. IPv6 addresses
9. MAC addresses
10. Windows UNC paths
11. Kerberos principals (`user@REALM` format)
12. `DOMAIN\user` patterns
13. `user@domain` email-shaped non-emails (handled in step 4 already, but catch any stragglers)
14. Unix user paths (`/home/<user>/`, `/Users/<user>/`, `/export/home/<user>/`)
15. Windows user paths (`C:\Users\<user>\`, `C:\Documents and Settings\<user>\`)
16. Customer allowlist substring pass — runs last, finds any literal occurrence of customer-supplied hostnames anywhere in the line, including inside paths and compound strings

### Decision 5: Pseudonymize identifiers, fully redact secrets
- **Pseudonymize** (replace with deterministic token, mapping retained): hostnames, IPs, usernames, emails, domains, MACs, paths
- **Fully redact** (replace with `SECRET_REDACTED`, no mapping kept): passwords, API keys, OAuth tokens, JWTs, AWS keys, GCP keys, SSH key material, any other credential

The mapping file must never contain a real password or key. This is a hard rule.

### Decision 6: False positive prevention
Several patterns commonly cause false positives. Implement these guards:

- **IPv4 vs version numbers:** Validate octets 0-255. Additionally, suppress matches where the surrounding context strongly suggests a version (preceded by `v`, `version`, `release`, `SAS`, or appears after a SAS product name on the same line). Maintain a small list of known-false IPs to skip: `127.0.0.1` should still be tokenized (it is a real loopback in logs), but explicit version strings like `9.4.1.2` should not.
- **FQDN vs filename:** Require the rightmost label to be in a TLD allowlist (top ~30 common TLDs plus common internal pseudo-TLDs like `local`, `internal`, `corp`, `lan`, `intra`, `home`, `arpa`). Filenames like `app.log` or `server.xml` will not match.
- **UUIDs:** Do not tokenize UUIDs. Geode uses them for member IDs and they are useful for correlation. Add a UUID-shape detector that *claims spans* (so other detectors skip them) but emits no replacement.
- **SAS log timestamps:** The format `HH:MM:SS.mmm` should not be misread as anything. Time patterns are unlikely to match other detectors but verify with test cases.

### Decision 7: Buffer sizes
Java stack traces and SAS PROC output can produce single lines well over 1 MB. Configure the line scanner with a 16 MB buffer ceiling. Use `bufio.Reader` with a custom split function rather than `bufio.Scanner`, which has a default 64 KB limit that silently truncates.

### Decision 8: Encoding handling
Detect file encoding via BOM sniffing:
- UTF-8 BOM (`EF BB BF`) → UTF-8
- UTF-16 LE BOM (`FF FE`) → UTF-16 LE (common for Windows SAS logs)
- UTF-16 BE BOM (`FE FF`) → UTF-16 BE (rare)
- No BOM → assume UTF-8, fall back to Windows-1252 only if invalid UTF-8 sequences are detected

Internally process as UTF-8. Re-emit in the source encoding to preserve compatibility with downstream tools the customer might use.

Preserve original line endings (CRLF on Windows, LF on Linux). Detect on first line, apply on output.

### Decision 9: Binary file handling
Before processing, sniff the first 512 bytes of each file. If non-printable byte ratio exceeds 30%, classify as binary and skip with a warning logged. Also skip by extension allowlist exclusion: `.hprof`, `.jfr`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.zip`, `.gz`, `.tar`, `.jar`, `.war`, `.ear`, `.class`, `.so`, `.dll`, `.exe`, `core`, `core.*`.

### Decision 10: Idempotency requirement
Running the tool on already-sanitized output must produce byte-identical output. The token format `CATEGORY_NNN` must not match any detector. Add an idempotency test that runs sanitize twice and diffs the results.

## Tokenization scheme

| Category | Token format | Example | Action |
|---|---|---|---|
| Hostname (FQDN) | `HOST_NNN` | `HOST_001` | Pseudonymize |
| Bare hostname (allowlist match) | `HOST_NNN` | `HOST_042` | Pseudonymize, shares numbering with FQDN |
| Domain (suffix only) | `DOMAIN_NNN` | `DOMAIN_001` | Pseudonymize |
| IPv4 address | `IPV4_NNN` | `IPV4_001` | Pseudonymize |
| IPv6 address | `IPV6_NNN` | `IPV6_001` | Pseudonymize |
| MAC address | `MAC_NNN` | `MAC_001` | Pseudonymize |
| Email address | `EMAIL_NNN` | `EMAIL_001` | Pseudonymize |
| Username | `USER_NNN` | `USER_001` | Pseudonymize |
| LDAP DN | `DN_NNN` | `DN_001` | Pseudonymize |
| Kerberos principal | `KRB_NNN` | `KRB_001` | Pseudonymize |
| URL/URI | `URL_NNN` | `URL_001` | Pseudonymize whole; embedded host also added to HOST mapping |
| UNC path | `UNC_NNN` | `UNC_001` | Pseudonymize |
| Password | `SECRET_REDACTED` | `SECRET_REDACTED` | Fully redact, no mapping |
| API key / token | `SECRET_REDACTED` | `SECRET_REDACTED` | Fully redact, no mapping |
| AWS access key | `SECRET_REDACTED` | `SECRET_REDACTED` | Fully redact, no mapping |
| JWT | `SECRET_REDACTED` | `SECRET_REDACTED` | Fully redact, no mapping |

Use 3-digit zero-padded numbers up to 999, then 4-digit, etc. (`HOST_001`, `HOST_999`, `HOST_1000`).

## Project structure

```
sas-log-sanitize/
├── cmd/
│   └── sanitize/
│       └── main.go                   CLI entry point, flag parsing, error reporting
├── pkg/
│   └── sanitize/                     Public library API
│       ├── sanitize.go               Top-level Sanitize(opts) function
│       ├── options.go                Options struct, defaults, validation
│       └── doc.go                    Package documentation
├── internal/
│   ├── detect/
│   │   ├── detector.go               Detector interface, Span type, LineState
│   │   ├── credentials.go            Passwords, JDBC URLs with creds, OPTIONS METAUSER/METAPASS
│   │   ├── secrets.go                API keys, JWTs, AWS keys, GCP keys, SSH key fragments
│   │   ├── ldap.go                   DN parser
│   │   ├── network.go                IPv4, IPv6, FQDN, MAC, URL with embedded host extraction
│   │   ├── identity.go               Emails, DOMAIN\user, Kerberos principals, bare usernames
│   │   ├── paths.go                  UNC paths, /home/, /Users/, C:\Users\
│   │   ├── uuid.go                   UUID detector — claims spans, emits no replacement
│   │   └── allowlist.go              Customer hostname substring matching
│   ├── tokenize/
│   │   ├── registry.go               Global ordered map of value→token per category
│   │   └── token.go                  Token generation, formatting
│   ├── pipeline/
│   │   ├── pipeline.go               Two-pass orchestration
│   │   ├── scan.go                   Pass 1: collect unique values
│   │   ├── replace.go                Pass 2: substitute tokens
│   │   └── reverse.go                Reverse mode: token→original
│   ├── audit/
│   │   ├── scanner.go                Post-pass suspicious-token detector
│   │   └── report.go                 Audit report formatting
│   ├── io/
│   │   ├── encoding.go               BOM detection, UTF-16 to UTF-8 conversion
│   │   ├── filetype.go               Binary detection, extension filtering
│   │   ├── reader.go                 Large-buffer line reader
│   │   └── writer.go                 Line writer preserving encoding/line endings
│   ├── profile/
│   │   ├── profile.go                Profile loader
│   │   └── builtin/                  Embedded YAML profiles
│   │       ├── default.yaml
│   │       ├── sas94.yaml
│   │       ├── tomcat.yaml
│   │       ├── apache.yaml
│   │       ├── postgres-wipds.yaml
│   │       ├── activemq.yaml
│   │       └── geode.yaml
│   └── runlog/
│       └── runlog.go                 Application's own structured logger
├── testdata/
│   ├── synthetic/                    Hand-crafted synthetic logs with known PII
│   │   ├── sas94/
│   │   ├── tomcat/
│   │   ├── apache/
│   │   ├── postgres-wipds/
│   │   ├── activemq/
│   │   ├── geode/
│   │   └── mixed-bundle/
│   ├── golden/                       Expected sanitized output
│   └── encodings/                    Files in UTF-8, UTF-16 LE, with/without BOMs, CRLF/LF
├── docs/
│   ├── usage.md                      User guide
│   ├── architecture.md               Design rationale
│   ├── detectors.md                  Per-detector behavior and known limitations
│   ├── adding-detectors.md           How to extend
│   └── reversing.md                  How to use the mapping file
├── README.md
├── LICENSE
├── CHANGELOG.md
├── Makefile                          build, test, cross-compile targets
├── go.mod
└── go.sum
```

## CLI design

### Primary commands

```
sas-log-sanitize <input-dir> [flags]
sas-log-sanitize --reverse <mapping-file> <text-or-file>
sas-log-sanitize --audit-only <sanitized-dir> --mapping <mapping-file>
sas-log-sanitize --version
sas-log-sanitize --help
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--input` / `-i` | required | Input directory containing logs |
| `--output` / `-o` | `<input>-sanitized` | Output directory (created if missing) |
| `--mapping` / `-m` | `<output>/_mapping.json` | Path for mapping file |
| `--hostlist` | none | Path to customer-supplied hostname allowlist (one per line) |
| `--profiles` | auto | Comma-separated list of profiles to apply, or `auto` to detect per file |
| `--audit` | true | Run audit pass after sanitization |
| `--strict` | false | Exit non-zero if audit finds suspicious tokens |
| `--reverse` | n/a | Reverse mode: takes mapping file path |
| `--audit-only` | n/a | Audit-only mode: scan already-sanitized output |
| `--config` | none | Path to YAML config file |
| `--verbose` / `-v` | false | Verbose logging to the runlog |
| `--quiet` / `-q` | false | Suppress non-error output |
| `--dry-run` | false | Show what would be replaced, write nothing |
| `--no-color` | false | Disable terminal colors |

### Exit codes

- 0: success, no suspicious tokens in audit
- 1: success, but audit found suspicious tokens (warning)
- 2: input error (directory not found, permissions, etc.)
- 3: processing error (encoding failure, IO error, etc.)
- 4: configuration error (invalid YAML, bad flag combination)

### Output bundle structure

```
<output-dir>/
├── <every-input-file-sanitized>     Same relative paths as input
├── _mapping.json                    Reverse mapping file
├── _audit.txt                       Suspicious tokens report
├── _summary.txt                     Per-category replacement counts
└── _runlog.txt                      Application's own log of the run
```

## Detector specifications

For each detector, write tests covering at minimum: 5 positive cases (must match), 5 negative cases (must not match), and 2 edge cases (overlap with another detector, encoding edge case).

### Credentials detector
Patterns:
- `password\s*=\s*["']?([^"'\s,;)]+)` — case-insensitive
- `pwd\s*=\s*["']?([^"'\s,;)]+)`
- `secret\s*=\s*["']?([^"'\s,;)]+)`
- `pass(word)?:\s*([^\s,;)]+)`
- JDBC: `jdbc:[^/]+://([^:]+):([^@]+)@` — capture password group
- ActiveMQ: `(tcp|ssl|nio|amqp)://([^:]+):([^@]+)@`
- SAS: `OPTIONS\s+[^;]*METAPASS\s*=\s*["']?([^"'\s;]+)`, `OPTIONS\s+[^;]*METAUSER\s*=\s*["']?([^"'\s;]+)` (user is pseudonymized, pass is redacted)
- LDAP bind: `(bind\s*(password|pw|pwd))\s*[:=]\s*["']?([^"'\s]+)`
- Generic key=value where key contains `pass`, `secret`, `apikey`, `api_key`, `token`, `credential`

For all of these, redact only the value, not the key — `password=Passw0rd!` becomes `password=SECRET_REDACTED`.

### Secrets/keys detector
- AWS access key ID: `AKIA[0-9A-Z]{16}`
- AWS secret: contextual — preceded by `aws_secret_access_key` or similar
- Generic API key heuristics: `[a-zA-Z0-9_-]{32,}` *only when* preceded by key=value style with key matching `apikey|api_key|token|access_token|bearer`
- JWT: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- Bearer header: `Bearer\s+[A-Za-z0-9._~+/=-]+`
- GCP service account JSON markers: `"private_key":\s*"-----BEGIN`
- SSH key markers: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----` and surrounding key body until `-----END`
- Kerberos keytab references are paths, not secrets — handle in path detector

### LDAP DN detector
Pattern (case-insensitive): `(?:CN|OU|DC|UID|O|L|ST|C)=[^,)\s]+(?:,\s*(?:CN|OU|DC|UID|O|L|ST|C)=[^,)\s]+)+`

Tokenize the entire DN as a single unit (`DN_001`). Do not try to decompose into components — the DN as a whole is the meaningful identifier.

### Email detector
RFC 5322 simplified: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`

Edge case: don't match inside already-claimed DN spans (DNs may contain `mail=foo@bar` style attributes).

### URL/URI detector
Pattern: `(https?|ftp|ftps|sftp|jdbc:[a-z]+|tcp|ssl|nio|amqp|amqps|mqtt|ldap|ldaps)://[^\s<>"',;)]+`

When a URL is matched, also extract the host portion (between `://` and the next `:`, `/`, `?`, or end) and add it to the FQDN registry so it gets the same `HOST_NNN` token wherever it appears standalone elsewhere. The full URL gets its own `URL_NNN` token. This is the cross-format consistency mechanism.

### FQDN detector
Pattern: `\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`

After regex match, validate:
- Rightmost label is in TLD allowlist (~30 public TLDs + internal: `local`, `internal`, `corp`, `lan`, `intra`, `home`, `arpa`, `localdomain`, `priv`, `private`)
- Total length ≤ 253 characters
- Each label ≤ 63 characters
- Does not match a known false-positive list (e.g., `org.apache.foo.Bar` is a Java class, not an FQDN — heuristic: if surrounded by Java identifier characters or appears in a stack trace context, skip)

### IPv4 detector
Pattern: `\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`

Validation:
- All four octets 0-255 (regex already enforces, but double-check)
- Skip if preceded by `v`, `V`, `version`, `release`, `SAS`, or product version markers within the previous 20 characters
- Always tokenize `127.0.0.1`, `0.0.0.0`, private ranges — these matter in logs

### IPv6 detector
Use a robust IPv6 regex (these are notoriously hard). Recommend importing `net/netip` from stdlib and validating candidate matches with `netip.ParseAddr`. Match common shapes:
- Full: `[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}`
- Compressed: contains `::`
- IPv4-mapped: `::ffff:1.2.3.4`
- With zone ID: `fe80::1%eth0`

After regex candidate match, parse with `netip.ParseAddr` to confirm validity. Skip if parse fails.

### MAC address detector
Pattern: `\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`

### UNC path detector
Pattern: `\\\\[a-zA-Z0-9_-]+\\[a-zA-Z0-9_$.-]+(\\[^\s"<>|]*)?`

Tokenize the whole UNC path. The server portion should also be added to the host registry.

### User identity detector
Patterns:
- `DOMAIN\user`: `\b[A-Z][A-Z0-9_-]{1,15}\\[a-zA-Z0-9._-]+\b` (tokenize each part: domain → DOMAIN_NNN, user → USER_NNN, output: `DOMAIN_001\USER_001`)
- Kerberos: `[a-zA-Z0-9._-]+@[A-Z][A-Z0-9.-]+` (realm in uppercase distinguishes from email)
- Bare `username:` in known SAS log positions: `userid=`, `user=`, `username=`, `metaUser=`, `Authenticated user:`

### Path detectors
- `/home/<username>/...` and `/Users/<username>/...` and `/export/home/<username>/...`: tokenize the username portion only, leave rest of path
- `C:\Users\<username>\...` and `C:\Documents and Settings\<username>\...`: same
- Token output: `/home/USER_001/whatever/the/rest.txt`

### UUID claim detector
Pattern: `\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`

This detector claims spans but performs no replacement. Its purpose is to prevent later detectors from accidentally matching parts of UUIDs.

### Customer allowlist detector
Loaded from `--hostlist` file, one hostname per line, comments allowed (`#`). Performs literal substring matching on each line, longest-match-first (sort allowlist by length descending). Each match is replaced with the host's existing token (if already in registry from FQDN detection) or assigned a new `HOST_NNN` token.

This is the *only* detector that does substring matching rather than word-boundary matching, because customers explicitly want bare hostnames found inside compound paths like `/var/log/db-prod-01-archive/`.

**Short/ambiguous entry guard:** because this detector matches substrings rather than whole words, a short or non-distinctive allowlist entry will also match inside unrelated strings — e.g. `db1` matches inside `db10`, `adb1x`, `db1-archive-old`. At load time, reject or warn (configurable via `--strict`-style hard-fail vs. soft-warn) on allowlist entries shorter than a minimum length (default 4 characters) and flag entries that are a prefix of another entry already in the list. Document this limitation prominently in `docs/usage.md` and the README's allowlist section: customers should supply fully-qualified or sufficiently distinctive hostnames, not short fragments.

## Audit pass

After all replacements, walk the output and flag suspicious patterns:

| Pattern | Severity | Description |
|---|---|---|
| Unredacted IPv4 shape | High | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` (excluding tokens) |
| Unredacted FQDN shape | High | Multi-label dotted name not matching token format |
| Hostname-shaped bare word | Medium | `[a-z][a-z0-9-]*-?(prod|dev|uat|qa|stage|stg|dr|test)[0-9]*` |
| Server-suffix bare word | Medium | `[a-z]+[0-9]+(-(srv|server|host|node|db|web|app|mq))?` |
| Long random-looking string near credential keyword | Medium | 20+ char alphanumeric within 30 chars of `password`, `token`, `secret`, `key`, `credential` |
| Email shape | High | Standard email regex match in output |
| MAC shape | High | MAC regex match |
| Windows path with username | Medium | `C:\Users\[^\\]+\\` where the username is not `USER_NNN` |
| Unix path with username | Medium | `/home/[^/]+/` where the username is not `USER_NNN` |

The audit report (`_audit.txt`) lists each finding with file path, line number, line excerpt, and the suspicious text highlighted. Severities are tallied at the bottom.

In `--strict` mode, any High severity finding causes exit code 1 and a clear stderr message.

**Expected noise:** several Medium-severity heuristics are intentionally broad (e.g. `Hostname-shaped bare word` and `Server-suffix bare word` will also match things like `log4j`, `java8`, `port8080`, or other version/build identifiers that aren't real hostnames). This is by design — false negatives are worse than false positives for a security tool — but it means Medium findings should be expected at non-trivial volume on real logs and are not by themselves actionable failures. Only High severity gates `--strict`, specifically because the High-severity patterns (raw IPv4/FQDN shape, email shape, MAC shape) have a much lower false-positive rate. Before relying on `--strict` in any automated workflow, validate the false-positive rate of the High-severity rules against the synthetic test corpus (target: zero High findings on golden sanitized output across all profiles) and track that as an explicit acceptance criterion for Milestone 6.

## Mapping file format

```json
{
  "schema_version": 1,
  "generated_at": "2026-05-08T14:32:01Z",
  "tool_version": "0.1.0",
  "input_dir": "/path/to/bundle",
  "categories": {
    "HOST": {
      "HOST_001": "db-prod-01.acme.internal",
      "HOST_002": "app-prod-01.acme.internal"
    },
    "DOMAIN": {
      "DOMAIN_001": "acme.internal"
    },
    "IPV4": {
      "IPV4_001": "192.168.10.42"
    },
    "USER": {
      "USER_001": "jdoe"
    }
  },
  "stats": {
    "files_processed": 12,
    "bytes_processed": 87234566,
    "replacements_by_category": {
      "HOST": 1247,
      "IPV4": 89,
      "USER": 23
    }
  }
}
```

The mapping file does **not** contain any password, key, token, or other secret. Those are only ever redacted, never recorded.

**File permissions:** `_mapping.json` contains real internal hostnames, IPs, usernames, and other identifiers — it is the single most sensitive artifact the tool produces. Write it (and `_runlog.txt`, defensively, even though it should contain no real values per the implementer notes) with restrictive permissions: `0600` on Linux/macOS, and the equivalent owner-only ACL on Windows. Document in `docs/reversing.md` that the mapping file should be deleted or moved to encrypted storage at the end of the support case, consistent with the "ephemeral, per-case" non-goal around long-term mapping storage.

## Configuration file format

Optional `--config` flag accepts a YAML file:

```yaml
output: ./sanitized
hostlist: ./customer-hosts.txt
profiles: [sas94, tomcat, postgres-wipds]
audit: true
strict: false
verbose: true

# Per-detector overrides (advanced)
detectors:
  fqdn:
    extra_internal_tlds: [acmecorp, customerdomain]
  ipv4:
    skip_ranges: ["169.254.0.0/16"]   # link-local — usually noise
  allowlist:
    case_insensitive: true
```

## Testing strategy

Three layers, all run via `make test`:

### Unit tests
Each detector has its own `_test.go` file with a table-driven test:

```go
func TestIPv4Detector(t *testing.T) {
    cases := []struct {
        name     string
        input    string
        expected []Span  // expected match positions
    }{
        {"simple match", "Connected from 192.168.1.1", []Span{{15, 26}}},
        {"version string skip", "SAS 9.4.1.2 build", nil},
        {"loopback matches", "bind to 127.0.0.1", []Span{{8, 17}}},
        // ... at least 5 positive, 5 negative, 2 edge
    }
    // ...
}
```

### Golden file tests
`testdata/synthetic/<profile>/input.log` paired with `testdata/golden/<profile>/expected.log`. The test sanitizes input.log with a fixed allowlist and salt, then byte-compares against expected.log. Update goldens with `go test -update`.

Build at minimum 8 synthetic input files spanning every profile, plus one mixed-bundle directory simulating a real support bundle.

### Property tests
- **Idempotency:** sanitize(sanitize(input)) == sanitize(input)
- **Mapping completeness:** every original value detected appears as a key in the mapping file
- **No leakage:** for every original value detected in input, that value does not appear anywhere in the output (excluding the mapping file)
- **Reversibility:** reverse(sanitize(input)) == input (modulo redacted secrets, which are not reversible by design)

## Application logging (runlog)

The tool maintains its own structured log written to `_runlog.txt` in the output directory. Format: timestamped, one event per line, both human-readable and grep-friendly.

Events to log:
- Tool version, invocation arguments, working directory
- Files discovered, files skipped (with reason)
- Per-file: bytes read, encoding detected, line count, processing duration
- Per-category replacement counts after pass 1
- Audit findings counts by severity
- Total wall-clock time
- Any warnings or errors encountered

`--verbose` adds per-detector match counts per file.

## README requirements

The README must include:

- One-paragraph project description and intended audience
- Quick-start example with a real-looking command line
- Installation: `go install`, plus binary download instructions once releases exist
- Usage examples for the three primary modes (sanitize, reverse, audit-only)
- Explanation of the mapping file and warnings about its sensitivity
- Explanation of the allowlist file format and when to use it
- Limitations section (no streaming, no archives, no AIX, etc. — be honest)
- Pointer to `docs/` for deeper material
- License notice
- Contributing notes (link to `docs/adding-detectors.md`)

## License

Use the license your company's GitLab requires. If unsure, ask before committing. Commonly Apache 2.0 or MIT for internal tools. Include a `LICENSE` file at the repo root regardless.

## Build and tooling

`Makefile` targets:

```
make build      # build for current platform
make test       # run all tests
make lint       # go vet + staticcheck if installed
make cross      # build linux-amd64, windows-amd64, darwin-arm64 in dist/
make clean      # remove dist/ and test artifacts
make install    # go install
```

Use Go 1.22 or later. Pin via `go.mod`. Standard library first; only add dependencies for genuinely needed functionality (YAML parsing, possibly a CLI flag library like spf13/cobra if the flag set grows).

## Implementation milestones

A suggested order of work for Claude Code. Each milestone should end with passing tests and a working binary.

### Milestone 1: skeleton and IO foundation
- Project structure as specified
- `go.mod`, basic `main.go`, `Makefile`
- IO layer: encoding detection, line reader with large buffer, line writer preserving encoding/line endings, binary file detection
- Unit tests for IO layer including UTF-16 LE files with BOMs
- A `--version` flag works end-to-end

### Milestone 2: detector framework
- `Detector` interface, `Span` type, `LineState` with overlap detection
- Token registry (`internal/tokenize`)
- Two-pass pipeline scaffolding (no real detectors yet, just the orchestration)
- Unit tests for `LineState` overlap behavior

### Milestone 3: core network detectors
- IPv4, IPv6, FQDN, URL, MAC, UUID detectors with full tests
- TLD allowlist, version-string suppression
- Audit pass for these categories
- End-to-end test: a synthetic file with these elements is correctly sanitized

### Milestone 4: identity and credentials
- Email, DN, DOMAIN\user, Kerberos principal, path detectors
- Credentials and secrets detectors (full redaction path)
- Tests covering JDBC URLs with embedded passwords, SAS OPTIONS, JWTs, AWS keys

### Milestone 5: allowlist and customer integration
- Customer hostname allowlist loader
- Substring-matching detector running last
- Cross-detector consistency: hostname found by FQDN matches hostname found by allowlist matches hostname inside URL — all get the same token

### Milestone 6: audit pass and reverse mode
- Full audit scanner with severity reporting
- Reverse mode: read mapping, substitute back
- Tests for round-trip reversibility

### Milestone 7: profiles and CLI polish
- Built-in YAML profiles per log format
- Profile auto-detection (filename heuristics + first-line sniffing)
- Final CLI ergonomics: dry-run, strict mode, exit codes, runlog
- README, docs/, CHANGELOG, LICENSE

### Milestone 8: cross-platform and release
- `make cross` produces three binaries
- Manual smoke test on Windows (encoding edge cases) and Linux
- Tag v0.1.0

## Notes for the implementer

- Do not import any regex library other than the standard `regexp` package. Go's RE2-based regex is fast and safe (no catastrophic backtracking). If a detector needs PCRE features, restructure rather than reach for a different engine.
- Be conservative about adding dependencies. `gopkg.in/yaml.v3` for config, possibly `spf13/cobra` for the CLI, possibly `fatih/color` for terminal colors. Resist anything else without strong justification.
- Comment generously, especially in the detector files. The reader of this code will be a support engineer, not a Go expert. Explain *why* a regex looks the way it does, not just *what* it does.
- Every public function in `pkg/sanitize` needs a godoc comment.
- Do not log original PII values to the runlog. Log counts, file paths, and tokens — never the values being protected.
- Keep error messages user-friendly. Wrap underlying errors with context: `fmt.Errorf("reading %s: %w", path, err)`.
- The mapping file is sensitive. The runlog is not. Make sure no real values leak from the mapping file into the runlog or stdout.
