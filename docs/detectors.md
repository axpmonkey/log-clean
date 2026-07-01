# Detectors

All detectors live in `internal/detect`. Each implements the `Detector`
interface (`Name() string`, `Detect(line string) []Match`) and is run in the
fixed order defined by `pipeline.DefaultDetectorChain`.

| Detector | Category | Action | Notes |
|---|---|---|---|
| `UUIDDetector` | (none) | Claim-only | Never replaced; just blocks other detectors from matching inside a UUID. |
| `CredentialsDetector` | `USER` (for embedded usernames) / redact | Redact values, pseudonymize usernames | Password/pwd/secret key=value forms, SAS `OPTIONS METAUSER`/`METAPASS`, JDBC/ActiveMQ embedded creds, LDAP bind passwords. See known JDBC/bare-host limitation in its doc comment. |
| `SecretsDetector` | redact | Redact | AWS keys, JWTs, Bearer tokens, GCP private_key JSON fields, SSH/PEM BEGIN/END marker lines. The multi-line key *body* between the markers is redacted separately by the file-level PEM block redactor in `pipeline.Run` (a per-line detector can't see it). |
| `DNDetector` | `DN` | Pseudonymize | Whole LDAP DN tokenized as one unit. |
| `EmailDetector` | `EMAIL` | Pseudonymize | |
| `URLDetector` | `URL` | Pseudonymize whole value | Embedded host cross-registered into `HOST` (see architecture.md). |
| `FQDNDetector` | `HOST` | Pseudonymize | TLD-allowlist gated; `NewFQDNDetectorWithExtraTLDs` accepts profile-driven extras. |
| `IPv4Detector` | `IPV4` | Pseudonymize | Version-string context suppressed (shared with the audit pass via `LooksLikeVersionString`). |
| `IPv6Detector` | `IPV6` | Pseudonymize | Candidate regex + `net/netip.ParseAddr` validation. |
| `MACDetector` | `MAC` | Pseudonymize | |
| `UNCDetector` | `UNC` | Pseudonymize whole value | Embedded server cross-registered into `HOST`. |
| `KerberosDetector` | `KRB` | Pseudonymize | Mostly catches bare (non-dotted) realms; dotted uppercase realms are usually claimed by `EmailDetector` first. |
| `DomainUserDetector` | `DOMAIN` + `USER` | Pseudonymize both parts | `DOMAIN\user` -> `DOMAIN_NNN\USER_NNN`. |
| `BareUserDetector` | `USER` | Pseudonymize | `userid=`/`user=`/`username=`/`metaUser=`/`Authenticated user:` forms. |
| `UnixUserPathDetector` | `USER` | Pseudonymize username portion only | `/home/`, `/Users/`, `/export/home/`. |
| `WindowsUserPathDetector` | `USER` | Pseudonymize username portion only | `C:\Users\`, `C:\Documents and Settings\`. |
| `AllowlistDetector` | `HOST` | Pseudonymize | Customer-supplied, literal substring matching, runs last. |

## Known limitations (see also README)

- Kerberos principals with a dotted, uppercase realm are usually classified
  as `EMAIL` rather than `KRB` (still safely tokenized, just a different
  category).
