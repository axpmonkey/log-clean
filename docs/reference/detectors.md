# Detectors

All detectors live in `internal/detect`. Each implements the `Detector`
interface (`Name() string`, `Detect(line string) []Match`) and is run in the
fixed order defined by `pipeline.DefaultDetectorChain`. Detectors may also
implement `Prefilter` (`MightMatch(line string) bool`), a cheap check that
lets the pipeline skip them on lines that can't match; it must never reject
a line the detector would match.

| Detector | Category | Action | Notes |
|---|---|---|---|
| `UUIDDetector` | (none) | Claim-only | Never replaced; just blocks other detectors from matching inside a UUID. A UUID that is a credential's value (CSRF token, session cookie, `"access_token":"<uuid>"`) is *not* claimed, so the credential rules redact it. |
| `CredentialsDetector` | redact / `USER` / `HOST` | Redact values, pseudonymize usernames and hosts | See "Credential rules" below. |
| `SecretsDetector` | redact | Redact | AWS access keys and `aws_secret_access_key`, `api_key`/`token` values of 32+ chars, JWTs, Bearer tokens, GCP `private_key` JSON fields, SSH/PEM BEGIN/END marker lines. The multi-line key *body* between the markers is redacted by the file-level PEM block tracking in `pipeline` (a per-line detector can't see it). |
| `DNDetector` | `DN` | Pseudonymize | Whole LDAP DN tokenized as one unit. See "LDAP DNs" below. |
| `EmailDetector` | `EMAIL` | Pseudonymize | Case-insensitive token. |
| `URLDetector` | `HOST` + `USER` (host mode) / `URL` (whole mode) | Pseudonymize host and userinfo, or the whole URL | Default `--url-mode=host`: only userinfo (user -> `USER_NNN`, password -> `SECRET_REDACTED`) and host (`HOST_NNN`) are replaced; scheme, port, path and parameter names stay. IP hosts are left to the IPv4/IPv6 detectors; `localhost` is left alone. `--url-mode=whole`: one `URL_NNN` per URL, embedded host also registered into `HOST`. Schemes: http(s), ftp(s), sftp, `jdbc:<driver>`, tcp, ssl, nio, amqp(s), mqtt, ldap(s). |
| `FQDNDetector` | `HOST` | Pseudonymize | TLD-allowlist gated; `NewFQDNDetectorWithExtraTLDs` accepts profile-driven extras. JVM `-Dkey.name=` property keys are not hostnames. |
| `IPv4Detector` | `IPV4` (`IPV4_PRIV` / `IPV4_PUB` with `--ip-class`) | Pseudonymize | See "IPv4 and version strings" below. `detectors.ipv4.skip_ranges` leaves chosen ranges untouched. |
| `IPv6Detector` | `IPV6` | Pseudonymize | Candidate regex + `net/netip.ParseAddr` validation; zone suffixes (`%eth0`) included. |
| `MACDetector` | `MAC` | Pseudonymize | |
| `UNCDetector` | `UNC` | Pseudonymize whole value | Embedded server also registered into `HOST`. |
| `KerberosDetector` | `KRB` | Pseudonymize | Mostly catches bare (non-dotted) realms; dotted uppercase realms are usually claimed by `EmailDetector` first. |
| `DomainUserDetector` | `DOMAIN` + `USER` | Pseudonymize both parts | `DOMAIN\user` -> `DOMAIN_NNN\USER_NNN`. `DOMAIN` tokens are case-insensitive. |
| `BareUserDetector` | `USER` | Pseudonymize | `userid=`/`user=`/`username=`/`metaUser=`/`Authenticated user:` forms, and `uid=` when the value starts with a letter (numeric Unix uids such as `uid=1001(sas)` are left alone; a `uid=` inside a DN is part of the DN token). |
| `UnixUserPathDetector` | `USER` | Pseudonymize username portion only | `/home/`, `/Users/`, `/export/home/`. |
| `WindowsUserPathDetector` | `USER` | Pseudonymize username portion only | `C:\Users\`, `C:\Documents and Settings\`. |
| `AllowlistDetector` | `HOST` | Pseudonymize | Customer-supplied (`--hostlist`), literal substring matching. Only in the chain when a hostlist is given. |
| `KnownValuesDetector` | `USER` / `HOST` | Pseudonymize | Added for Pass 2 only, last in the chain: replaces every registered `USER`/`HOST` value (and each host's short name) wherever it appears. See architecture.md, "Cross-detector consistency". |

### SAS internal accounts

The SAS 9.4 internal accounts `sasadm@saspw`, `sastrust@saspw`,
`sasevs@saspw` and `webanon@saspw` are never pseudonymized: they are the
same at every site, identify no person, and show which identity a server
connected as. The exemption applies only to the `<name>@saspw` form
(case-insensitive), whichever detector finds it, including the known-values
sweep. The same name elsewhere (`/home/sastrust/`, `user=sastrust`) is
still tokenized, and other `@saspw` accounts (`jsmith@saspw`) are still
masked. The list is `sasInternalAccounts` in
`internal/detect/knownvalues.go`.

## Credential rules

`CredentialsDetector` redacts only the value, never the key
(`password=SECRET_REDACTED`). Its rules, in the order they claim spans:

1. **HTTP `Authorization` / `Proxy-Authorization`** -- header form, JSON
   `"Authorization": "..."`, and HAR `{"name":"Authorization","value":...}`.
   The scheme (`Basic`, `Negotiate`, `NTLM`, `Digest`, `Bearer`, ...) is
   kept; the rest of the value is redacted.
2. **Cookies** -- `Cookie:` (every value) and `Set-Cookie:` (the first
   pair's value; attributes like `Path=` stay), in the same three forms.
   Cookie names are kept.
3. **Custom credential headers** -- `X-CSRF-Token:`, `X-XSRF-TOKEN:`,
   `X-Auth-Token:`, `x-api-key:`, `X-Session-Id:` and similar.
4. **`jsessionid=`** anywhere, including the `;jsessionid=` URL path
   parameter.
5. **SAS-encoded passwords** -- `{SAS001}`..`{SAS009}`, `{SASENC}`,
   `{AES}`, `{AES256}` values are reversible, so the whole encoded value,
   prefix included, is redacted whatever key precedes it.
6. **Query-string / form / JSON credential parameters** -- values of
   `ticket`, `access_token`, `id_token`, `refresh_token`, `SAMLRequest`,
   `SAMLResponse`, `RelayState`, `client_secret`, `password`, `pwd`,
   `sessionid`, `jsessionid` anywhere as `name=value`; `code`, `state` and
   `token` only after `?`, `&` or `;` (so `job state=RUNNING` and `exit
   code=0` survive); HAR `{"name":...,"value":...}` pairs and JSON
   `"access_token": "..."`-style keys. Each value is redacted separately and
   stops at `&`, so later parameters (`&redirect_uri=/SASDrive`) are kept.
   Standalone CAS tickets (`ST-`, `PT-`, `TGT-`, `PGT-`) are redacted too.
7. **`key=value` forms** -- `password=`, `pwd=`, `secret=`, `pass:`,
   SAS `OPTIONS ... METAPASS=`, LDAP `bind password=`, and a catch-all for
   keys containing `pass`/`secret`/`apikey`/`token`/`credential`.
8. **SAS `OPTIONS ... METAUSER=`** -- pseudonymized as `USER`.
9. **Oracle JDBC** -- thin URLs (`jdbc:oracle:thin:@host:1521:SID`,
   `@//host:1521/service`, `user/password@host`) and TNS descriptors
   (`(HOST=...)`): user -> `USER`, password redacted, host -> `HOST` (an IP
   host is left to the IPv4 detector). These have no `://`, so the URL
   detector never sees them.
10. **JDBC / ActiveMQ `user:password@host`** -- user pseudonymized, password
    redacted; a bare (non-dotted) host is tokenized as `HOST` here, a dotted
    host or IP is left for the FQDN/IPv4 detectors.

Each rule is gated on a keyword its pattern requires, so most lines skip
most regexes.

## IPv4 and version strings

A dotted quad is treated as a version string, and left alone, only when all
of these hold: a version keyword (`v`, `version`, `release`, `sas`) is the
*immediately* preceding token (`SAS 9.4.8.0`, `version: 1.2.3.4`); it is not
followed by `:<port>`; and it is not in a private range (10/8, 172.16/12,
192.168/16). So `Connecting to SAS server at 10.20.30.40`,
`SAS Metadata 10.20.30.41:8561` and `release 10.20.30.42 is the gateway` are
all tokenized. The audit pass shares this rule (`LooksLikeVersionString`).

With `--ip-class`, private, loopback (127/8), link-local (169.254/16) and
CGNAT (100.64/10) addresses become `IPV4_PRIV_NNN` and the rest
`IPV4_PUB_NNN`.

## LDAP DNs

A DN is two or more `ATTR=value` components joined by commas; the first and
last attribute must be a well-known one (`CN`, `OU`, `DC`, `UID`, `O`, `L`,
`ST`, `C`), inner ones may be any attribute (`mail=`, `SN=`, ...). Inner
values run to the next unescaped comma, so they may contain spaces, periods,
hyphens and apostrophes (`CN=Jane Q. Smith`, `CN=Mary-Ann O'Brien`);
`\,` escapes are part of the value (`CN=Doe\, John`). The final value stops
at whitespace or a terminator (`" ' ( ) [ ] < >`), except that a name-like
final attribute (`CN`, `OU`, `O`, `L`, `ST`) runs on over following words
when they end at a terminator or end of line (`...,OU=Sales Team`); text
containing `:`, `=` or `,` (`rc=49`, timestamps) is never pulled in.

## Known limitations (see also README)

- Kerberos principals with a dotted, uppercase realm are usually classified
  as `EMAIL` rather than `KRB` (still safely tokenized, just a different
  category).
- A DN whose final name-like component runs to end of line takes any
  trailing name-like words with it (`...,OU=Users logged in` becomes one
  token): over-redaction, chosen over leaking the second word of
  `OU=Sales Team`.
- A non-private dotted quad right after a version keyword is assumed to be a
  version; a private-range one is always treated as an address, so a version
  like `release 10.2.0.1` is tokenized (over-redaction, the safe direction).
- An `Authorization:` header in log *prose* (`Authorization: access
  denied`) has everything after its first word redacted.
- UUIDs that are ordinary identifiers stay in the output (by design, for
  correlation). A secret UUID is only redacted when it appears in a
  credential context the rules above recognize.
- Generic account names (`admin`, `root`, `sas`, `test`, ...) are not swept
  across the bundle; they are only replaced where a detector matches them.
- A host that only ever appears as a bare short name (never with its full
  name) needs the allowlist (`--hostlist`).
