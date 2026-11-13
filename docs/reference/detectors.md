# Detectors

Detectors find the values to replace. They run on every line in a fixed order.
Once a detector claims part of a line, later detectors can't match anything
that overlaps it. This page lists what each detector catches, in the order
they run, and the trade-offs each one makes.

For how the ordering and claiming work internally, see
[Architecture](../architecture.md#span-claiming).

## Detector list

| # | Detector | Produces | Catches |
|---|---|---|---|
| 1 | UUID | *(nothing)* | UUIDs. They're claimed so nothing matches inside them, but left unchanged so they're still useful for correlation. A UUID that is a credential's value (a CSRF token, a session cookie, `"access_token":"<uuid>"`) isn't claimed, so the credential rules can redact it. |
| 2 | Credentials | `SECRET_REDACTED`, `USER`, `HOST` | Passwords, auth headers, cookies, session IDs, SAS-encoded passwords, JDBC credentials. See [Credential rules](#credential-rules). |
| 3 | Secrets | `SECRET_REDACTED` | AWS access keys and secret keys, `api_key`/`token` values of 32 or more characters, JWTs, Bearer tokens, GCP `private_key` fields, and SSH/PEM key blocks, including the body lines between `BEGIN` and `END`. |
| 4 | LDAP DN | `DN` | Whole distinguished names. See [LDAP DNs](#ldap-dns). |
| 5 | Email | `EMAIL` | Email addresses, matched regardless of case. |
| 6 | URL | `HOST`, `USER`, `SECRET_REDACTED`, or `URL` | See [URLs](#urls). |
| 7 | Hostname | `HOST` | Fully qualified names ending in a known top-level domain or an [extra internal TLD](config.md#keys). JVM `-Dkey.name=` property names are ignored. |
| 8 | IPv4 | `IPV4` (`IPV4_PRIV`/`IPV4_PUB`) | Dotted quads, except version strings. See [IPv4 addresses and version strings](#ipv4-addresses-and-version-strings). |
| 9 | IPv6 | `IPV6` | Valid IPv6 addresses, including zone suffixes (`%eth0`). |
| 10 | MAC | `MAC` | MAC addresses. |
| 11 | UNC path | `UNC` | `\\server\share\...` as one token. The server name also gets a `HOST` token. |
| 12 | Kerberos | `KRB` | Realms without dots. Dotted uppercase realms are usually caught by the email detector first. |
| 13 | Domain user | `DOMAIN`, `USER` | `CORP\jdoe` → `DOMAIN_001\USER_001`. Domains are matched regardless of case. |
| 14 | Bare user | `USER` | `user=`, `userid=`, `username=`, `metaUser=`, `Authenticated user:`, and `uid=` when the value starts with a letter. Numeric uids such as `uid=1001(sas)` are left alone. |
| 15 | Unix home path | `USER` | The username in `/home/<user>`, `/Users/<user>`, and `/export/home/<user>`. |
| 16 | Windows profile path | `USER` | The username in `C:\Users\<user>` and `C:\Documents and Settings\<user>`. |
| 17 | Hostlist | `HOST` | Entries from `--hostlist`, matched as literal substrings. Runs only when a hostlist is given. |
| 18 | Known-values sweep | `USER`, `HOST` | Every username and hostname found anywhere in the bundle, plus each host's short name, replaced wherever it appears. See [Known-values sweep](#known-values-sweep). |

Hostnames, domains, and email addresses are matched regardless of case.
`SASMID01.corp.example.com` and `sasmid01.corp.example.com` share one token, and
the mapping file keeps the spelling that was seen first. Usernames are
case-sensitive, as they are on Unix.

## Credential rules

The credentials detector redacts the **value** and keeps the key
(`password=SECRET_REDACTED`), so the log line still makes sense. Its rules run
in this order:

1. **`Authorization` and `Proxy-Authorization`.** This covers the header form,
   JSON form, and HAR form. The scheme (`Basic`, `Negotiate`, `NTLM`, `Bearer`,
   and so on) is kept, and everything after it is redacted.
2. **Cookies.** For `Cookie:`, every value is redacted. For `Set-Cookie:`, the
   first value is redacted and attributes such as `Path=` are kept. Cookie
   names are kept.
3. **Credential headers.** `X-CSRF-Token`, `X-XSRF-TOKEN`, `X-Auth-Token`,
   `x-api-key`, `X-Session-Id`, and similar headers.
4. **`jsessionid=`** anywhere, including the `;jsessionid=` URL path parameter.
5. **SAS-encoded passwords.** `{SAS001}` to `{SAS009}`, `{SASENC}`, `{AES}`,
   and `{AES256}` values can be decoded, so the whole value, prefix included,
   is redacted after any key.
6. **Credential parameters** in query strings, forms, and JSON:
   - `ticket`, `access_token`, `id_token`, `refresh_token`, `SAMLRequest`,
     `SAMLResponse`, `RelayState`, `client_secret`, `password`, `pwd`,
     `sessionid`, and `jsessionid`, wherever they appear as `name=value`.
   - `code`, `state`, and `token`, but only after `?`, `&`, or `;`. This
     means `job state=RUNNING` and `exit code=0` are left alone.
   - Each value is redacted up to the next `&`, so later parameters such as
     `&redirect_uri=/SASDrive` survive.
   - Standalone CAS tickets (`ST-…`, `PT-…`, `TGT-…`, `PGT-…`) are redacted too.
7. **`key=value` forms.** `password=`, `pwd=`, `secret=`, `pass:`,
   `METAPASS=`, LDAP `bind password=`, and any key containing `pass`, `secret`,
   `apikey`, `token`, or `credential`.
8. **`METAUSER=`** values become `USER` tokens.
9. **Oracle JDBC.** Thin URLs (`@host:1521:SID`, `@//host:1521/service`,
   `user/password@host`) and TNS descriptors (`(HOST=…)`). The user becomes
   `USER`, the password is redacted, and the host becomes `HOST`.
10. **`user:password@host`** in JDBC and ActiveMQ strings. The user becomes
    `USER` and the password is redacted. A host without dots becomes `HOST`
    here. Dotted hosts and IP addresses are left to later detectors.

## SAS internal accounts

`sasadm@saspw`, `sastrust@saspw`, `sasevs@saspw`, and `webanon@saspw` are
**never** tokenized. They're the same at every site, identify no person, and
show which identity a server connected as.

The exemption applies only to the exact `<name>@saspw` form, in any case. The
same name in another form (`/home/sastrust/`, `user=sastrust`) is still
tokenized, and other `@saspw` accounts (`jsmith@saspw`) are still masked.

## URLs

Supported schemes: `http(s)`, `ftp(s)`, `sftp`, `jdbc:<driver>`, `tcp`, `ssl`,
`nio`, `amqp(s)`, `mqtt`, and `ldap(s)`.

Input: `BalancerMember http://sasmid01.corp.example.com:8080/SASStudio route=1`

| Mode | Output |
|---|---|
| `--url-mode host` (default) | `BalancerMember http://HOST_001:8080/SASStudio route=1` |
| `--url-mode whole` | `BalancerMember URL_001 route=1` |

In `host` mode, only the user information and host are replaced. The username
becomes `USER`, any password is redacted, and the host becomes `HOST`. IP
hosts are left to the IP detectors, and `localhost` is kept. In `whole` mode,
the host is still registered as a `HOST`, so it gets the same token everywhere
else in the bundle.

A URL with a credential parameter, such as `?ticket=`, is never replaced
whole, even in `whole` mode. The credential rule redacts the parameter
first, and the host is then tokenized on its own:
`https://HOST_001:8343/SASLogon/login?ticket=SECRET_REDACTED&service=x`.

## IPv4 addresses and version strings

A dotted quad is treated as a **version** and kept only when all of these are
true:

- a version keyword (`v`, `version`, `release`, or `sas`) comes *immediately*
  before it, as in `SAS 9.4.8.0` or `version: 1.2.3.4`;
- no `:<port>` follows it;
- it isn't in a private range (10/8, 172.16/12, 192.168/16).

Everything else is treated as an address:

```text
Connecting to SAS server at 10.20.30.40 failed   →  Connecting to SAS server at IPV4_001 failed
SAS Metadata 10.20.30.41:8561 refused            →  SAS Metadata IPV4_002:8561 refused
SAS 9.4.8.0 (TS1M8) starting                     →  SAS 9.4.8.0 (TS1M8) starting
```

With `--ip-class`, private, loopback (127/8), link-local (169.254/16), and
CGNAT (100.64/10) addresses become `IPV4_PRIV_NNN`, and all others become
`IPV4_PUB_NNN`.

## LDAP DNs

A DN is two or more `ATTR=value` parts separated by commas. The first and last
attributes must be one of `CN`, `OU`, `DC`, `UID`, `O`, `L`, `ST`, or `C`.
Attributes in between can be anything.

- Values can contain spaces, periods, hyphens, and apostrophes:
  `CN=Jane Q. Smith`, `CN=Mary-Ann O'Brien`.
- Escaped commas are part of the value: `CN=Doe\, John`.
- The final value stops at whitespace or one of these characters:
  `" ' ( ) [ ] < >`. One exception: when the final attribute is `CN`, `OU`,
  `O`, `L`, or `ST`, the value continues over the following words if they run
  to one of those characters or to the end of the line (`…,OU=Sales Team`).
  Text containing `:`, `=`, or `,` is never pulled in.

## Known-values sweep

After the first pass, every `USER` and `HOST` value found anywhere is replaced
everywhere in the second pass, as a whole word and regardless of case. This
includes lines where no detector would have matched it. For example, after
`/home/jdoe/` is seen, `user jdoe logged in` becomes `user USER_001 logged in`.

A host's short name gets the full name's token: `pghost01` becomes the token
of `pghost01.corp.example.com`, so reverse mode returns the full name.

These values are **not** swept:

- usernames shorter than 3 characters, and host short names shorter than 4;
- purely numeric values;
- common words and generic account names (`admin`, `root`, `sas`, `test`, …);
- short names taken from two-part domains. In `acme.com`, `acme` is the
  organization, not a host.

## Known limitations

These cases are documented trade-offs. Where the tool must choose, it prefers
replacing too much over leaking.

| Case | Behavior | Direction |
|---|---|---|
| Kerberos principal with a dotted uppercase realm | Tokenized as `EMAIL`, not `KRB` | Safe (wrong category only) |
| `user@host` in a URL with no password (`ldaps://svc@dc01.example.com`) | The user and host together become one `EMAIL` token | Safe (wrong category only) |
| DN whose last name-like part runs to the end of the line | Trailing words are included (`…,OU=Users logged in` becomes one token) | Over-redaction |
| Version-like dotted quad in a private range (`release 10.2.0.1`) | Tokenized as an address | Over-redaction |
| `Authorization:` in log text (`Authorization: access denied`) | Everything after the first word is redacted | Over-redaction |
| An ordinary UUID | Kept, for correlation. A UUID is redacted only in a recognized credential context. | By design |
| A generic account name (`admin`, `root`, `sas`) | Replaced only where a detector recognizes it, not swept everywhere | By design |
| A host that only ever appears as a short name | Missed unless it's in the hostlist | Possible leak. Use `--hostlist`. |
| A value split across wrapped lines | May be missed | Possible leak. The audit is the backstop. |
