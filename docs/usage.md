# Usage guide

## Sanitize mode (default)

```sh
sas-log-sanitize -i /path/to/log-bundle -o /path/to/output
sas-log-sanitize -i /path/to/single.log -o /path/to/output
```

`input` may be a directory (walked recursively, alphabetically by output
path -- this matters: token numbering depends on file processing order being
deterministic), a single file, or a `.zip`/`.tar`/`.tar.gz`/`.tgz` bundle.
Archives (as the input or anywhere inside it) are extracted to a private
temporary directory and their files written under a folder named after the
archive (`bundle.zip` -> `<output>/bundle/...`). Unsafe entries (absolute or
`..` paths, symlinks) and archives inside archives are skipped and listed.
Rotated `*.gz` logs are read decompressed and written back gzipped under the
same name. For each file:

1. Skipped if its extension is in the binary-extension allowlist, or if its
   content looks binary (>30% non-printable bytes in the first 512 bytes).
   Skipped files are listed at the top of `_summary.txt` and printed at the
   end of the run.
2. Otherwise, encoding is detected from the first 64 KB (UTF-8 BOM, UTF-16
   LE/BE BOM, or no BOM -- assumed UTF-8, falling back to Windows-1252 only
   if the sample isn't valid UTF-8). Files are streamed, so memory doesn't
   grow with file size.
3. Pass 1 scans every line and registers every detected, non-secret value in
   the token registry.
4. Pass 2 replaces every detected value with its token and writes the
   sanitized file to the output directory, preserving the original relative
   path, encoding, and line-ending style (CRLF/LF).

Both passes run files -- and chunks of each large file -- in parallel
(`--workers`, default one per CPU), with results combined in input order, so
output and token numbering are identical for any worker count. Progress
(files, MB, MB/s, ETA) is printed to stderr unless `-q` is given.

After both passes: the audit report (`_audit.txt`, if `--audit` is on), a
per-category replacement summary (`_summary.txt`, plus the same data as
`_summary.json` for other tools: counts by category, skipped files with
reasons, audit counts by severity, and the exit status), and a runlog
(`_runlog.txt`) are written to the output directory.

URLs keep their scheme, port, path and parameter names; only the userinfo
and host are tokenized (`https://HOST_001:8343/SASLogon/login?ticket=SECRET_REDACTED`).
`--url-mode=whole` restores the old one-token-per-URL behavior.

HAR files (`*.har`, or `*.json` starting with a top-level `"log"` key) are
processed as JSON, streamed entry by entry so memory doesn't grow with file
size (`*.har.gz` too): credential headers (Authorization, Cookie, Set-Cookie,
CSRF/token headers) and cookie values are redacted whole, credential query
parameters are redacted, response bodies are dropped unless
`--keep-har-bodies` is given, and every other string goes through the normal
detectors. Timings, sizes, status codes, methods and header names are left
untouched, and the output is valid JSON. A HAR that doesn't parse falls back
to line-based sanitization (noted in the runlog). The mapping file is
written next to it, at `<output>.mapping.json` (override with `--mapping`;
a path inside the output directory is refused unless
`--allow-mapping-in-output` is passed).

Between the passes, every USER and HOST value found anywhere in the bundle
(plus each host's short name, e.g. `pghost01` for
`pghost01.corp.example.com`) is swept out of every line of every file in
Pass 2, with the same token -- so a value found once is gone everywhere.
Short values and common words are not swept.

Hostnames, Windows domains and email addresses are case-insensitive:
`SASMID01.corp.example.com` and `sasmid01.corp.example.com` share one token
(the mapping keeps the spelling seen first). Usernames stay case-sensitive.

Oracle thin JDBC URLs (`jdbc:oracle:thin:@host:1521:SID`,
`@//host:1521/service`, `user/password@host`) and TNS descriptors
(`(HOST=...)`) are recognized: the host is tokenized, the user pseudonymized
and the password redacted.

## Ignoring hostnames/domains

```sh
sas-log-sanitize -i /path/to/log-bundle -o /path/to/output --ignorelist ./ignored-hosts.txt
```

`--ignorelist` points to a file of hostnames/domains that should never be
tokenized or redacted, even if a detector would otherwise match them --
useful for a noisy but non-sensitive vendor domain that shows up constantly
in license-check or support-portal URLs. One entry per non-empty,
non-comment (`#`) line:

```
# exact hostname
license.example.com

# wildcard: matches sas.com itself and any subdomain (db1.sas.com, etc.)
*.sas.com
```

This is the inverse of `--hostlist`/`hostlist`, which *forces* a customer
hostname to always be tokenized, including inside compound strings.
`--ignorelist` is also honored by `--audit-only`, so re-auditing
already-sanitized output doesn't flag the intentionally-untouched
hostnames as residual PII.

## Reverse mode

```sh
sas-log-sanitize --reverse <mapping-file> <text-or-file>
```

If the second argument is a path to an existing, readable file, its contents
are used as the text to reverse; otherwise the argument itself is treated as
literal text. Every `CATEGORY_NNN` token found is replaced with its original
value from the mapping file; unknown tokens (typos, tokens from a different
run) and `SECRET_REDACTED` are left unchanged.

## Audit-only mode

```sh
sas-log-sanitize --audit-only [--mapping <mapping-file>] [--ignorelist ./ignored-hosts.txt] <sanitized-dir>
```

Re-scans every file in `<sanitized-dir>` (skipping the tool's own
`_mapping.json`/`_audit.txt`/`_summary.txt`/`_runlog.txt`) for patterns that
look like residual PII, without re-running sanitization. Useful for checking
output that was sanitized by an earlier run, or after manually editing
sanitized files.

With the run's mapping file (`--mapping`, or found automatically at
`<sanitized-dir>.mapping.json`), it also searches for every original value
the mapping holds; any hit is a High `known-original-value` finding, so the
run exits 1. Exit codes follow the sanitize rule: 1 for High findings, and
for any finding under `--strict`.

## Config file

`--config` accepts a YAML file as an alternative to passing flags:

```yaml
output: ./sanitized
hostlist: ./customer-hosts.txt
ignorelist: ./ignored-hosts.txt
profiles: [sas94, tomcat, postgres-wipds]
audit: true
strict: false
verbose: true

detectors:
  fqdn:
    extra_internal_tlds: [acmecorp, customerdomain]
  ipv4:
    skip_ranges: [10.0.0.0/8, 192.168.0.0/16]
    ip_class: false
  allowlist:
    case_insensitive: true
  url:
    mode: host
```

Flags passed explicitly on the command line always win over the config
file's values. Detector overrides:

- `detectors.ipv4.skip_ranges` — CIDR blocks whose IPv4 addresses are left
  untokenized (e.g. non-sensitive internal ranges). A malformed CIDR is a
  config error. The audit pass honors these too, so skipped addresses aren't
  flagged as residual PII (in `--audit-only`, pass the same `--config`).
- `detectors.allowlist.case_insensitive` — match `--hostlist` entries
  regardless of case. The token still records the exact text from the log,
  so reverse mode restores original casing.
- `detectors.ipv4.ip_class` — same as `--ip-class`.
- `detectors.url.mode` — same as `--url-mode` (`host` or `whole`).
- `detectors.fqdn.extra_internal_tlds` — additional pseudo-TLDs to treat as
  valid hostnames (e.g. a customer's internal `acmecorp` suffix), unioned
  with any extras contributed by the active profiles.

## Dry run

`--dry-run` runs both passes and computes accurate stats/findings, but
writes nothing to the output directory -- useful for previewing what a run
would do before committing to it.

## Profiling

`--cpuprofile <file>` writes a Go CPU profile of the run, for performance
work: `go tool pprof -top sas-log-sanitize <file>` lists where the time
went. It has no effect on output.
