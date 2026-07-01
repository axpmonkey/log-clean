# Usage guide

## Sanitize mode (default)

```sh
sas-log-sanitize -i /path/to/log-bundle -o /path/to/output
sas-log-sanitize -i /path/to/single.log -o /path/to/output
```

`input` may be a directory (walked recursively, alphabetically by path --
this matters: token numbering depends on file processing order being
deterministic) or a single file. For each file:

1. Skipped if its extension is in the binary-extension allowlist, or if its
   content looks binary (>30% non-printable bytes in the first 512 bytes).
2. Otherwise, encoding is detected (UTF-8 BOM, UTF-16 LE/BE BOM, or no BOM --
   assumed UTF-8, falling back to Windows-1252 only if the content isn't
   valid UTF-8).
3. Pass 1 scans every line and registers every detected, non-secret value in
   the token registry.
4. Pass 2 replaces every detected value with its token and writes the
   sanitized file to the output directory, preserving the original relative
   path, encoding, and line-ending style (CRLF/LF).

After both passes: the mapping file (`_mapping.json`), audit report
(`_audit.txt`, if `--audit` is on), a per-category replacement summary
(`_summary.txt`), and a runlog (`_runlog.txt`) are written to the output
directory.

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
sas-log-sanitize --audit-only <sanitized-dir> [--ignorelist ./ignored-hosts.txt]
```

Re-scans every file in `<sanitized-dir>` (skipping the tool's own
`_mapping.json`/`_audit.txt`/`_summary.txt`/`_runlog.txt`) for patterns that
look like residual PII, without re-running sanitization. Useful for checking
output that was sanitized by an earlier run, or after manually editing
sanitized files.

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
```

Flags passed explicitly on the command line always win over the config
file's values. Note: `detectors.ipv4.skip_ranges` and
`detectors.allowlist.case_insensitive` are parsed (so a config file
containing them won't error) but are not yet applied to detector behavior --
only `detectors.fqdn.extra_internal_tlds` is wired through.

## Dry run

`--dry-run` runs both passes and computes accurate stats/findings, but
writes nothing to the output directory -- useful for previewing what a run
would do before committing to it.
