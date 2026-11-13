# Tune detection

The defaults work for most SAS 9.4 bundles. Use this guide when the tool
misses a value or replaces one you need to keep readable.

| Problem | Fix |
|---|---|
| A hostname without dots (`sasapp01`) is left in the output | [Hostlist](#always-tokenize-a-hostname) |
| A hostname embedded in a longer string (`/var/log/db-prod-01-archive/`) is left in | [Hostlist](#always-tokenize-a-hostname) |
| A non-sensitive vendor domain is replaced everywhere and makes logs hard to read | [Ignorelist](#never-tokenize-a-hostname-or-domain) |
| Internal hosts use a private suffix (`app01.acmecorp`) that isn't recognized | [Extra internal TLDs](#recognize-a-private-domain-suffix) |
| You need to tell internal IP addresses from external ones | [`--ip-class`](#keep-internal-and-external-ips-distinguishable) |
| Some IP ranges aren't sensitive and should stay readable | [`skip_ranges`](#leave-ip-ranges-readable) |
| You want each URL replaced as a single token | [`--url-mode whole`](#replace-whole-urls) |

## Always tokenize a hostname

Most hostnames are caught without help. A fully qualified name such as
`sasapp01.corp.example.com` is detected, and once it's found, its short name
(`sasapp01`) is replaced everywhere too. A host that *only* ever appears in
short form, or only inside a longer string, needs a **hostlist**.

1. Create a text file with one hostname per line. Lines starting with `#` are
   comments.

   ```text
   # customer-hosts.txt
   sasapp01
   db-prod-01
   ```

2. Pass it with `--hostlist`:

   ```sh
   sas-log-sanitize -i case-12345 -o case-12345-clean --hostlist customer-hosts.txt
   ```

> [!IMPORTANT]
> Hostlist entries match as **literal substrings**, not whole words. `db1`
> also matches inside `db10` and `adb1x`. Use distinctive names. The tool warns
> on stderr about entries shorter than four characters, and about entries that
> are substrings of other entries.

Hostlist matching is case-sensitive. However, once an entry has been found
anywhere in the bundle, the known-values sweep replaces it in any case wherever
it stands as a whole word. So `SASAPP01` is caught after `sasapp01` has been
seen. To also catch other casings *inside* longer strings, set
`detectors.allowlist.case_insensitive: true` in a
[config file](../reference/config.md). The mapping file records the exact text
from the log, so reverse mode restores the original casing.

## Never tokenize a hostname or domain

An **ignorelist** is the opposite of a hostlist. It names hosts and domains to
leave alone even when a detector matches them. It's useful for vendor domains
that show up constantly in license-check or support-portal URLs.

```text
# ignored-hosts.txt

# An exact hostname, matched regardless of case
license.example.com

# A wildcard: matches sas.com and every subdomain of it
*.sas.com
```

```sh
sas-log-sanitize -i case-12345 -o case-12345-clean --ignorelist ignored-hosts.txt
```

When you re-audit later with `--audit-only`, pass the same `--ignorelist`.
Otherwise the audit reports the hosts you deliberately kept.

## Recognize a private domain suffix

Hostnames are detected only when they end in a known top-level domain. If the
customer uses a private suffix such as `.acmecorp`, add it in a config file:

```yaml
detectors:
  fqdn:
    extra_internal_tlds: [acmecorp]
```

## Keep internal and external IPs distinguishable

By default every IPv4 address becomes `IPV4_NNN`. With `--ip-class`, private,
loopback, link-local, and CGNAT addresses become `IPV4_PRIV_NNN` and all
others become `IPV4_PUB_NNN`. The assistant can then tell an internal hop from
an internet-facing one.

```sh
sas-log-sanitize -i case-12345 -o case-12345-clean --ip-class
```

## Leave IP ranges readable

To keep addresses in some ranges untouched, list the CIDR blocks in a config
file:

```yaml
detectors:
  ipv4:
    skip_ranges: [10.0.0.0/8, 192.168.0.0/16]
```

The audit pass skips these ranges too. When you re-audit with `--audit-only`,
pass the same `--config`.

## Replace whole URLs

By default only a URL's host and user information are replaced. The scheme,
port, path, and parameter names stay readable:

```text
https://HOST_001:8343/SASLogon/login?ticket=SECRET_REDACTED&service=x
```

If the paths themselves are sensitive, replace each URL with a single token:

```sh
sas-log-sanitize -i case-12345 -o case-12345-clean --url-mode whole
```

```text
BalancerMember http://HOST_001:8080/SASStudio route=1   (host, the default)
BalancerMember URL_001 route=1                          (whole)
```

The host inside the URL still gets its own `HOST` token, so it matches the
same host elsewhere in the bundle. A URL with a credential parameter, such as
`?ticket=`, isn't replaced whole. Its credential is redacted and its host is
tokenized, as in `host` mode. See [URLs](../reference/detectors.md#urls).

## Save your settings

Once you've settled on a combination, put it in a config file and pass
`--config` instead of repeating flags. See
[Configuration file](../reference/config.md).
