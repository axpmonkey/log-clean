# Configuration file

Pass a YAML file with `--config` to save settings you'd otherwise repeat as
flags. Every key is optional.

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
    extra_internal_tlds: [acmecorp]
  ipv4:
    skip_ranges: [10.0.0.0/8, 192.168.0.0/16]
    ip_class: false
  allowlist:
    case_insensitive: true
  url:
    mode: host
```

**Precedence:** a flag you type on the command line always overrides the same
setting in the file.

## Keys

| Key | Type | Equivalent flag | Description |
|---|---|---|---|
| `output` | path | `--output` | Output directory. |
| `hostlist` | path | `--hostlist` | Hostnames to always tokenize. |
| `ignorelist` | path | `--ignorelist` | Hostnames and domains to never tokenize. |
| `profiles` | list | `--profiles` | Profile names. Leave it out to use all of them. |
| `audit` | bool | `--audit` | Run the audit pass. Defaults to `true`. |
| `strict` | bool | `--strict` | Exit `1` on Medium findings too. |
| `verbose` | bool | `--verbose` | More detail in `_runlog.txt`. |
| `detectors.fqdn.extra_internal_tlds` | list | *(config only)* | Extra suffixes to accept as hostname endings, such as a customer's internal `acmecorp`. Added to the suffixes contributed by the active profiles. |
| `detectors.ipv4.skip_ranges` | list of CIDRs | *(config only)* | IPv4 ranges to leave untokenized. The audit skips them too. A malformed CIDR is a configuration error (exit `4`). |
| `detectors.ipv4.ip_class` | bool | `--ip-class` | Use separate tokens for private and public IPv4 addresses. |
| `detectors.allowlist.case_insensitive` | bool | *(config only)* | Match hostlist entries in any case. |
| `detectors.url.mode` | `host` or `whole` | `--url-mode` | How URLs are replaced. |

## Profiles

Built-in profiles: `default`, `sas94`, `tomcat`, `apache`, `activemq`,
`geode`, `postgres-wipds`.

Profiles currently affect detection in **one** way: each profile can add
extra internal hostname suffixes (`extra_internal_tlds`) to the hostname
detector. The suffixes from every selected profile are combined and apply to
the whole run.

- `auto`, the default, selects every built-in profile.
- An unknown profile name is a configuration error (exit `4`).
- The profiles in effect are listed in `_runlog.txt`.

Each profile also defines file-name and first-line patterns for recognizing
log types. Those patterns don't yet select different detectors for each file.
