# Troubleshooting

## The run exited with a non-zero code

| Code | Meaning | What to do |
|---|---|---|
| `1` | The audit found High findings, or any findings with `--strict`. The output **was** written. | Read `_audit.txt`. See [Check the audit](../getting-started.md#3-check-the-audit). |
| `2` | Input error: a path doesn't exist or can't be read. This includes the hostlist and ignorelist. | Check the paths in the error message. |
| `3` | Processing error while reading, extracting, or writing. | Check disk space and permissions. Run again with `-v` and read `_runlog.txt`. |
| `4` | Configuration error: a bad flag value, an unknown profile, a malformed CIDR or YAML, or a mapping path inside the output folder. | Fix the setting the error names. |

## A value was left in the output

Work through these in order.

1. **Was the file processed at all?** Check the skipped list at the top of
   `_summary.txt`. Binary-looking files and archives nested inside other
   archives are skipped.
2. **Is it a hostname with no dots?** Short names are replaced only if their
   full name appears somewhere in the bundle. Otherwise, add the name to a
   [hostlist](tune-detection.md#always-tokenize-a-hostname).
3. **Is it a hostname with an unusual suffix?** Add the suffix as an
   [extra internal TLD](tune-detection.md#recognize-a-private-domain-suffix).
4. **Is it a generic account name** such as `admin`, `root`, `sas`, or `test`?
   These are replaced only where a detector recognizes them in context, not
   everywhere in the bundle. This is by design.
5. **Is it a SAS internal account** (`sasadm@saspw`, `sastrust@saspw`,
   `sasevs@saspw`, `webanon@saspw`)? These are kept on purpose. See
   [Detectors](../reference/detectors.md#sas-internal-accounts).
6. **Is it split across two wrapped lines?** Wrapped lines aren't joined.
   Fix the line by hand, then re-check with `--audit-only`.

If none of these explain it, please report it as a detector bug with a
redacted sample line.

## Something was replaced that shouldn't have been

- **A vendor or public domain:** add it to an
  [ignorelist](tune-detection.md#never-tokenize-a-hostname-or-domain).
- **A non-sensitive IP range:** use
  [`skip_ranges`](tune-detection.md#leave-ip-ranges-readable).
- **A version number that looks like an IP address** (`release 10.2.0.1`):
  dotted quads in private ranges are always treated as addresses. This
  over-redaction is deliberate.
- **Text after `Authorization:` in a log message:** everything after the first
  word is redacted. This is also deliberate.

## The audit lists many Medium findings

Medium rules are deliberately broad, because missing a leak is worse than an
extra warning. They flag words such as `java8` or `server01`. Medium findings
don't affect the exit code unless you pass `--strict`. Skim the list for real
hostnames and ignore the rest.

## The download is blocked

Release files are served from `objects.githubusercontent.com`. If a corporate
proxy blocks that host, [build from source](../../CONTRIBUTING.md#build).

## A large bundle is slow or uses a lot of disk

- Both passes use one worker per CPU by default. `--workers` lowers that.
  Output is identical for any worker count.
- Archives are extracted to a temporary folder, up to 20 GiB in total.
  `--max-extract-mb` changes the limit.
- Memory grows with the number of *distinct* values found, not with file size.
