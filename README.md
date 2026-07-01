# sas-log-sanitize

A command-line tool that sanitizes SAS 9.4 support log bundles by replacing
infrastructure identifiers, credentials, and PII with consistent, reversible
tokens. The sanitized output is meant for feeding into AI assistants for root
cause analysis; the original-to-token mapping stays on the analyst's local
machine so findings can be translated back to real values for the duration of
the support case.

Intended audience: SAS support engineers and admins who need to share log
bundles with AI assistants (or anyone else) without exposing customer
hostnames, IPs, usernames, emails, or credentials.

## Quick start

```sh
sas-log-sanitize -i /path/to/log-bundle -o /path/to/sanitized-output
# or a single file:
sas-log-sanitize -i /path/to/single.log -o /path/to/sanitized-output
```

This walks the input (a directory or a single file), replaces detected
identifiers with tokens (`HOST_001`, `USER_001`, `IPV4_001`, ...), fully
redacts credentials and secrets (`SECRET_REDACTED`), and writes the
sanitized files plus a mapping file, audit report, summary, and runlog to
the output directory.

## Installation

Pre-built binaries are checked into [`dist/`](dist/) -- clone the repo and run
the one matching your platform, no Go toolchain required:

| Platform | Binary |
|---|---|
| Linux (amd64) | `dist/sas-log-sanitize-linux-amd64` |
| Windows (amd64) | `dist/sas-log-sanitize-windows-amd64.exe` |
| macOS (arm64) | `dist/sas-log-sanitize-darwin-arm64` |

```sh
git clone git@github.com:axpmonkey/log-clean.git
./log-clean/dist/sas-log-sanitize-linux-amd64 -i /path/to/log-bundle -o /path/to/sanitized-output
```

On macOS/Linux, mark it executable first if needed: `chmod +x dist/sas-log-sanitize-*`.

### Building from source

Only needed if you're changing the tool itself, or `dist/` is out of date:

```sh
make build      # builds for your current platform into dist/
make cross      # cross-compiles linux-amd64, windows-amd64, darwin-arm64
```

All `make` targets run inside a `golang:1.26` Docker container, so a local Go
install isn't required. See the Makefile for details.

## Usage

### Sanitize a bundle

```sh
sas-log-sanitize -i /path/to/log-bundle -o /path/to/output \
  --hostlist customer-hosts.txt \
  --strict
```

| Flag | Default | Purpose |
|---|---|---|
| `--input` / `-i` | required | Input directory containing logs, or a single log file |
| `--output` / `-o` | `<input>-sanitized` | Output directory (created if missing) |
| `--mapping` / `-m` | `<output>/_mapping.json` | Path for the mapping file |
| `--hostlist` | none | Path to a customer-supplied hostname allowlist |
| `--ignorelist` | none | Path to hostnames/domains to never redact (supports `*.domain` wildcards) |
| `--profiles` | `auto` | Comma-separated profiles to apply, or `auto` |
| `--audit` | `true` | Run the audit pass after sanitization |
| `--strict` | `false` | Print a clear warning and exit 1 if the audit finds High-severity suspicious tokens |
| `--config` | none | Path to a YAML config file |
| `--verbose` / `-v` | `false` | Verbose logging to the runlog |
| `--quiet` / `-q` | `false` | Suppress non-error stdout output |
| `--dry-run` | `false` | Show what would happen, write nothing |

Exit codes: `0` clean, `1` audit found suspicious tokens, `2` input error,
`3` processing error, `4` configuration error.

### Reverse mode

Translate tokens in a sanitized excerpt (or file) back to their original
values, using the mapping file from the original run:

```sh
sas-log-sanitize --reverse /path/to/output/_mapping.json "saw HOST_001 fail"
sas-log-sanitize --reverse /path/to/output/_mapping.json /path/to/excerpt.txt
```

`SECRET_REDACTED` is never reversible -- redacted secrets are never recorded
anywhere, by design (see "The mapping file" below).

### Audit-only mode

Re-scan an already-sanitized directory for anything that looks like residual
PII, without re-running sanitization:

```sh
sas-log-sanitize --audit-only /path/to/output --strict
```

Pass `--ignorelist` here too if the original run used one, so hostnames it
intentionally left untouched aren't re-flagged as residual PII.

## The mapping file

`_mapping.json` is the reverse mapping from tokens back to real values
(hostnames, IPs, usernames, emails, etc.). **It is the single most sensitive
artifact this tool produces** -- treat it like a credential:

- It is written with owner-only (`0600`) file permissions.
- It is per-case and ephemeral by design: delete it (or move it to encrypted
  storage) once the support case is closed. This tool does not implement
  long-term mapping storage or cross-bundle consistency on purpose.
- It never contains a password, API key, or other secret -- those are always
  fully redacted (`SECRET_REDACTED`), never tokenized or recorded.
- The sanitized log output itself, the audit report, the summary, and the
  runlog are **not** sensitive in the same way and contain no real values.

## The allowlist file

`--hostlist` accepts a customer-supplied hostname allowlist: one hostname per
line, comments allowed with `#`. It exists because some hostnames appear
embedded inside compound strings the other detectors can't reliably parse
out on their own (e.g. `/var/log/db-prod-01-archive/`), and because bare,
non-dotted hostnames (no TLD) aren't caught by the FQDN detector at all.

The allowlist detector does **literal substring matching**, not word-boundary
matching -- it's the only detector that works this way. That means a short
or non-distinctive entry (e.g. `db1`) will also match inside unrelated text
(`db10`, `adb1x`). The tool warns at load time about entries shorter than 4
characters or that are themselves substrings of another entry; prefer fully
qualified or otherwise distinctive hostnames.

## The ignorelist file

`--ignorelist` is the inverse of `--hostlist`: it names hostnames/domains
that should **never** be tokenized or redacted, even if a detector would
otherwise match them. Useful for a noisy but non-sensitive vendor domain
that shows up constantly (e.g. license-check or support-portal URLs). One
entry per line, comments allowed with `#`:

```
license.example.com
*.sas.com
```

A bare entry matches that exact hostname (case-insensitively); a
`*.domain` entry matches the domain itself and any subdomain. `--ignorelist`
is honored by both sanitize mode and `--audit-only`.

## Limitations

Be aware of these before relying on this tool for a sensitive bundle:

- **No streaming/daemon mode.** On-demand processing only.
- **No archive support.** Extract `.zip`/`.tar.gz`/etc. bundles before running.
- **Binary files are skipped, not scrubbed.** Detected by extension
  allowlist and a non-printable-byte-ratio heuristic; binary content
  dominated by high bytes (0x80-0xFF) rather than control characters may not
  always be detected as binary -- when in doubt, remove non-text files from
  the bundle before running.
- **SAS log line unwrapping is not implemented.** Wrapped/continuation lines
  may cause a residual miss; the audit pass is the backstop, not a guarantee.
- **JDBC/ActiveMQ connection strings with embedded credentials and a bare
  (non-dotted) hostname** can leave that hostname untokenized, e.g.
  `jdbc:postgresql://user:pass@dbprod01:5432/db` leaves `dbprod01` as plain
  text (a dotted hostname like `db-prod-01.acme.internal` in the same
  position is tokenized correctly). The audit pass's bare-word rules are the
  backstop for this case.
- **Per-file profile-driven detector tuning is partial.** Profile
  auto-detection exists, but `extra_internal_tlds` is the only profile
  override actually wired into detector behavior; `ipv4.skip_ranges` and
  `allowlist.case_insensitive` from the config file are parsed but not yet
  applied.
- **No AIX support.** Linux, Windows, and macOS only.
- **No CI/CD pipeline.** Local builds only for now.
- **No cross-bundle consistency.** Each run gets a fresh token registry;
  the same hostname in two different runs gets different tokens.

## Documentation

See [`docs/`](docs/) for more:

- [`docs/usage.md`](docs/usage.md) -- detailed usage guide
- [`docs/architecture.md`](docs/architecture.md) -- design rationale (two-pass
  pipeline, span-claiming, detector ordering)
- [`docs/detectors.md`](docs/detectors.md) -- per-detector behavior and known
  limitations
- [`docs/adding-detectors.md`](docs/adding-detectors.md) -- how to add a new
  detector
- [`docs/reversing.md`](docs/reversing.md) -- using the mapping file safely

## License

Apache License 2.0 -- see [LICENSE](LICENSE).

## Contributing

See [`docs/adding-detectors.md`](docs/adding-detectors.md) for the most
common kind of contribution (a new detector). Run `make test` and `make lint`
before submitting changes.
