# Command-line reference

```text
sas-log-sanitize -i <input> [-o <output>] [flags]          sanitize (default mode)
sas-log-sanitize --reverse <mapping-file> <text-or-file>    reverse tokens
sas-log-sanitize --audit-only <sanitized-dir> [flags]       re-audit output
sas-log-sanitize --version | --help
```

Flags can go before or after positional arguments. They take one or two
dashes (`-input` and `--input` are the same), and values can follow a space or
`=` (`--url-mode whole`, `--url-mode=whole`). A bare `--` ends flag parsing:
everything after it is positional, even if it starts with `-`.

In reverse mode, everything after the mapping file is taken as literal text,
so the text you reverse can start with `-`.

## Sanitize mode

```sh
sas-log-sanitize -i case-12345.zip -o case-12345-clean
```

`-i` is optional. You can pass the input as the first positional argument instead.

### Input and output

| Flag | Default | Description |
|---|---|---|
| `-i`, `--input` | *(required)* | A directory, a single file, or a `.zip`, `.tar`, `.tar.gz`, or `.tgz` archive. |
| `-o`, `--output` | `<input>-sanitized` | Output directory. It's created if it doesn't exist. |
| `-m`, `--mapping` | `<output>.mapping.json` | Where to write the mapping file. It must be outside the output directory. |
| `--allow-mapping-in-output` | off | Allow `--mapping` to point inside the output directory. Not recommended. |
| `--config` | none | A YAML [configuration file](config.md). Flags on the command line override it. |
| `--dry-run` | off | Run both passes and report statistics and findings, but write nothing. |

### Detection

| Flag | Default | Description |
|---|---|---|
| `--hostlist` | none | A file of hostnames to always tokenize, matched as literal substrings. See [Tune detection](../guides/tune-detection.md#always-tokenize-a-hostname). |
| `--ignorelist` | none | A file of hostnames or `*.domain` wildcards to never tokenize. |
| `--profiles` | `auto` | A comma-separated list of [profiles](config.md#profiles), or `auto` for all of them. |
| `--url-mode` | `host` | `host` replaces only a URL's user information and host. `whole` replaces the entire URL with a single `URL_NNN` token. |
| `--ip-class` | off | Tokenize IPv4 addresses as `IPV4_PRIV_NNN` or `IPV4_PUB_NNN`. |
| `--keep-har-bodies` | off | Keep HAR response bodies, after scanning them, instead of dropping them. |

### Audit

| Flag | Default | Description |
|---|---|---|
| `--audit` | `true` | Run the audit pass on the output. To turn it off, use `--audit=false`. |
| `--strict` | off | Exit `1` on Medium findings too. High findings always exit `1`. |

### Performance and logging

| Flag | Default | Description |
|---|---|---|
| `--workers` | one per CPU | How many files, and chunks of large files, are processed in parallel. Output is identical for any value. |
| `--max-extract-mb` | `20480` | The maximum total size, in MB, extracted from archives. Protects against decompression bombs. |
| `-v`, `--verbose` | off | Write more detail to `_runlog.txt`. |
| `-q`, `--quiet` | off | Print only errors. Turns off the progress lines. |
| `--cpuprofile` | none | Write a Go CPU profile to this file. Inspect it with `go tool pprof -top <binary> <file>`. Output is unaffected. |

### What sanitize mode does to each file

| Input | Handling |
|---|---|
| Plain text, in UTF-8, UTF-16 (with a BOM), or Windows-1252 | Sanitized line by line. The encoding and line endings (CRLF/LF) are preserved. |
| `*.gz` (rotated logs) | Decompressed, sanitized, and written back gzipped under the same name. |
| `.zip`, `.tar`, `.tar.gz`, `.tgz` | Extracted to a private temporary folder. Output goes under a folder named after the archive (`bundle.zip` → `bundle/`). |
| `*.har`, or `*.json` starting with a top-level `"log"` key | Processed as JSON. Credential headers, cookies, and credential query parameters are redacted. Response bodies are dropped. The output is valid JSON. |
| Binary files, by extension or content | Skipped and listed in `_summary.txt`. |
| Archives inside archives, symlinks, and entries with `..` or absolute paths | Skipped and listed. |

Files are processed in alphabetical order by output path, so token numbers are
the same every time you run the tool on the same input.

## Reverse mode

```sh
sas-log-sanitize --reverse <mapping-file> <text-or-file>
```

If `<text-or-file>` is a readable file, the tool reverses its contents.
Otherwise it treats the argument as literal text. Each token found in the
mapping file is replaced with its original value, and the result is printed to
stdout. Unknown tokens and `SECRET_REDACTED` are left unchanged. See
[Reverse tokens](../guides/share-safely.md#reverse-tokens).

## Audit-only mode

```sh
sas-log-sanitize --audit-only <sanitized-dir> [--strict] [--mapping <file>] [--ignorelist <file>] [--config <file>]
```

Re-scans an existing output folder without sanitizing it again. The tool's own
files (`_audit.txt`, `_summary.*`, `_runlog.txt`) are skipped. Findings are
printed to stdout, and the exit code follows the sanitize rules.

- **Mapping file:** if `--mapping` is set, or `<sanitized-dir>.mapping.json`
  exists, the audit also searches for every original value in it. Any hit is a
  High `known-original-value` finding.
- **Ignorelist and config:** pass the same `--ignorelist` and `--config` as the
  original run. Otherwise hosts and IP ranges you deliberately kept are
  reported as findings.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, with no High findings. With `--strict`, no findings at all. |
| `1` | Success, but the audit found High findings. With `--strict`, it found findings of any severity. |
| `2` | Input error: a missing or unreadable input, hostlist, or ignorelist. |
| `3` | Processing error: a failure while reading, extracting, or writing. |
| `4` | Configuration error: an invalid flag or config value, an unknown profile, or a mapping path inside the output directory. |

Exit code `1` still writes all the output. Codes `2` to `4` mean the run didn't
complete.
