# sas-log-sanitize

Strip hostnames, IP addresses, usernames, email addresses, and credentials
from SAS 9.4 support log bundles so you can share them with an AI assistant,
a vendor, or a colleague, then translate any finding back to the real values
on your own machine.

```text
Before                                               After
---------------------------------------------------  ---------------------------------------------
Reading /home/jdoe/sas/config.properties             Reading /home/USER_001/sas/config.properties
Connected to pghost01.corp.example.com on port 9432  Connected to HOST_001 on port 9432
user jdoe logged in from workstation                 user USER_001 logged in from workstation
host=pghost01 port=9432 dbname=SharedServices        host=HOST_001 port=9432 dbname=SharedServices
pw: {AES}Zm9vYmFyYmF6cXV4                            pw: SECRET_REDACTED
```

- **Consistent.** The same value gets the same token in every file of the bundle,
  so an assistant can still follow `HOST_001` across logs.
- **Reversible.** A local mapping file translates `HOST_001` back to
  `pghost01.corp.example.com`. The mapping file never leaves your machine.
- **Secrets are destroyed, not tokenized.** Passwords, keys, and session
  tickets become `SECRET_REDACTED` and aren't recorded anywhere.
- **Self-checking.** An audit pass re-scans the output for anything that still
  looks sensitive and fails the run if it finds something.

## Install

Download the binary for your platform from the
[latest release](https://github.com/axpmonkey/log-clean/releases/latest).
You don't need a Go toolchain.

| Platform | File |
|---|---|
| Linux (x86-64) | `sas-log-sanitize-linux-amd64` |
| Windows (x86-64) | `sas-log-sanitize-windows-amd64.exe` |
| macOS (Apple silicon) | `sas-log-sanitize-darwin-arm64` |

Verify the download against the release's `SHA256SUMS` file:

```sh
base=https://github.com/axpmonkey/log-clean/releases/latest/download
curl -LO "$base/sas-log-sanitize-linux-amd64"
curl -LO "$base/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
chmod +x sas-log-sanitize-linux-amd64
./sas-log-sanitize-linux-amd64 --version
```

- **macOS:** use `shasum -a 256 --ignore-missing -c SHA256SUMS`.
- **Windows:** run `certutil -hashfile sas-log-sanitize-windows-amd64.exe SHA256`
  and compare the result with the matching line in `SHA256SUMS`.

If your network blocks `objects.githubusercontent.com`, build from source.
See [CONTRIBUTING.md](CONTRIBUTING.md#build).

## Use it

The workflow has four steps.

1. **Sanitize** the bundle. The input can be a directory, a single file, or a
   `.zip`, `.tar`, `.tar.gz`, or `.tgz` archive.

   ```sh
   sas-log-sanitize -i case-12345.zip -o case-12345-clean
   ```

2. **Review** `case-12345-clean/_audit.txt`. The run exits with code `1` if the
   audit found anything high-severity.
3. **Share** the `case-12345-clean` folder. The mapping file is written next to
   it, at `case-12345-clean.mapping.json`, so it can't end up in the folder you
   share by accident.
4. **Reverse** whatever the assistant tells you:

   ```sh
   sas-log-sanitize --reverse case-12345-clean.mapping.json "HOST_003 refused the connection"
   ```

For a full walkthrough, see [Getting started](docs/getting-started.md).

## Before you share

> [!WARNING]
> Check these four things every time. The tool can't do them for you.

- [ ] **Leave the mapping file out.** `*.mapping.json` contains every real value.
- [ ] **Read `_audit.txt`, and leave it out if it lists findings.** Findings
      quote the suspect line, which may include real values.
- [ ] **Check the file names.** The tool sanitizes file contents, not file
      names. Rename any file whose name contains a hostname or username.
- [ ] **Delete the mapping file when the case closes.**

The reasons are covered in [Share output safely](docs/guides/share-safely.md).

## Documentation

| Guide | Read it to... |
|---|---|
| [Getting started](docs/getting-started.md) | Sanitize your first bundle, end to end |
| [Share output safely](docs/guides/share-safely.md) | Handle the mapping file and audit report, and reverse tokens |
| [Tune detection](docs/guides/tune-detection.md) | Force or exempt hostnames, set up a config file |
| [Troubleshooting](docs/guides/troubleshooting.md) | Fix missed values, noisy audits, and non-zero exit codes |

| Reference | Contents |
|---|---|
| [Command line](docs/reference/cli.md) | Every mode, flag, and exit code |
| [Configuration file](docs/reference/config.md) | YAML schema and profiles |
| [Output files](docs/reference/output-files.md) | `_audit.txt`, `_summary.*`, `_runlog.txt`, and the mapping file |
| [Detectors](docs/reference/detectors.md) | What gets replaced, how, and known limitations |

| For contributors | |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test, and release |
| [Architecture](docs/architecture.md) | How the pipeline works and why |
| [Add a detector](docs/adding-detectors.md) | Step-by-step guide |

## Limitations

- **The audit is a backstop, not a guarantee.** Review the output before you
  share it.
- **File names aren't sanitized.** Output paths mirror input paths.
- **Binary files are skipped, not scrubbed.** Remove non-text files you don't need.
- **Wrapped SAS log lines aren't joined.** A value split across two lines can
  be missed.
- **Archives are unpacked one level deep.** An archive inside an archive is
  skipped and listed in `_summary.txt`.
- **Each run is independent.** The same hostname gets different tokens in
  different runs. This is deliberate: mapping files are per-case and short-lived.
- **Runs on demand only.** There's no watch or daemon mode.
- **Supported platforms are Linux, Windows, and macOS.** AIX isn't supported.

Detector-level limitations are listed in
[Detectors](docs/reference/detectors.md#known-limitations).

## Glossary

| Term | Meaning |
|---|---|
| **Bundle** | The set of logs you sanitize: a directory, a file, or an archive. |
| **Token** | A stand-in such as `HOST_001` or `USER_002`. It's reversible with the mapping file. |
| **Redact** | Replace a secret with `SECRET_REDACTED`. It can't be reversed. |
| **Mapping file** | The local JSON file that maps tokens to original values. |
| **Finding** | Something in the output that the audit thinks still looks sensitive. |

## License

Apache License 2.0. See [LICENSE](LICENSE).
