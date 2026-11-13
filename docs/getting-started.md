# Getting started

This tutorial takes one log bundle from raw to shareable, then translates an
assistant's answer back to real values. It takes about five minutes.

**You need:** the `sas-log-sanitize` binary (see [Install](../README.md#install))
and a log bundle: a folder, a single log file, or a `.zip`/`.tar`/`.tar.gz` archive.

The examples use a folder named `case-12345`. Replace it with your own path.

## 1. Sanitize the bundle

```sh
sas-log-sanitize -i case-12345 -o case-12345-clean
```

Progress is printed to stderr while the tool runs. A summary follows:

```text
pass 1: 4/4 files, 0.0 of 0.0 MB, 3.6 MB/s, ETA 0s
pass 2: 4/4 files, 0.0 of 0.0 MB, 2.4 MB/s, ETA 0s
Processed 4 files (0 skipped), 806 bytes
Output: case-12345-clean
Mapping: case-12345-clean.mapping.json
```

You now have two things side by side:

```text
case-12345-clean/                 ← share this folder
├── logs/...                      sanitized copies of your files, same layout
├── _audit.txt                    what the audit pass found
├── _summary.txt                  replacement counts and skipped files
├── _summary.json                 the same summary, machine-readable
└── _runlog.txt                   what the tool did (no original values)
case-12345-clean.mapping.json     ← never share this file
```

## 2. Look at what changed

Here's one file from the bundle, before and after sanitizing:

```text
user jdoe logged in from workstation                    user USER_001 logged in from workstation
host=pghost01 port=9432 dbname=SharedServices           host=HOST_001 port=9432 dbname=SharedServices
[error] proxy: AH00957: HTTP: attempt to connect to     [error] proxy: AH00957: HTTP: attempt to connect to
  SASMID01 failed                                         HOST_002 failed
```

These lines show three things:

- `jdoe` was found in a path (`/home/jdoe/`) in a *different* file and then
  replaced everywhere it appears. This is the known-values sweep.
- `pghost01` is a short name. It got the same token as
  `pghost01.corp.example.com`, which appeared elsewhere in the bundle.
- `SASMID01` matched `sasmid01.corp.example.com` regardless of case.

Port numbers, database names, and Apache message IDs stay as they are. An
assistant needs those to diagnose the problem.

## 3. Check the audit

Open `case-12345-clean/_audit.txt`. A clean run looks like this:

```text
Summary: High=0, Medium=0
```

A run with findings lists each one with its file, line, rule, and the line it
appeared on:

```text
[Medium] logs/c.log:3: server-suffix-bare-word ("sasapp01")
    JVM java8 on sasapp01 restarted
[High] logs/c.log:4: known-original-value ("jdoe")
    jdoe again
```

- **High** findings are very likely real leaks. The tool exits with code `1`
  when there are any. Fix the source line or remove it before you share.
- **Medium** findings are intentionally broad. Many are noise, like `java8`.
  Skim them; `sasapp01` here is a real hostname the detectors couldn't
  recognize on their own. To catch it, add it to a hostlist and run again (see
  [Tune detection](guides/tune-detection.md#always-tokenize-a-hostname)).

> [!WARNING]
> `_audit.txt` quotes the suspect lines, so it can contain real values. If it
> lists any findings, leave it out of what you share.

## 4. Share the output

Zip and send `case-12345-clean/`. Before you do, go through the
[sharing checklist](guides/share-safely.md#checklist).

## 5. Reverse the answer

Suppose the assistant replies, "`HOST_001` refused the connection from `USER_001`."
Translate the reply locally:

```sh
sas-log-sanitize --reverse case-12345-clean.mapping.json "HOST_001 refused the connection from USER_001"
```

```text
pghost01.corp.example.com refused the connection from jdoe
```

`SECRET_REDACTED` and tokens that aren't in the mapping file are left unchanged.

## Next steps

- [Share output safely](guides/share-safely.md): what's in the mapping file
  and how to look after it.
- [Tune detection](guides/tune-detection.md): handle hostnames the tool misses
  or flags when it shouldn't.
- [Command line reference](reference/cli.md): every flag.
