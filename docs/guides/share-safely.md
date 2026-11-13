# Share output safely

Sanitizing produces one folder that's safe to share and two artifacts that
aren't. This guide explains which is which, how to check the output before it
leaves your machine, and how to translate findings back to real values.

## What's safe and what isn't

| Artifact | Contains original values? | Share it? |
|---|---|---|
| Sanitized log files | No | Yes |
| `_summary.txt`, `_summary.json` | No (counts and relative paths only) | Yes |
| `_runlog.txt` | No | Yes |
| `_audit.txt` | **Yes, when it lists findings.** Each finding quotes the suspect line. | Only if it says `High=0, Medium=0` |
| `<output>.mapping.json` | **Yes, every one.** | **Never** |
| File and folder names | **Possibly.** Names aren't sanitized. | Check and rename first |

## Checklist

Run through this list before you send anything.

1. **The audit has no High findings.** The run exited with code `0`, or you've
   fixed every High line in `_audit.txt`.
2. **You've skimmed the Medium findings.** Most are noise. A real hostname in
   the list means you need a [hostlist](tune-detection.md#always-tokenize-a-hostname).
3. **`_audit.txt` is excluded** if it lists any findings.
4. **No file or folder name contains a hostname, username, or customer name.**
5. **The mapping file isn't in the folder.** By default it's written *next to*
   the output folder, and the tool refuses to put it inside one unless you pass
   `--allow-mapping-in-output`.
6. **The skipped files are expected.** `_summary.txt` lists them first. The
   assistant won't see those files.

If you edit sanitized files by hand, re-check them with the run's mapping file:

```sh
sas-log-sanitize --audit-only case-12345-clean --strict
```

The mapping file is found automatically at `case-12345-clean.mapping.json`.
Pass `--mapping <file>` if it's somewhere else. With the mapping file, the
audit also searches for every original value it holds. Any hit is a High
`known-original-value` finding.

## Look after the mapping file

The mapping file is a complete dictionary from every token back to the real
hostname, IP address, username, or email address it represents. Treat it like
a credential.

- **Keep it local.** Don't put it in a shared drive, ticket, or chat.
- **Leave its permissions alone.** It's written as owner-only (`0600`).
- **Never give it to the assistant** that's reading the sanitized logs. That
  undoes the sanitizing.
- **Delete it when the case closes,** or move it to encrypted storage.
  Nothing depends on keeping it: every run starts a fresh mapping, so a later
  run never needs an earlier one.

The mapping file never contains passwords, keys, or other secrets. Those are
redacted to `SECRET_REDACTED` and aren't recorded anywhere, not even in
`_runlog.txt`.

For the file format, see [Output files](../reference/output-files.md#mapping-file).

## Reverse tokens

When the assistant says something like "the connection from `HOST_003` keeps
timing out," translate it on your machine:

```sh
sas-log-sanitize --reverse case-12345-clean.mapping.json "the connection from HOST_003 keeps timing out"
```

To translate a longer excerpt, save it to a file and pass the path instead:

```sh
sas-log-sanitize --reverse case-12345-clean.mapping.json excerpt.txt
```

If the second argument is a readable file, the tool reverses the file's
contents. Otherwise it treats the argument as text. The result goes to stdout.

| Input | Result |
|---|---|
| A token in the mapping file (`HOST_003`, `IPV4_PRIV_002`) | The original value |
| A token-shaped string that isn't in the mapping file (a typo, or a token from another run) | Left unchanged. The tool doesn't guess. |
| `SECRET_REDACTED` | Left unchanged. There's nothing to reverse it to. |

Reverse mode is for your own reading. Don't paste the reversed text back into
the conversation with the assistant.
