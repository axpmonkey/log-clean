# Output files

A sanitize run writes the sanitized copies of your files plus four report
files to the output directory, and the mapping file next to it.

```text
case-12345-clean/
├── <your files, same relative paths>
├── _audit.txt
├── _summary.txt
├── _summary.json
└── _runlog.txt
case-12345-clean.mapping.json
```

With `--dry-run`, nothing is written.

## `_audit.txt`

Lists each audit finding, then a total. It's written only when the audit is on
(the default).

```text
[Medium] logs/c.log:3: server-suffix-bare-word ("sasapp01")
    JVM java8 on sasapp01 restarted
[High] logs/c.log:4: known-original-value ("jdoe")
    jdoe again

Summary: High=1, Medium=1
```

Each finding is `[Severity] <file>:<line>: <rule> ("<match>")`, followed by the
full line it came from.

> [!WARNING]
> Findings quote real text from the output. If the file lists any findings,
> don't share it.

### Audit rules

| Rule | Severity | Flags |
|---|---|---|
| `unredacted-ipv4` | High | A dotted-quad IP address |
| `unredacted-fqdn` | High | A fully qualified hostname |
| `email-shape` | High | An email address |
| `mac-shape` | High | A MAC address |
| `known-original-value` | High | Any original value from the mapping file |
| `hostname-shaped-bare-word` | Medium | A word with an environment marker, such as `app-prod01` or `db-uat` |
| `server-suffix-bare-word` | Medium | Letters followed by digits, such as `sasapp01`, `java8`, or `log4j` |
| `long-random-near-credential-keyword` | Medium | A random-looking string of 20 or more characters on a line that mentions `password`, `token`, `secret`, `key`, or `credential` |
| `windows-path-with-username` | Medium | `C:\Users\<name>` with an untokenized name |
| `unix-path-with-username` | Medium | `/home/<name>` with an untokenized name |

High rules are tuned to rarely fire on clean output. Medium rules are
deliberately broad. Known noise is suppressed, including Apache message IDs
(`AH01102`), Java build suffixes (`-b10`), and attribute *names* that contain
a credential keyword (`certificateKeystorePassword`).

## `_summary.txt`

A readable summary. Skipped files come first, so you don't overlook them.

```text
Skipped files (0):
  none

Files processed: 4
Files skipped: 0
Bytes processed: 806

Replacements by category:
  HOST: 8
  SECRET: 7
  USER: 3
```

## `_summary.json`

The same data for scripts and other tools. It contains no original values.

```json
{
  "schema_version": 1,
  "tool_version": "v0.3.0",
  "files_processed": 4,
  "files_skipped": 0,
  "bytes_processed": 806,
  "replacements_by_category": { "HOST": 8, "SECRET": 7, "USER": 3 },
  "unique_values_by_category": { "HOST": 4, "USER": 2 },
  "skipped_files": [],
  "audit": { "enabled": true, "high": 0, "medium": 0 },
  "exit_status": 0
}
```

| Field | Description |
|---|---|
| `schema_version` | Format version of this file. Currently `1`. |
| `tool_version` | Version of the tool that wrote the file. |
| `files_processed`, `files_skipped`, `bytes_processed` | Run totals. |
| `replacements_by_category` | How many replacements were made in each category. Counts every occurrence. |
| `unique_values_by_category` | How many distinct values were tokenized in each category. `SECRET` never appears here, because secrets aren't recorded. |
| `skipped_files` | A list of `{ "path", "reason" }` entries. Paths are relative and use forward slashes. |
| `audit` | `enabled`, plus `high` and `medium` finding counts. |
| `exit_status` | The exit code the run ended with (`0` or `1`). |

## `_runlog.txt`

Timestamped log of the run: settings, the profiles in effect, pass timings,
and warnings. It contains no original values. Hostlist warnings, which quote
hostlist entries, go to stderr instead. Add `-v` for more detail.

## Mapping file

Written to `<output>.mapping.json` by default, with owner-only (`0600`)
permissions. See [Share output safely](../guides/share-safely.md#look-after-the-mapping-file).

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-13T11:39:53.371633Z",
  "tool_version": "v0.3.0",
  "input_dir": "case-12345",
  "categories": {
    "HOST": {
      "HOST_001": "pghost01.corp.example.com",
      "HOST_002": "sasmid01.corp.example.com"
    },
    "USER": {
      "USER_001": "jdoe"
    }
  },
  "stats": {
    "files_processed": 4,
    "bytes_processed": 806,
    "replacements_by_category": { "HOST": 8, "SECRET": 7, "USER": 3 }
  }
}
```

`categories` maps each category to `{ token: original value }`. Secrets are
never included.

## Token categories

| Token | Replaces |
|---|---|
| `HOST_NNN` | Hostnames, including short names and hosts inside URLs |
| `IPV4_NNN` | IPv4 addresses (`IPV4_PRIV_NNN` / `IPV4_PUB_NNN` with `--ip-class`) |
| `IPV6_NNN` | IPv6 addresses |
| `MAC_NNN` | MAC addresses |
| `USER_NNN` | Usernames |
| `EMAIL_NNN` | Email addresses (and dotted Kerberos principals) |
| `DOMAIN_NNN` | Windows domains in `DOMAIN\user` |
| `KRB_NNN` | Kerberos realms |
| `DN_NNN` | LDAP distinguished names |
| `UNC_NNN` | UNC paths (`\\server\share`) |
| `URL_NNN` | Whole URLs, only with `--url-mode whole` |
| `SECRET_REDACTED` | Passwords, keys, tokens, cookies, and tickets. Not reversible. |

For which detector produces each token, see [Detectors](detectors.md).
