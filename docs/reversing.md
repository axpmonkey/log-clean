# Reversing sanitized output

When an AI assistant (or anyone else) points out something interesting in
sanitized output -- "the connection from `HOST_003` keeps timing out" -- use
reverse mode to translate that back to the real value, on your own machine,
using the mapping file from the original run:

```sh
sas-log-sanitize --reverse /path/to/output/_mapping.json "the connection from HOST_003 keeps timing out"
```

Or point it at a file containing a larger excerpt:

```sh
sas-log-sanitize --reverse /path/to/output/_mapping.json /path/to/excerpt.txt
```

## What does and doesn't reverse

- Every `CATEGORY_NNN` token (e.g. `HOST_003`, `USER_001`, `IPV4_002`) is
  replaced with its original value, if it's in the mapping file.
- A token-shaped string with no entry in the mapping (a typo, a token from a
  *different* run's mapping file, or just text that happens to look like a
  token) is left unchanged rather than guessed at.
- `SECRET_REDACTED` is **never reversible**. Passwords, API keys, and other
  secrets are fully redacted at sanitization time and never recorded
  anywhere -- not in the mapping file, not in the runlog. There is nothing
  to reverse them to, by design.

## Handling the mapping file safely

The mapping file is the single most sensitive artifact this tool produces --
it's a complete dictionary from every token back to the real hostname, IP,
username, or email it represents. Treat it like a credential:

- Keep it on your own machine, not in a shared location, for the duration of
  the support case.
- It's written with owner-only (`0600`) permissions; don't loosen that.
- Delete it (or move it to encrypted storage) once the case is closed --
  this tool deliberately does not implement long-term mapping storage, and
  there is no cross-bundle consistency to lose by deleting it (each run gets
  a fresh mapping).
- Never paste the mapping file's contents into the same AI assistant
  conversation you're using the sanitized logs with -- that would defeat the
  entire point of sanitizing them in the first place. Reverse translation is
  for your own local reading, not for re-injecting real values back into a
  shared context.
