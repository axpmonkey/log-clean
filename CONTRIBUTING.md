# Contributing

## Prerequisites

| Tool | Needed for |
|---|---|
| Docker | `build`, `test`, `lint`, and `cross`. These run inside a `golang:1.26` container, so you don't need Go installed locally. |
| `git`, and the [GitHub CLI](https://cli.github.com/) (`gh`), logged in | `make release` only |

## Build

```sh
make build    # binary for your platform → dist/sas-log-sanitize
make cross    # linux-amd64, windows-amd64, darwin-arm64 → dist/
make clean    # remove dist/
make shell    # interactive shell in the build container
```

`dist/` isn't tracked in git. Binaries are stamped with `git describe`, for
example `v0.3.0-1-ge085423-dirty`, which `--version` prints.

## Test

```sh
make test     # go test ./...
make lint     # go vet, plus staticcheck if it's installed in the container
```

Run both before you open a pull request.

| Test type | Location |
|---|---|
| Unit tests | Next to each package (`*_test.go`) |
| Golden tests | `testdata/golden/<case>/{input,expected}/`: full-run output compared byte for byte |
| Equivalence and fuzz tests | Hand-written scanners compared with their reference regexes, and prefilters checked to never reject a real match. See [Architecture](docs/architecture.md#performance-techniques). |

## Common changes

- **Add a detector:** follow [Add a detector](docs/adding-detectors.md).
- **Change detection behavior:** update
  [Detectors](docs/reference/detectors.md), including its known-limitations
  table.
- **Add or change a flag:** update [Command line](docs/reference/cli.md), and
  [Configuration file](docs/reference/config.md) if the flag has a config key.
- **Change an output file:** update [Output files](docs/reference/output-files.md),
  and bump `schema_version` if the change isn't backward compatible.

## Release

```sh
make release RELEASE=0.4.0 [NOTES=path/to/notes.md]
```

The target refuses to run unless you're on `main`, with a clean tree, in sync
with `origin/main`, and the tag doesn't exist yet. It then:

1. cross-compiles with version `v0.4.0`;
2. writes `dist/SHA256SUMS` and verifies it;
3. tags the commit and pushes the tag;
4. creates the GitHub release with the three binaries and `SHA256SUMS`
   attached.

Without `NOTES`, GitHub generates the release notes from the commits. Release
assets have no version number in their names, so
`releases/latest/download/<name>` always points to the newest build.

## Using the library

`pkg/sanitize` is the public Go API that the CLI is built on:

```go
opts := sanitize.DefaultOptions("case-12345")
opts.OutputDir = "case-12345-clean"
result, err := sanitize.Sanitize(opts)
if err != nil { /* handle */ }
os.Exit(result.ExitStatus())
```

`Reverse(mappingPath, text)` and `AuditDirectory(...)` provide reverse and
audit-only mode. See the package documentation in `pkg/sanitize/doc.go`.
