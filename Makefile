GO_IMAGE := golang:1.26
# Version stamped into binaries (sas-log-sanitize --version). Development
# builds describe the commit relative to the last release tag, e.g.
# v0.2.0-3-gabc1234-dirty; `make release` builds with VERSION=v<RELEASE>.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Platform binaries published with each GitHub release. Names carry no
# version, so https://github.com/<owner>/<repo>/releases/latest/download/<name>
# always points at the newest one.
RELEASE_BINARIES := sas-log-sanitize-linux-amd64 sas-log-sanitize-windows-amd64.exe sas-log-sanitize-darwin-arm64

# Host OS/ARCH in Go's naming, so `make build` produces a binary you can run
# directly on this machine (the container's own GOOS/GOARCH defaults to its
# own Linux platform, not the host's).
HOST_GOOS := $(shell uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/darwin/;s/linux/linux/')
HOST_GOARCH := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/arm64/arm64/')

DOCKER_RUN := docker run --rm \
	-v $(CURDIR):/src \
	-w /src \
	-v sas-log-sanitize-gocache:/root/.cache/go-build \
	-v sas-log-sanitize-gomod:/go/pkg/mod \
	-e GOFLAGS=-mod=mod \
	$(GO_IMAGE)

.PHONY: build test lint cross clean install shell release

build:
	$(DOCKER_RUN) env GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) go build -ldflags "-X main.version=$(VERSION)" -o dist/sas-log-sanitize ./cmd/sanitize

test:
	$(DOCKER_RUN) go test ./...

lint:
	$(DOCKER_RUN) sh -c "go vet ./... && (command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo 'staticcheck not installed, skipping')"

cross:
	$(DOCKER_RUN) sh -c "\
		GOOS=linux GOARCH=amd64 go build -ldflags \"-X main.version=$(VERSION)\" -o dist/sas-log-sanitize-linux-amd64 ./cmd/sanitize && \
		GOOS=windows GOARCH=amd64 go build -ldflags \"-X main.version=$(VERSION)\" -o dist/sas-log-sanitize-windows-amd64.exe ./cmd/sanitize && \
		GOOS=darwin GOARCH=arm64 go build -ldflags \"-X main.version=$(VERSION)\" -o dist/sas-log-sanitize-darwin-arm64 ./cmd/sanitize"

clean:
	rm -rf dist

install:
	$(DOCKER_RUN) go install ./cmd/sanitize

# Interactive shell inside the build container, for ad-hoc go commands.
shell:
	docker run --rm -it -v $(CURDIR):/src -w /src $(GO_IMAGE) bash

# Publish a GitHub release: make release RELEASE=0.2.0 [NOTES=path/to/notes.md]
#
# Refuses unless on main, with a clean tree, in sync with origin/main, and the
# tag doesn't exist yet. Then cross-compiles with VERSION=v$(RELEASE), writes
# dist/SHA256SUMS (verified), tags the commit, pushes the tag, and creates the release
# with the binaries and checksums attached (gh CLI, logged in). Without NOTES,
# GitHub generates release notes from the commits.
release:
	@test -n "$(RELEASE)" || { echo "usage: make release RELEASE=x.y.z [NOTES=file]"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "release: not on main"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { echo "release: working tree not clean"; exit 1; }
	@git fetch -q origin main && test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" || { echo "release: main not in sync with origin/main"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/v$(RELEASE)" >/dev/null || { echo "release: tag v$(RELEASE) already exists"; exit 1; }
	@command -v gh >/dev/null || { echo "release: gh CLI not found"; exit 1; }
	$(MAKE) cross VERSION=v$(RELEASE)
	@# Checksums are computed on the host, from the exact files gh uploads,
	@# and verified before anything is tagged or published.
	cd dist && { command -v sha256sum >/dev/null && sha256sum $(RELEASE_BINARIES) || shasum -a 256 $(RELEASE_BINARIES); } > SHA256SUMS
	cd dist && { command -v sha256sum >/dev/null && sha256sum -c SHA256SUMS || shasum -a 256 -c SHA256SUMS; }
	git tag -a v$(RELEASE) -m "sas-log-sanitize v$(RELEASE)"
	git push origin v$(RELEASE)
	gh release create v$(RELEASE) $(addprefix dist/,$(RELEASE_BINARIES)) dist/SHA256SUMS \
		--title "sas-log-sanitize v$(RELEASE)" \
		$(if $(NOTES),--notes-file $(NOTES),--generate-notes)
