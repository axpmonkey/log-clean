GO_IMAGE := golang:1.26
VERSION := 0.1.0-dev

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

.PHONY: build test lint cross clean install shell

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
