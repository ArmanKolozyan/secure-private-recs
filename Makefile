# Build and test helpers.

# The go command to use (override with `make GO=/path/to/go ...`), and the
# environment every build needs: an amd64 target with cgo enabled for the C parts.
GO    ?= go
GOENV := GOARCH=amd64 CGO_ENABLED=1

# Packages whose tests need no network or AWS credentials
# (except for TestS3, which is skipped below).
FAST_PKGS := ./uint128 ./rand ./dcf ./dmsb ./multdpf ./net ./share

# These targets are commands, not files to build, so make always runs them.
.PHONY: build test-share test-fast test-protocol run clean

## build: compiles every package
build:
	$(GOENV) $(GO) build ./...
	$(GOENV) $(GO) build -o bin/nudge .

## test-share: tests of the share package (secret sharing, matrix operations,
## in-process power iteration). TestS3 needs AWS credentials and is skipped.
test-share:
	$(GOENV) $(GO) test -skip TestS3 ./share

## test-fast: tests of every package except protocol
test-fast:
	$(GOENV) $(GO) test -skip TestS3 $(FAST_PKGS)

## test-protocol: three servers over local TCP. Its TestPowerIt used to upload
## the result to an AWS S3 bucket and read it back, which fails without
## correct AWS credentials. In protocol/server_test.go (runPowerIt) server 0 now
## writes the result to a local file and the test reads it from there.
test-protocol:
	mkdir -p protocol/scratch
	$(GOENV) $(GO) test -timeout 60m ./protocol

## run: runs a Go program with the amd64 settings applied,
run:
	$(GOENV) $(GO) run $(CMD) $(ARGS)

## clean: removes the compiled program and any test binaries and CPU profiles
clean:
	rm -rf bin
	find . -name '*.test' -delete -o -name '*.prof' -delete
