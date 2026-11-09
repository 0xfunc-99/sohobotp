#!/bin/sh
# Agent checks in a throwaway Go container: gofmt, go vet (Linux and Windows), race tests,
# and builds for linux/amd64, linux/arm64 and windows/amd64 into agent/dist/.
# Usage (from the repository root):  sh agent/tests/run-in-docker.sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
docker run --rm -v "$REPO":/src -w /src/agent -e GOFLAGS=-buildvcs=false \
  -v sohobotp-go-cache:/go/pkg/mod golang:1.22.10-bookworm sh -euc '
    echo "== gofmt"; test -z "$(gofmt -l .)" || { gofmt -l .; echo "FAIL gofmt"; exit 1; }; echo "formatted"
    echo "== go vet"; go vet ./... && GOOS=windows go vet ./... && echo "vet ok"
    echo "== tests (race)"; go test -race -count=1 ./...
    echo "== builds"
    mkdir -p dist
    VERSION=${AGENT_VERSION:-0.1.0}
    for target in linux/amd64 linux/arm64 windows/amd64; do
      os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
      CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X multiotp-portal/agent/internal/inventory.Version=$VERSION" \
        -o "dist/sohobotp-agent-$os-$arch$ext" ./cmd/sohobotp-agent
      echo "built dist/sohobotp-agent-$os-$arch$ext"
    done'
