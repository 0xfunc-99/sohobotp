#!/bin/sh
# Builds agent/dist/sohobotp-agent.msi from agent/dist/sohobotp-agent-windows-amd64.exe with
# msitools (wixl) in a throwaway Debian container, then lists the tables that matter.
# Usage (from the repository root, after agent/tests/run-in-docker.sh):  sh agent/packaging/windows/build-msi.sh
set -eu
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
VERSION="${AGENT_VERSION:-0.1.0}"
docker run --rm -v "$REPO/agent":/agent -e VERSION="$VERSION" debian:bookworm-slim sh -euc '
  apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends msitools wixl >/dev/null
  work=$(mktemp -d); cp /agent/dist/sohobotp-agent-windows-amd64.exe "$work/sohobotp-agent.exe"
  cp /agent/packaging/windows/sohobotp-agent.wxs "$work/"
  cd "$work" && wixl -a x64 -D Version="$VERSION" -o /agent/dist/sohobotp-agent.msi sohobotp-agent.wxs
  echo "built agent/dist/sohobotp-agent.msi"
  for table in Component File ServiceInstall ServiceControl Registry Property; do
    echo "== $table"; msiinfo export /agent/dist/sohobotp-agent.msi "$table" | tail -n +4
  done'
