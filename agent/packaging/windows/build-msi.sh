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
  # installer windows (setup form, progress, finish, cancel, error): wixl cannot author them,
  # so the tables in packaging/windows/ui are added with msibuild. Silent installs skip them.
  msi=/agent/dist/sohobotp-agent.msi; ui=/agent/packaging/windows/ui
  for t in TextStyle Dialog Control ControlEvent ControlCondition EventMapping; do
    cp "$ui/$t.idt" "$work/$t.idt"
    msibuild "$msi" -i "$work/$t.idt"
  done
  for t in InstallUISequence Property; do
    msiinfo export "$msi" "$t" | sed "s/\r\$//" > "$work/$t.idt"
    sed "s/\r\$//" "$ui/$t.rows" >> "$work/$t.idt"
    msibuild "$msi" -i "$work/$t.idt"
  done
  # SaveToken: the enrolment token reaches the agent without the registry or the log (tables/README.md)
  tables=/agent/packaging/windows/tables
  cp "$tables/CustomAction.idt" "$work/CustomAction.idt" && msibuild "$msi" -i "$work/CustomAction.idt"
  msiinfo export "$msi" InstallExecuteSequence | sed "s/\r\$//" > "$work/InstallExecuteSequence.idt"
  sed "s/\r\$//" "$tables/InstallExecuteSequence.rows" >> "$work/InstallExecuteSequence.idt"
  msibuild "$msi" -i "$work/InstallExecuteSequence.idt"
  echo "built agent/dist/sohobotp-agent.msi (with installer windows)"
  for table in Component File ServiceInstall ServiceControl Registry CustomAction InstallExecuteSequence Property InstallUISequence Dialog ControlCondition; do
    echo "== $table"; msiinfo export /agent/dist/sohobotp-agent.msi "$table" | tail -n +4
  done'
