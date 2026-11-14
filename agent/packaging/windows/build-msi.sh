#!/bin/sh
# Builds agent/dist/sohobotp-agent.msi from agent/dist/sohobotp-agent-windows-amd64.exe with
# msitools (wixl) in a throwaway Debian container, then lists the tables that matter.
# Usage (from the repository root, after agent/tests/run-in-docker.sh):  sh agent/packaging/windows/build-msi.sh
#   AGENT_VERSION=x.y.z        MSI version (must grow for an upgrade; default 0.2.0)
#   AGENT_EXE=dist/...exe      agent binary, relative to agent/ (default dist/sohobotp-agent-windows-amd64.exe)
#   MSI_OUT=dist/...msi        output, relative to agent/ (default dist/sohobotp-agent.msi)
set -eu
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
VERSION="${AGENT_VERSION:-0.2.0}"
docker run --rm -v "$REPO/agent":/agent -e VERSION="$VERSION" \
  -e EXE="${AGENT_EXE:-dist/sohobotp-agent-windows-amd64.exe}" -e OUT="${MSI_OUT:-dist/sohobotp-agent.msi}" debian:bookworm-slim sh -euc '
  apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends msitools wixl >/dev/null
  work=$(mktemp -d); cp "/agent/$EXE" "$work/sohobotp-agent.exe"
  cp /agent/packaging/windows/sohobotp-agent.wxs "$work/"
  mkdir -p "$(dirname "/agent/$OUT")"
  cd "$work" && wixl -a x64 -D Version="$VERSION" -o "/agent/$OUT" sohobotp-agent.wxs
  # installer windows (setup form, progress, finish, cancel, error): wixl cannot author them,
  # so the tables in packaging/windows/ui are added with msibuild. Silent installs skip them.
  msi="/agent/$OUT"; ui=/agent/packaging/windows/ui
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
  # Major upgrade (wixl cannot author it, tables/README.md): any older or same version of this
  # product is removed first (the agent state is kept: ForgetState skips upgrades), a newer
  # one blocks the install (no downgrade).
  up="{FC89F2FA-D510-465B-ADD5-625A33E9964B}"
  printf "UpgradeCode\tVersionMin\tVersionMax\tLanguage\tAttributes\tRemove\tActionProperty\ns38\tS20\tS20\tS255\ti4\tS255\ts72\nUpgrade\tUpgradeCode\tVersionMin\tVersionMax\tLanguage\tAttributes\n%s\t0.0.1\t%s\t\t769\t\tWIX_UPGRADE_DETECTED\n%s\t%s\t\t\t2\t\tNEWERVERSIONDETECTED\n" "$up" "$VERSION" "$up" "$VERSION" > "$work/Upgrade.idt"
  msibuild "$msi" -i "$work/Upgrade.idt"
  cp "$tables/LaunchCondition.idt" "$work/LaunchCondition.idt" && msibuild "$msi" -i "$work/LaunchCondition.idt"
  msiinfo export "$msi" InstallUISequence | sed "s/\r\$//" > "$work/InstallUISequence.idt"
  sed "s/\r\$//" "$tables/InstallUISequence.rows" >> "$work/InstallUISequence.idt"
  msibuild "$msi" -i "$work/InstallUISequence.idt"
  echo "built agent/$OUT $VERSION (with installer windows)"
  for table in Component File ServiceInstall ServiceControl Registry CustomAction Upgrade LaunchCondition InstallExecuteSequence Property InstallUISequence Dialog ControlCondition; do
    echo "== $table"; msiinfo export "$msi" "$table" | tail -n +4
  done'
