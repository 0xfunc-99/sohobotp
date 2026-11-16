#!/bin/sh
# Builds a SIGNED agent release: agents that can update themselves, and the files the portal
# hands out for it.
#
#   AGENT_VERSION=0.3.0 sh agent/packaging/release.sh
#
#   AGENT_VERSION     x.y.z, higher than every version released before (required)
#   RELEASE_KEY_DIR   folder of the release key (default: ~/SohobOTP-release-key). It is created,
#                     with a new key, the first time. KEEP IT: back it up somewhere safe and
#                     never copy release-private.key to the portal server or into this repository.
#                     Agents only accept releases signed with the key they were built with: if
#                     the key is lost, every computer needs a new agent installed by hand.
#
# What it does: runs the agent checks and builds the four programs with the public key built in
# (agent/tests/run-in-docker.sh), signs each one (sohobotp-agent release sign), builds the
# Windows MSI, and writes everything to agent/dist/release-<version>/:
#
#   sohobotp-agent-<os>-<arch>[.exe]   + .manifest.json (the signature) for each platform
#   sohobotp-agent-<version>-x64.msi   Windows installer (by hand, or Group Policy software installation)
#   SHA256SUMS, release-public.key
#
# Then, on the portal server (once per release):
#   docker cp agent/dist/release-<version> sohobotp:/tmp/release
#   docker exec sohobotp php /usr/local/bin/multiotp/portal/bin/portal-admin.php release-key-set --key="$(cat release-public.key)"   (first time)
#   docker exec sohobotp php /usr/local/bin/multiotp/portal/bin/portal-admin.php agent-release-add --dir=/tmp/release
# and choose the version as "Agent version" in the computer policies.
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${AGENT_VERSION:-}"
case "$VERSION" in
  *[!0-9.]*|"") echo "Set AGENT_VERSION=x.y.z (for example AGENT_VERSION=0.3.0)" >&2; exit 2 ;;
esac
KEYDIR="${RELEASE_KEY_DIR:-$HOME/SohobOTP-release-key}"
GO="golang:1.22.10-bookworm"
run_go() { # run_go <extra docker options...> -- <command...>   (in agent/, as in the tests)
  opts=""
  while [ "$1" != "--" ]; do opts="$opts $1"; shift; done
  shift
  # shellcheck disable=SC2086
  docker run --rm $opts -v "$REPO":/src -w /src/agent -e GOFLAGS=-buildvcs=false -v sohobotp-go-cache:/go/pkg/mod "$GO" "$@"
}

if [ ! -f "$KEYDIR/release-private.key" ]; then
  echo "== no release key in $KEYDIR: creating one"
  mkdir -p "$KEYDIR"
  chmod 700 "$KEYDIR"
  run_go -v "$KEYDIR":/key -- go run ./cmd/sohobotp-agent release keygen --out /key | sed -n 's/^Public key (build agents with it): //p' > "$KEYDIR/release-public.key"
  chmod 600 "$KEYDIR/release-private.key"
  cat > "$KEYDIR/README.txt" <<TXT
SohobOTP release key (created $(date -u +%Y-%m-%d))

release-private.key   SECRET. Signs agent releases (agent/packaging/release.sh). Whoever has it
                      can make every SohobOTP agent built with this key run their program.
                      Keep a backup offline (USB stick in a safe, password manager). Never put
                      it on the portal server, in the repository, in a chat or an e-mail.
release-public.key    Not secret. Built into the agents; given to the portal
                      (portal-admin.php release-key-set) so it refuses other uploads.

If the private key is lost: agents cannot update themselves any more; make a new key and install
a new agent on every computer by hand (or with the Windows MSI by Group Policy).
TXT
fi
PUBLIC="$(tr -d ' \n\r' < "$KEYDIR/release-public.key")"
[ ${#PUBLIC} -eq 44 ] || { echo "release-public.key in $KEYDIR is not a public key" >&2; exit 1; }
echo "== release $VERSION, release key $PUBLIC"

AGENT_VERSION="$VERSION" RELEASE_PUBLIC_KEY="$PUBLIC" sh "$REPO/agent/tests/run-in-docker.sh"

OUT="dist/release-$VERSION"
rm -rf "$REPO/agent/$OUT"
mkdir -p "$REPO/agent/$OUT"
cp "$KEYDIR/release-public.key" "$REPO/agent/$OUT/"
echo "== signing"
run_go -v "$KEYDIR":/key:ro -e VERSION="$VERSION" -e OUT="$OUT" -- sh -euc '
  for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
    os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
    name="sohobotp-agent-$os-$arch$ext"
    cp "dist/$name" "$OUT/$name"
    go run ./cmd/sohobotp-agent release sign --key /key/release-private.key --file "$OUT/$name" \
      --version "$VERSION" --os "$os" --arch "$arch" --out "$OUT/$name.manifest.json"
    echo "signed $name"
  done'
echo "== Windows MSI"
AGENT_VERSION="$VERSION" AGENT_EXE="$OUT/sohobotp-agent-windows-amd64.exe" MSI_OUT="$OUT/sohobotp-agent-$VERSION-x64.msi" \
  sh "$REPO/agent/packaging/windows/build-msi.sh" | grep "^built"
(cd "$REPO/agent/$OUT" && shasum -a 256 sohobotp-agent-* > SHA256SUMS)
echo
echo "Release $VERSION is in agent/$OUT"
echo "Portal (once): portal-admin.php release-key-set --key=$PUBLIC"
echo "Portal:        portal-admin.php agent-release-add --dir=<that folder on the portal server>"
