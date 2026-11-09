#!/bin/sh
# Shows the MSI's installer windows under Wine on a virtual display, fills the form and takes
# screenshots into agent/dist/msi-ui/ (1-empty-form, 2-filled-form, 3-after-install).
# Wine cannot start the agent service, so the last screenshot is the error window; on real
# Windows the install ends on the finish window. First run downloads about 1 GB.
# Usage (from the repository root, after build-msi.sh):  sh agent/packaging/windows/check-msi-ui.sh
set -eu
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
docker build --platform linux/amd64 -q -t sohobotp-wine "$REPO/agent/packaging/windows/wine" >/dev/null
mkdir -p "$REPO/agent/dist/msi-ui"
docker run --rm --platform linux/amd64 -v "$REPO/agent":/agent:ro -v "$REPO/agent/dist/msi-ui":/out \
  -v "$REPO/agent/packaging/windows/wine/render.sh":/render.sh:ro sohobotp-wine sh /render.sh
