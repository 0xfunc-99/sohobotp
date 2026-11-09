#!/bin/sh
# Runs every SohobOTP test suite one after the other and prints a summary.
# Needs Docker; takes about 40 minutes the first time (images are cached afterwards).
#
#   sh run-all-tests.sh            everything
#   SKIP_AD=1 SKIP_WINE=1 sh run-all-tests.sh   without the Samba AD and the Wine MSI check
#
# Logs: test-results/<suite>.log
set -u
REPO="$(cd "$(dirname "$0")" && pwd)"
OUT="$REPO/test-results"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
STATUS=0

run() { # name, command, pattern of result lines to show
  name=$1; cmd=$2; pattern=$3
  printf '%-34s ' "$name"
  start=$(date +%s)
  if (cd "$REPO" && sh -c "$cmd") > "$OUT/$name.log" 2>&1; then result=PASS; else result=FAIL; STATUS=1; fi
  secs=$(( $(date +%s) - start ))
  detail=$(grep -E "$pattern" "$OUT/$name.log" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-110)
  fails=$(grep -c '^FAIL' "$OUT/$name.log" 2>/dev/null || true)
  line=$(printf '%-34s %s  %4ss  %s' "$name" "$result" "$secs" "$detail")
  [ "${fails:-0}" != 0 ] && line="$line  ($fails FAIL lines)"
  echo "$line" | cut -c36-
  echo "$line" >> "$SUMMARY"
}

echo "SohobOTP: all test suites ($(git -C "$REPO" rev-parse --short HEAD 2>/dev/null))"
if [ "${SKIP_AD:-}" = 1 ]; then
  run portal-unit-e2e "sh portal/tests/run-in-docker.sh" "checks passed"
else
  run portal-unit-e2e-ad "MULTIOTP_TEST_AD=1 sh portal/tests/run-in-docker.sh" "checks passed|AD checks"
fi
run appliance "sh portal/tests/run-appliance-test.sh" "checks passed"
run agent-unit-builds "sh agent/tests/run-in-docker.sh" "^ok|^FAIL|^---|vet ok"
run agent-e2e-debian "sh agent/tests/e2e-linux.sh" "end-to-end checks"
run agent-e2e-rocky "DISTRO=rocky sh agent/tests/e2e-linux.sh" "end-to-end checks"
run agent-msi "sh agent/packaging/windows/build-msi.sh" "^built"
if [ "${SKIP_WINE:-}" != 1 ]; then
  run agent-msi-windows-ui "sh agent/packaging/windows/check-msi-ui.sh && test -s agent/dist/msi-ui/2-filled-form.png" "^screenshot"
fi

echo
echo "Summary saved in test-results/summary.txt; logs in test-results/."
[ "$STATUS" = 0 ] && echo "ALL SUITES PASSED" || echo "SOME SUITES FAILED"
exit $STATUS
