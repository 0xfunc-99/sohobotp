# Fetches the embedded Windows PHP runtime (stable\php, stable\php_x86) from the upstream
# multiOTP Credential Provider at the pinned commit; it is not stored in this repository.
$ErrorActionPreference = "Stop"
$commit = "7ddc67a11227a6ace45087969cfb800d0ff61aa3"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$tmp = Join-Path $env:TEMP "sohobotp-upstream-$commit"
if (-not (Test-Path $tmp)) {
  git clone --filter=blob:none --no-checkout https://github.com/multiOTP/multiOTPCredentialProvider.git $tmp
  git -C $tmp sparse-checkout set stable/php stable/php_x86
  git -C $tmp checkout $commit
}
Copy-Item -Recurse -Force (Join-Path $tmp "stable\php") (Join-Path $here "stable\php")
Copy-Item -Recurse -Force (Join-Path $tmp "stable\php_x86") (Join-Path $here "stable\php_x86")
Write-Host "Embedded PHP copied into stable\php and stable\php_x86"
