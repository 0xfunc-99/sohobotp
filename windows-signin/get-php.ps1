# Fetches the third-party files SohobOTP Sign-in bundles, unchanged, from the upstream
# multiOTP Credential Provider at the pinned commit (they are not stored in this repository):
#   stable\php, stable\php_x86   embedded Windows PHP runtime (PHP License 3.01)
#   tools\x64, tools\i386        SetACL.exe by Helge Klein (LGPL-3.0), used by the installer
#                                to restrict the permissions of its registry key and folders
$ErrorActionPreference = "Stop"
$commit = "7ddc67a11227a6ace45087969cfb800d0ff61aa3"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$tmp = Join-Path $env:TEMP "sohobotp-upstream-$commit"
if (-not (Test-Path $tmp)) {
  git clone --filter=blob:none --no-checkout https://github.com/multiOTP/multiOTPCredentialProvider.git $tmp
}
git -C $tmp sparse-checkout set stable/php stable/php_x86 tools
git -C $tmp checkout $commit
Copy-Item -Recurse -Force (Join-Path $tmp "stable\php") (Join-Path $here "stable\php")
Copy-Item -Recurse -Force (Join-Path $tmp "stable\php_x86") (Join-Path $here "stable\php_x86")
New-Item -ItemType Directory -Force (Join-Path $here "tools") | Out-Null
Copy-Item -Recurse -Force (Join-Path $tmp "tools\x64") (Join-Path $here "tools\x64")
Copy-Item -Recurse -Force (Join-Path $tmp "tools\i386") (Join-Path $here "tools\i386")
Write-Host "Embedded PHP copied into stable\php and stable\php_x86, SetACL into tools"
& (Join-Path $here "patch-engine.ps1")
