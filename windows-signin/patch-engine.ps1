# SohobOTP Sign-in: patch the multiOTP engine bundled with the embedded PHP runtime
# (stable\php\multiotp.windows.php and stable\php_x86\..., fetched by get-php.ps1).
#
# Upstream turns TLS certificate checks off for the client -> server requests. SohobOTP turns
# them on whenever portal-ca.pem exists in the SohobOTP Sign-in folder: the SohobOTP agent
# writes there the certificate authority that verified the portal (its own pinned TLS), so
# Sign-in only talks to that portal. Without the file (Sign-in not managed by an agent) the
# upstream behaviour stays. The file is patched byte for byte (CRLF kept); the build stops
# if the expected upstream text is not found. The file mixes UTF-8 and Latin-1 bytes: it is
# read and written as ISO-8859-1, which maps every byte to itself.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$oldLines = @(
  "      `$this->_default_ssl_context = array(",
  "          'ssl' => array(",
  "              'verify_peer'         => false,",
  "              'verify_peer_name'    => false,"
)
$newLines = @(
  "      `$this->_default_ssl_context = array(",
  "          'ssl' => array(",
  "              // SohobOTP: verify the portal with the CA written by the SohobOTP agent",
  "              'verify_peer'         => is_file(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'portal-ca.pem'),",
  "              'verify_peer_name'    => is_file(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'portal-ca.pem'),",
  "              'cafile'              => dirname(__DIR__) . DIRECTORY_SEPARATOR . 'portal-ca.pem',"
)
$bytes = [System.Text.Encoding]::GetEncoding(28591) # ISO-8859-1: byte for byte
foreach ($folder in "stable\php", "stable\php_x86") {
  $file = Join-Path $here "$folder\multiotp.windows.php"
  if (-not (Test-Path $file)) { continue }
  $text = [System.IO.File]::ReadAllText($file, $bytes)
  if ($text.Contains("verify the portal with the CA written by the SohobOTP agent")) {
    Write-Host "$folder\multiotp.windows.php already patched"
    continue
  }
  $done = $false
  foreach ($nl in "`r`n", "`n") { # the upstream file mixes CRLF and LF lines: keep what is there
    $old = $oldLines -join $nl
    $count = ([regex]::Matches($text, [regex]::Escape($old))).Count
    if ($count -gt 1) { throw "$file : the upstream TLS settings appear $count times (upstream changed?)" }
    if ($count -eq 1) {
      [System.IO.File]::WriteAllText($file, $text.Replace($old, ($newLines -join $nl)), $bytes)
      $done = $true
      break
    }
  }
  if (-not $done) { throw "$file : upstream TLS settings not found (upstream changed?)" }
  Write-Host "$folder\multiotp.windows.php patched: portal certificate checked with portal-ca.pem"
}
