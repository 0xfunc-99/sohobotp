# SohobOTP Windows end-to-end test (run as Administrator, on a test machine or the CI runner).
#
#   .\e2e.ps1 -AgentMsi sohobotp-agent.msi -FakePortal fakeportal.exe [-SignInMsi SohobOTPSignIn.msi]
#
# Installs SohobOTP Sign-in (or, without -SignInMsi, creates its registry key like its
# installer would), installs the agent MSI silently against a local test portal, then checks
# enrolment, the registry values the agent writes, the service, DPAPI-sealed keys, the token
# being deleted, restart after a crash, uninstall, and tamper protection (locked service,
# uninstall code, events). Exit code = number of failed checks.
param(
  [Parameter(Mandatory = $true)][string]$AgentMsi,
  [Parameter(Mandatory = $true)][string]$FakePortal,
  [string]$SignInMsi = "",
  [string]$UpgradeMsi = "",
  [string]$Work = (Join-Path $env:TEMP "sohobotp-e2e")
)
$ErrorActionPreference = "Continue"
$script:failures = 0
function Check([string]$name, [bool]$ok, [string]$detail = "") {
  if ($ok) { Write-Host "ok   $name" } else { Write-Host "FAIL $name  [$detail]"; $script:failures++ }
}
function Wait-Until([scriptblock]$cond, [int]$seconds) {
  $end = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $end) { if (& $cond) { return $true }; Start-Sleep -Seconds 2 }
  return $false
}

$work = $Work
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $work | Out-Null
$clsid = "{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}"
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
$cpKey = "HKCR:\CLSID\$clsid"

Write-Host "== SohobOTP Sign-in"
if ($SignInMsi -ne "") {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$SignInMsi`" /qn /l*v `"$work\signin-install.log`""
  Check "SohobOTP Sign-in MSI installs (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  Check "SohobOTP Sign-in DLL in System32" (Test-Path "$env:SystemRoot\System32\SohobOTPSignIn.dll")
  Check "registered as a Windows credential provider" (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid")
  Check "COM server registered" ((Get-ItemProperty "$cpKey\InprocServer32" -ErrorAction SilentlyContinue).'(default)' -like "*SohobOTPSignIn.dll")
} else {
  Write-Host "(no -SignInMsi: creating its registry key with the installer's value types)"
  New-Item -Force $cpKey | Out-Null
  New-ItemProperty -Force -Path $cpKey -Name multiOTPServerTimeout -PropertyType DWord -Value 5 | Out-Null
  New-ItemProperty -Force -Path $cpKey -Name multiOTPCacheEnabled -PropertyType String -Value "0" | Out-Null
  New-ItemProperty -Force -Path $cpKey -Name multiOTPServers -PropertyType String -Value "https://192.168.1.88" | Out-Null
}

Write-Host "== test portal"
$portal = Start-Process -FilePath $FakePortal -ArgumentList "--dir `"$work\portal`" --addr 127.0.0.1:8443" -PassThru -WindowStyle Hidden `
  -RedirectStandardError "$work\fakeportal.log"
Check "test portal started" (Wait-Until { Test-Path "$work\portal\pin.txt" } 30)
$token = (Get-Content "$work\portal\token.txt" -Raw).Trim()
$pin = (Get-Content "$work\portal\pin.txt" -Raw).Trim()
Copy-Item "$work\portal\ca.pem" "$work\ca.pem"

Write-Host "== agent MSI (silent, as Group Policy would)"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$AgentMsi`" /qn PORTAL=https://127.0.0.1:8443 TOKEN=$token PIN=$pin CAFILE=`"$work\ca.pem`" /l*v `"$work\agent-install.log`""
Check "agent MSI installs (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
$svc = Get-Service SohobOTPAgent -ErrorAction SilentlyContinue
Check "service SohobOTPAgent exists, automatic" ($null -ne $svc -and $svc.StartType -eq "Automatic")
Check "service running" (Wait-Until { (Get-Service SohobOTPAgent).Status -eq "Running" } 30)
$log = Get-Content "$work\agent-install.log" -Raw -ErrorAction SilentlyContinue
$leaks = @(Get-Content "$work\agent-install.log" -ErrorAction SilentlyContinue | Where-Object { $_.Contains($token) } |
  ForEach-Object { $_.Replace($token, "<TOKEN>") } | Select-Object -First 3)
Check "token not written to the MSI log" ($leaks.Count -eq 0) ($leaks -join " | ")
Check "token not in the registry (readable by all users)" ($null -eq (Get-ItemProperty "HKLM:\SOFTWARE\SohobOTP\Agent" -ErrorAction SilentlyContinue).Token)

Write-Host "== enrolment and configuration"
Check "agent enrolled and applied configuration 1" (Wait-Until {
  if (-not (Test-Path "$work\portal\state.json")) { return $false }
  $s = Get-Content "$work\portal\state.json" -Raw | ConvertFrom-Json
  return ($s.applied.version -eq 1 -and $s.applied.status -eq "applied")
} 120)
$expected = Get-Content "$work\portal\expected.json" -Raw | ConvertFrom-Json
$cp = Get-ItemProperty $cpKey
$protected = Get-ItemProperty "HKLM:\SOFTWARE\SohobOTP\SignIn" -ErrorAction SilentlyContinue
Check "shared secret in the protected key" ($null -ne $protected -and $protected.multiOTPSharedSecret -eq $expected.multiOTPSharedSecret)
Check "shared secret no longer in the Sign-in key every user can read" ($null -eq (Get-ItemProperty $cpKey).multiOTPSharedSecret)
$secretAcl = (Get-Acl "HKLM:\SOFTWARE\SohobOTP\SignIn").Access | ForEach-Object { $_.IdentityReference.Value }
Check "protected key: SYSTEM and Administrators only" (-not ($secretAcl -match "Users|Everyone|Authenticated") -and ($secretAcl -match "SYSTEM")) ($secretAcl -join ", ")
foreach ($name in "multiOTPServers", "cpus_logon", "cpus_unlock", "cpus_credui", "excluded_account", "login_text", "otp_text") {
  Check "registry $name" ($cp.$name -eq $expected.$name) "got '$($cp.$name)'"
}
$k = Get-Item $cpKey
Check "multiOTPServerTimeout kept as DWORD" ($k.GetValueKind("multiOTPServerTimeout") -eq "DWord")
Check "multiOTPCacheEnabled kept as its existing type, value 1" ($cp.multiOTPCacheEnabled -eq 1 -or $cp.multiOTPCacheEnabled -eq "1")
Check "multiOTPTimeoutUnlock written (10)" ($cp.multiOTPTimeoutUnlock -eq 10)
Check "multiOTPTimeoutReconnect written (15)" ($cp.multiOTPTimeoutReconnect -eq 15)
Check "accounts without a code written for SohobOTP Sign-in (svc-print)" ($cp.sohobotpCodeExempt -eq "svc-print")
Check "accounts without a code in admin prompts written (svc-print;helpdesk)" ($cp.sohobotpCodeExemptAdmin -eq "svc-print;helpdesk")

if ($SignInMsi -ne "") {
  Write-Host "== SohobOTP Sign-in pinned to the portal certificate"
  $mp = (Get-ItemProperty $cpKey).multiOTPPath
  Check "Sign-in finds its program: multiotp.exe and PHP in the folder multiOTPPath names" ((Test-Path (Join-Path $mp "multiotp.exe")) -and (Test-Path (Join-Path $mp "php\php.exe"))) $mp
  $caFile = Join-Path $mp "portal-ca.pem"
  $norm = { param($f) ((Get-Content $f -Raw) -replace "`r", "").Trim() }
  Check "agent wrote the portal CA into the Sign-in folder" (Wait-Until { (Test-Path $caFile) -and ((& $norm $caFile) -eq (& $norm "$work\portal\ca.pem")) } 60) $caFile
  Check "Sign-in's bundled engine checks the portal certificate" ($null -ne (Select-String -Path (Join-Path $mp "php\multiotp.windows.php") -SimpleMatch "written by the SohobOTP agent"))
  # the same TLS settings as the patched engine, run with Sign-in's own PHP
  @'
<?php
$ca = $argv[1] . DIRECTORY_SEPARATOR . 'portal-ca.pem';
$ctx = stream_context_create(['ssl' => ['verify_peer' => is_file($ca), 'verify_peer_name' => is_file($ca), 'cafile' => $ca,
    'disable_compression' => true, 'ciphers' => 'ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4']]);
$fp = @stream_socket_client('ssl://127.0.0.1:8443', $errno, $err, 10, STREAM_CLIENT_CONNECT, $ctx);
echo $fp ? "TLS-OK" : "TLS-FAIL $err";
'@ | Set-Content -Encoding ascii "$work\tls.php"
  $php = Join-Path $mp "php\php.exe"
  $out = (& $php "$work\tls.php" $mp 2>&1 | Out-String)
  Check "Sign-in's PHP connects to the portal with the pinned CA (IP address certificate)" ($out -match "TLS-OK") $out
  $other = Start-Process -FilePath $FakePortal -ArgumentList "--dir `"$work\other`" --addr 127.0.0.1:8444" -PassThru -WindowStyle Hidden
  Wait-Until { Test-Path "$work\other\ca.pem" } 30 | Out-Null
  Stop-Process -Id $other.Id -Force -ErrorAction SilentlyContinue
  Copy-Item $caFile "$work\pinned.pem"
  Copy-Item "$work\other\ca.pem" $caFile -Force
  $out = (& $php "$work\tls.php" $mp 2>&1 | Out-String)
  Check "with another CA the portal is refused (a man in the middle would be)" ($out -match "TLS-FAIL") $out
  Copy-Item "$work\pinned.pem" $caFile -Force
}

$boot = Get-ItemProperty "HKLM:\SOFTWARE\SohobOTP\Agent" -ErrorAction SilentlyContinue
Check "installer values in the registry, without the token" ($null -ne $boot -and $null -eq $boot.Token -and $boot.Portal -eq "https://127.0.0.1:8443")
Check "enrolment token deleted after enrolment" (-not (Test-Path "$env:ProgramData\SohobOTP\agent\enrol-token"))
$stateFile = "$env:ProgramData\SohobOTP\agent\agent.json"
$state = Get-Content $stateFile -Raw | ConvertFrom-Json
Check "private keys sealed with DPAPI" ($state.sign_seed.StartsWith("dpapi:") -and $state.box_private.StartsWith("dpapi:"))
$acl = (Get-Acl "$env:ProgramData\SohobOTP\agent").Access | ForEach-Object { $_.IdentityReference.Value }
Check "state folder: no access for Users or Everyone" (-not ($acl -match "Users|Everyone|Authenticated")) ($acl -join ", ")
$exe = "$env:ProgramFiles\SohobOTP\Agent\sohobotp-agent.exe"
$status = & $exe status 2>&1 | Out-String
Check "status shows the applied configuration" ($status -match "version 1, applied") $status
$inv = (Get-Content "$work\portal\state.json" -Raw | ConvertFrom-Json).inventory
Check "inventory reports Windows" ($inv.os -eq "windows" -and $inv.os_name -ne "") "$($inv.os_name)"
$names = @($inv.accounts | ForEach-Object { $_.name })
Check "inventory reports the local accounts, the administrator flagged" ($names.Count -ge 1 -and @($inv.accounts | Where-Object { $_.admin }).Count -ge 1) "$($names -join ', ')"

Write-Host "== service recovery"
$qf = (& sc.exe qfailure SohobOTPAgent) -join " "
Check "service restarts after a failure" ($qf -match "RESTART") $qf
$pid1 = (Get-CimInstance Win32_Service -Filter "Name='SohobOTPAgent'").ProcessId
Stop-Process -Id $pid1 -Force -ErrorAction SilentlyContinue
Check "service restarted after being killed" (Wait-Until {
  $s = Get-CimInstance Win32_Service -Filter "Name='SohobOTPAgent'"
  return ($s.State -eq "Running" -and $s.ProcessId -ne $pid1)
} 60)

$installed = $AgentMsi
if ($UpgradeMsi -ne "") {
  Write-Host "== upgrade with a newer MSI (as Group Policy would)"
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$UpgradeMsi`" /qn /l*v `"$work\agent-upgrade.log`""
  Check "newer agent MSI installs over the old one (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  $entries = @(Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -eq "SohobOTP Agent" })
  Check "one SohobOTP Agent in Programs, version 0.3.1" ($entries.Count -eq 1 -and $entries[0].DisplayVersion -eq "0.3.1") (($entries | ForEach-Object { $_.DisplayVersion }) -join ", ")
  Check "upgraded program installed" ((& $exe version 2>&1 | Out-String) -match "sohobotp-agent 0.3.1")
  Check "service running after the upgrade" (Wait-Until { (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue).Status -eq "Running" } 30)
  $after = Get-Content $stateFile -Raw | ConvertFrom-Json
  Check "machine identity kept by the upgrade" ($after.endpoint_id -eq $state.endpoint_id -and $after.sign_seed -eq $state.sign_seed)
  Check "upgraded agent checks in with its new version" (Wait-Until { (Get-Content "$work\portal\state.json" -Raw | ConvertFrom-Json).inventory.agent_version -eq "0.3.1" } 90)
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$AgentMsi`" /qn /l*v `"$work\agent-downgrade.log`""
  Check "older MSI refused over the newer one (exit $($p.ExitCode))" ($p.ExitCode -ne 0 -and ((& $exe version 2>&1 | Out-String) -match "sohobotp-agent 0.3.1"))
  $installed = $UpgradeMsi
}

Write-Host "== uninstall"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$installed`" /qn /l*v `"$work\agent-uninstall.log`""
Check "agent MSI uninstalls (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
Check "service removed" ($null -eq (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue))
Check "agent program removed" (-not (Test-Path $exe))
Check "agent identity removed (C:\ProgramData\SohobOTP\agent)" (-not (Test-Path "$env:ProgramData\SohobOTP\agent"))

Write-Host "== SohobOTP Sign-in removed, then the agent reinstalled BEFORE it"
if ($SignInMsi -ne "") {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$SignInMsi`" /qn"
  Check "SohobOTP Sign-in uninstalls (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  Check "SohobOTP Sign-in unregistered" (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"))
}
Remove-Item -Recurse -Force $cpKey -ErrorAction SilentlyContinue
$firstId = $expected.endpoint_id
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$AgentMsi`" /qn PORTAL=https://127.0.0.1:8443 TOKEN=$token PIN=$pin CAFILE=`"$work\ca.pem`" /l*v `"$work\agent-reinstall.log`""
Check "agent MSI installs again (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
$state2 = { if (Test-Path "$work\portal\state.json") { Get-Content "$work\portal\state.json" -Raw | ConvertFrom-Json } }
Check "reinstall enrols as a NEW machine; without Sign-in the configuration fails and is reported" (Wait-Until {
  $s = & $state2
  return ($null -ne $s -and $s.endpoint_id -ne $firstId -and $s.applied.version -eq 1 -and $s.applied.status -eq "failed")
} 120) "$((& $state2) | ConvertTo-Json -Compress -Depth 4)"
$retry = & $exe status 2>&1 | Out-String
Check "status shows the error and the next retry" ($retry -match "not installed" -and $retry -match "Next retry") $retry
if ($SignInMsi -ne "") {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$SignInMsi`" /qn /l*v `"$work\signin-install2.log`""
  Check "SohobOTP Sign-in installed after the agent (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
} else {
  New-Item -Force $cpKey | Out-Null
  New-ItemProperty -Force -Path $cpKey -Name multiOTPServerTimeout -PropertyType DWord -Value 5 | Out-Null
}
Check "the agent retries by itself and applies the configuration" (Wait-Until {
  $s = & $state2
  return ($null -ne $s -and $s.applied.version -eq 1 -and $s.applied.status -eq "applied")
} 240)
$expected = Get-Content "$work\portal\expected.json" -Raw | ConvertFrom-Json
Check "registry multiOTPServers points to the new machine" ((Get-ItemProperty $cpKey).multiOTPServers -eq $expected.multiOTPServers) "got '$((Get-ItemProperty $cpKey).multiOTPServers)'"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$AgentMsi`" /qn /l*v `"$work\agent-uninstall2.log`""
Check "agent MSI uninstalls again (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
if ($SignInMsi -ne "") {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$SignInMsi`" /qn"
  Check "SohobOTP Sign-in uninstalls again (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
}

if ($SignInMsi -ne "") {
  Write-Host "== SohobOTP Sign-in installed by the agent (computer policy: install automatically)"
  # the installer's own version (ProductVersion), read with Windows Installer
  $wi = New-Object -ComObject WindowsInstaller.Installer
  $db = $wi.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $wi, @($SignInMsi, 0))
  $view = $db.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $db, @("SELECT Value FROM Property WHERE Property='ProductVersion'"))
  $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
  $rec = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
  $msiVersion = $rec.GetType().InvokeMember("StringData", "GetProperty", $null, $rec, 1)
  $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null) | Out-Null
  foreach ($o in @($rec, $view, $db, $wi)) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($o) }
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  Check "installer version read ($msiVersion)" ($msiVersion -match '^\d+(\.\d+){1,3}$')
  $signinEntry = { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "SohobOTP Sign-in*" } | Select-Object -First 1 }
  Check "starting point: SohobOTP Sign-in not installed" ($null -eq (& $signinEntry))
  Remove-Item -Recurse -Force $cpKey -ErrorAction SilentlyContinue
  $auto = Start-Process -FilePath $FakePortal -ArgumentList "--dir `"$work\auto`" --addr 127.0.0.1:8445 --signin-msi `"$SignInMsi`" --signin-version $msiVersion" -PassThru -WindowStyle Hidden `
    -RedirectStandardError "$work\fakeportal-auto.log"
  Wait-Until { Test-Path "$work\auto\pin.txt" } 30 | Out-Null
  $autoToken = (Get-Content "$work\auto\token.txt" -Raw).Trim(); $autoPin = (Get-Content "$work\auto\pin.txt" -Raw).Trim()
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$AgentMsi`" /qn PORTAL=https://127.0.0.1:8445 TOKEN=$autoToken PIN=$autoPin CAFILE=`"$work\auto\ca.pem`" /l*v `"$work\agent-auto.log`""
  Check "agent MSI installs (only the agent) (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  $state3 = { if (Test-Path "$work\auto\state.json") { Get-Content "$work\auto\state.json" -Raw | ConvertFrom-Json } }
  Check "the agent installs SohobOTP Sign-in by itself and applies the configuration" (Wait-Until {
    $s = & $state3
    return ($null -ne $s -and $s.applied.version -eq 1 -and $s.applied.status -eq "applied")
  } 300) "$((& $state3) | ConvertTo-Json -Compress -Depth 4)"
  $entry = & $signinEntry
  Check "SohobOTP Sign-in $msiVersion installed" ($null -ne $entry -and $entry.DisplayVersion -eq $msiVersion) "$($entry.DisplayName) $($entry.DisplayVersion)"
  Check "registered on the sign-in screen" (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid")
  $autoExpected = Get-Content "$work\auto\expected.json" -Raw | ConvertFrom-Json
  Check "its settings written by the agent right after (portal address)" ((Get-ItemProperty $cpKey -ErrorAction SilentlyContinue).multiOTPServers -eq $autoExpected.multiOTPServers)
  $agentLog = Get-Content "$env:ProgramData\SohobOTP\agent\agent.log" -Raw -ErrorAction SilentlyContinue
  Check "agent log: installing SohobOTP Sign-in $msiVersion" ($agentLog -match "installing SohobOTP Sign-in $([regex]::Escape($msiVersion))") (($agentLog -split "`n" | Select-Object -Last 5) -join " | ")
  Check "the downloaded installer is not left on the machine" (-not (Test-Path "$env:ProgramData\SohobOTP\agent\packages"))
  Check "the portal sees the installed version at the next check-in" (Wait-Until { $s = & $state3; return ($null -ne $s -and $s.inventory.component.version -eq $msiVersion) } 120)
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$AgentMsi`" /qn /l*v `"$work\agent-uninstall3.log`""
  Check "agent MSI uninstalls (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$SignInMsi`" /qn"
  Check "SohobOTP Sign-in uninstalls (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  Stop-Process -Id $auto.Id -Force -ErrorAction SilentlyContinue
}


Write-Host "== tamper protection (computer policy): uninstall code, locked service, events"
$code = "ABCD-EFGH-JKLM"
$signinEntry2 = { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "SohobOTP Sign-in*" } | Select-Object -First 1 }
$agentEntry = { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq "SohobOTP Agent" } | Select-Object -First 1 }
$tpArgs = "--dir `"$work\tamper`" --addr 127.0.0.1:8446 --tamper-code $code"
if ($SignInMsi -ne "") {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$SignInMsi`" /qn"
  Check "SohobOTP Sign-in installed for the tamper test (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
  $signinVersionNow = (& $signinEntry2).DisplayVersion
  $tpArgs += " --signin-msi `"$SignInMsi`" --signin-version $signinVersionNow"
} else {
  New-Item -Force $cpKey | Out-Null
  New-ItemProperty -Force -Path $cpKey -Name multiOTPServerTimeout -PropertyType DWord -Value 5 | Out-Null
}
$tp = Start-Process -FilePath $FakePortal -ArgumentList $tpArgs -PassThru -WindowStyle Hidden -RedirectStandardError "$work\fakeportal-tamper.log"
Wait-Until { Test-Path "$work\tamper\pin.txt" } 30 | Out-Null
$tpToken = (Get-Content "$work\tamper\token.txt" -Raw).Trim(); $tpPin = (Get-Content "$work\tamper\pin.txt" -Raw).Trim()
$tpState = { if (Test-Path "$work\tamper\state.json") { Get-Content "$work\tamper\state.json" -Raw | ConvertFrom-Json } }
$tpEvents = { if (Test-Path "$work\tamper\events.json") { @(Get-Content "$work\tamper\events.json" -Raw | ConvertFrom-Json | ForEach-Object { $_ }) } else { @() } }
$hasEvent = { param($kind) @(& $tpEvents | Where-Object { $_.kind -eq $kind }).Count -ge 1 }
$installProtected = {
  param($logName)
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$AgentMsi`" /qn PORTAL=https://127.0.0.1:8446 TOKEN=$tpToken PIN=$tpPin CAFILE=`"$work\tamper\ca.pem`" /l*v `"$work\$logName`""
  if ($p.ExitCode -ne 0) { return $false }
  return (Wait-Until { $s = & $tpState; return ($null -ne $s -and $s.applied.version -eq 1 -and $s.applied.status -eq "applied" -and $s.inventory.protected -eq $true) } 180)
}
Check "agent installed, configuration applied, the portal is told the computer is protected" (& $installProtected "agent-tamper.log") "$((& $tpState) | ConvertTo-Json -Compress -Depth 4)"
$status = & $exe status 2>&1 | Out-String
Check "status: tamper protection on" ($status -match "Tamper protection: on") $status

# locked service: an administrator can look and start, nothing else
$out = (& sc.exe stop SohobOTPAgent 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "an administrator cannot stop the service (access denied)" ($rc -eq 5 -and (Get-Service SohobOTPAgent).Status -eq "Running") "exit $rc $out"
$out = (& sc.exe config SohobOTPAgent start= disabled 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "an administrator cannot disable the service" ($rc -eq 5 -and (Get-Service SohobOTPAgent).StartType -eq "Automatic") "exit $rc $out"
$out = (& sc.exe delete SohobOTPAgent 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "an administrator cannot delete the service" ($rc -eq 5 -and $null -ne (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue)) "exit $rc $out"
$out = (& sc.exe sdset SohobOTPAgent "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "an administrator cannot change the service's permissions" ($rc -eq 5) "exit $rc $out"
Check "the service can still be queried" ((& sc.exe query SohobOTPAgent | Out-String) -match "RUNNING")
$before = Get-Content $stateFile -Raw
$denied = $false; try { Set-Content -Path $stateFile -Value "{}" -ErrorAction Stop } catch { $denied = $true }
Check "the agent state is read-only for administrators" ($denied -and (Get-Content $stateFile -Raw) -eq $before)
$denied = $false; try { Remove-Item -Force $exe -ErrorAction Stop } catch { $denied = $true }
Check "the agent program cannot be deleted by an administrator" ($denied -and (Test-Path $exe))
# Windows Installer writes the agent's own entry at the end of its install, after the service
# started: the agent hides it at its next check of the machine (once a minute)
Check "Uninstall hidden in Windows' list of programs (agent)" (Wait-Until { $e = & $agentEntry; ($null -ne $e -and $e.NoRemove -eq 1 -and $e.NoModify -eq 1) } 120)
if ($SignInMsi -ne "") { Check "Uninstall hidden in Windows' list of programs (SohobOTP Sign-in)" ((& $signinEntry2).NoRemove -eq 1) }

# uninstall needs the code
$out = (& $exe uninstall 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "uninstall without the code refused" ($rc -ne 0 -and $out -match "uninstall code" -and (Get-Service SohobOTPAgent).Status -eq "Running") "exit $rc $out"
$out = (& $exe uninstall --code WRNG-WRNG-WRNG 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "uninstall with a wrong code refused" ($rc -ne 0 -and $out -match "wrong uninstall code") "exit $rc $out"
$out = (& $exe forget 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "the agent's identity cannot be deleted either (forget)" ($rc -ne 0 -and (Test-Path $stateFile)) "exit $rc $out"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$AgentMsi`" /qn /l*v `"$work\agent-tamper-x1.log`""
Check "Windows Installer uninstall without the code fails (exit $($p.ExitCode)), agent untouched" ($p.ExitCode -ne 0 -and (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue).Status -eq "Running" -and (Test-Path $exe))
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$AgentMsi`" /qn UNINSTALLCODE=WRNG-WRNG-WRNG /l*v `"$work\agent-tamper-x2.log`""
Check "Windows Installer uninstall with a wrong code fails (exit $($p.ExitCode))" ($p.ExitCode -ne 0 -and (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue).Status -eq "Running")
Check "the portal is told about the uninstall attempts" (Wait-Until { & $hasEvent "uninstall_refused" } 30) "$((& $tpEvents) | ConvertTo-Json -Compress)"

# settings changed by hand are put back and reported
Set-ItemProperty -Path $cpKey -Name cpus_logon -Value "3e"
Check "a sign-in setting changed by hand is put back within two minutes" (Wait-Until { (Get-ItemProperty $cpKey).cpus_logon -eq "0e" } 120) "cpus_logon '$((Get-ItemProperty $cpKey).cpus_logon)'"
Check "the portal is told that settings were put back" (Wait-Until { & $hasEvent "settings_restored" } 90) "$((& $tpEvents) | ConvertTo-Json -Compress)"

# killed: restarted by Windows, reported
$pid2 = (Get-CimInstance Win32_Service -Filter "Name='SohobOTPAgent'").ProcessId
Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
Check "the agent killed by an administrator starts again" (Wait-Until { $s = Get-CimInstance Win32_Service -Filter "Name='SohobOTPAgent'"; return ($s.State -eq "Running" -and $s.ProcessId -ne $pid2) } 60)
Check "the portal is told that the agent was killed" (Wait-Until { & $hasEvent "agent_killed" } 120) "$((& $tpEvents) | ConvertTo-Json -Compress)"
Check "still locked after the restart" ((& sc.exe stop SohobOTPAgent 2>&1 | Out-String) -match "denied|5" -and (Get-Service SohobOTPAgent).Status -eq "Running")

if ($SignInMsi -ne "") {
  # SohobOTP Sign-in removed by an administrator: installed again by the agent, reported
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$SignInMsi`" /qn"
  Check "SohobOTP Sign-in removed by hand (exit $($p.ExitCode))" ($p.ExitCode -eq 0 -and $null -eq (& $signinEntry2))
  Check "the agent installs SohobOTP Sign-in again by itself" (Wait-Until { $null -ne (& $signinEntry2) -and (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid") } 300)
  Check "the portal is told that SohobOTP Sign-in had been removed" (Wait-Until { & $hasEvent "signin_removed" } 120) "$((& $tpEvents) | ConvertTo-Json -Compress)"
  Check "its Uninstall button is hidden again" (Wait-Until { (& $signinEntry2).NoRemove -eq 1 } 120)
}

# the right code: the command removes the agent with Windows Installer
$out = (& $exe uninstall --code abcd-efgh-jklm 2>&1 | Out-String); $rc = $LASTEXITCODE
Check "uninstall with the right code accepted" ($rc -eq 0) "exit $rc $out"
Check "agent removed (service, program, identity, list of programs)" (Wait-Until {
  ($null -eq (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue)) -and (-not (Test-Path $exe)) -and (-not (Test-Path $stateFile)) -and ($null -eq (& $agentEntry))
} 120)
Check "the portal is told that the agent was uninstalled with the code" (& $hasEvent "uninstalled") "$((& $tpEvents) | ConvertTo-Json -Compress)"
if ($SignInMsi -ne "") { Check "SohobOTP Sign-in can be uninstalled again (button back)" ($null -eq (& $signinEntry2).NoRemove -or (& $signinEntry2).NoRemove -eq 0) }

# again, removed with Windows Installer and the code
Remove-Item "$work\tamper\state.json" -ErrorAction SilentlyContinue
Check "agent installed and protected again" (& $installProtected "agent-tamper2.log")
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$AgentMsi`" /qn UNINSTALLCODE=$code /l*v `"$work\agent-tamper-x3.log`""
Check "Windows Installer uninstall with the right code (exit $($p.ExitCode))" ($p.ExitCode -eq 0 -and $null -eq (Get-Service SohobOTPAgent -ErrorAction SilentlyContinue) -and -not (Test-Path $stateFile))
$leaks = @(Get-ChildItem "$work\agent-tamper-x*.log" | ForEach-Object { Get-Content $_ } | Where-Object { $_ -match "ABCD-EFGH-JKLM|WRNG-WRNG-WRNG" } | Select-Object -First 3)
Check "uninstall codes not written to the Windows Installer logs" ($leaks.Count -eq 0) ($leaks -join " | ")
if ($SignInMsi -ne "") {
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$SignInMsi`" /qn"
  Check "SohobOTP Sign-in uninstalls (exit $($p.ExitCode))" ($p.ExitCode -eq 0)
}
Stop-Process -Id $tp.Id -Force -ErrorAction SilentlyContinue

Stop-Process -Id $portal.Id -Force -ErrorAction SilentlyContinue
Write-Host ""
if ($script:failures -eq 0) { Write-Host "All Windows checks passed." } else { Write-Host "$($script:failures) Windows check(s) failed." }
exit $script:failures
