<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Group Policy kit: one zip an Active Directory administrator copies to a share and names in
 * a computer startup script, so every Windows computer of an OU installs the SohobOTP agent
 * by itself at its next start.
 *
 *   SohobOTP-GroupPolicy/
 *     README.txt               the steps, in order
 *     Install-SohobOTP.cmd     the startup script to name in the Group Policy
 *     Install-SohobOTP.ps1     what it runs: installs the agent when the computer has none
 *     sohobotp-agent-amd64.exe the plain agent programs (no token inside)
 *     sohobotp-agent-arm64.exe
 *     portal-ca.pem            the portal's certificate authority, when it is not a public one
 *
 * The kit holds an enrolment token (in the .ps1). Every domain user can read a startup script,
 * so the token should be one with approval: a copied token then cannot add an unknown machine.
 * After the install the agent keeps itself (and SohobOTP Sign-in) up to date: the kit is only
 * needed again for new computers once its token has expired.
 */
final class GpoKit
{
    public const FOLDER = 'SohobOTP-GroupPolicy';

    /**
     * @param array<string, string> $programs arch (amd64, arm64) => agent program file
     * @param array{group: string, expires_at: int, max_uses: int, approval: string, tamper: bool, signin_auto: bool} $about
     */
    public static function build(string $portal, string $token, string $pin, string $caPem, array $programs, array $about, int $now): string
    {
        if ([] === $programs) {
            throw new ValidationException('The portal has no Windows agent program yet (portal-admin.php agent-program-add or agent-release-add).');
        }
        $files = [
            'README.txt' => self::crlf(self::readme($portal, array_keys($programs), '' !== $caPem, $about, $now)),
            'Install-SohobOTP.cmd' => self::crlf(self::cmd()),
            'Install-SohobOTP.ps1' => self::crlf(self::script($portal, $token, $pin, $about, $now)),
        ];
        if ('' !== $caPem) {
            $files['portal-ca.pem'] = $caPem;
        }
        $zip = new ZipWriter($now);
        foreach ($files as $name => $content) {
            $zip->add(self::FOLDER . '/' . $name, $content);
        }
        foreach ($programs as $arch => $file) {
            $data = @file_get_contents($file);
            if (false === $data) {
                throw new \RuntimeException('Cannot read the agent program.');
            }
            $zip->add(self::FOLDER . "/sohobotp-agent-$arch.exe", $data);
        }
        return $zip->finish();
    }

    private static function crlf(string $text): string
    {
        return str_replace("\n", "\r\n", str_replace("\r", '', $text));
    }

    private static function cmd(): string
    {
        return <<<'CMD'
@echo off
rem SohobOTP: computer startup script for Group Policy. It runs Install-SohobOTP.ps1 from the
rem same folder (see README.txt). Runs as SYSTEM; does nothing when the agent is installed.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Install-SohobOTP.ps1"
exit /b %ERRORLEVEL%

CMD;
    }

    /** PowerShell single-quoted string. */
    private static function quote(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }

    private static function script(string $portal, string $token, string $pin, array $about, int $now): string
    {
        $made = gmdate('Y-m-d', $now);
        $until = gmdate('Y-m-d H:i', $about['expires_at']) . ' UTC';
        $policy = str_replace(["\r", "\n"], ' ', $about['group']);
        $portalQ = self::quote($portal);
        $tokenQ = self::quote($token);
        $pinQ = self::quote($pin);
        return <<<PS1
# SohobOTP agent: installed by Group Policy (computer startup script, runs as SYSTEM).
# Made by the SohobOTP portal on $made for the computer policy "$policy".
# The enrolment token below works until $until, for up to {$about['max_uses']} computers.
# Everyone in the domain can read this file: revoke the token in the portal (Computers,
# Enrolment tokens) if it should no longer be used.
\$Portal = $portalQ
\$Pin    = $pinQ
\$Token  = $tokenQ

\$ErrorActionPreference = 'Stop'
\$Here = Split-Path -Parent \$MyInvocation.MyCommand.Path
\$LogDir = Join-Path \$env:ProgramData 'SohobOTP'
\$Log = Join-Path \$LogDir 'gpo-install.log'
function Write-Log([string]\$Message) {
    New-Item -ItemType Directory -Force -Path \$LogDir | Out-Null
    Add-Content -Path \$Log -Value ('{0} {1}' -f (Get-Date -Format 's'), \$Message)
}
\$setup = \$null; \$caCopy = \$null
try {
    # installed already: nothing to do (the agent updates itself and SohobOTP Sign-in)
    if (Get-Service -Name 'SohobOTPAgent' -ErrorAction SilentlyContinue) { exit 0 }
    \$arch = 'amd64'
    if (\$env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or \$env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { \$arch = 'arm64' }
    \$source = Join-Path \$Here "sohobotp-agent-\$arch.exe"
    if (-not (Test-Path \$source)) {
        if (\$arch -eq 'arm64' -and (Test-Path (Join-Path \$Here 'sohobotp-agent-amd64.exe'))) {
            \$source = Join-Path \$Here 'sohobotp-agent-amd64.exe' # Windows 11 on ARM runs the Intel/AMD program
        } else {
            Write-Log "no agent program for \$arch in \$Here"; exit 1
        }
    }
    # a local copy: the share may not stay reachable during the install
    \$setup = Join-Path \$env:SystemRoot 'Temp\\sohobotp-agent-setup.exe'
    Copy-Item -Force -Path \$source -Destination \$setup
    \$arguments = @('install', '--portal', \$Portal, '--token', \$Token, '--pin', \$Pin)
    \$ca = Join-Path \$Here 'portal-ca.pem'
    if (Test-Path \$ca) {
        \$caCopy = Join-Path \$env:SystemRoot 'Temp\\sohobotp-portal-ca.pem'
        Copy-Item -Force -Path \$ca -Destination \$caCopy
        \$arguments += @('--ca-file', \$caCopy)
    }
    \$ErrorActionPreference = 'Continue'
    \$output = (& \$setup @arguments 2>&1 | Out-String).Trim()
    \$code = \$LASTEXITCODE
    Write-Log ("sohobotp-agent install on {0}: exit {1}. {2}" -f \$env:COMPUTERNAME, \$code, \$output)
    exit \$code
} catch {
    Write-Log "error: \$_"
    exit 1
} finally {
    if (\$setup) { Remove-Item -Force -Path \$setup -ErrorAction SilentlyContinue }
    if (\$caCopy) { Remove-Item -Force -Path \$caCopy -ErrorAction SilentlyContinue }
}

PS1;
    }

    private static function readme(string $portal, array $archs, bool $withCa, array $about, int $now): string
    {
        $made = gmdate('Y-m-d', $now);
        $until = gmdate('Y-m-d H:i', $about['expires_at']) . ' UTC';
        $approval = [
            'none' => 'Computers are active as soon as they enrol.',
            'manual' => 'Each new computer waits in the portal (Computers, Waiting for approval) until you approve it.',
            'directory' => 'A new computer is approved by itself when the portal finds its computer account in Active Directory; any other waits for your approval.',
        ][$about['approval']] ?? '';
        $programs = implode(', ', array_map(static fn (string $a): string => "sohobotp-agent-$a.exe (" . ('arm64' === $a ? 'Windows on ARM' : 'Intel/AMD') . ')', $archs));
        $signin = $about['signin_auto']
            ? 'The policy has "Install and update SohobOTP Sign-in automatically": the agent installs SohobOTP Sign-in (the code on the sign-in screen) by itself. Nothing else to deploy.'
            : 'IMPORTANT: the policy does NOT have "Install and update SohobOTP Sign-in automatically". Turn it on in the portal (Computers, Computer policies, the policy), or deploy SohobOTPSignIn.msi yourself: without SohobOTP Sign-in the sign-in screen does not ask for a code.';
        $tamper = $about['tamper']
            ? 'The policy has Tamper protection: users who are administrators of their computer cannot remove the agent without the computer\'s uninstall code (portal: Computers, the computer, Show the uninstall code).'
            : 'Tip: turn on "Tamper protection" in the computer policy, so users who are administrators of their computer cannot remove the agent.';
        $ca = $withCa ? "\n  portal-ca.pem             the certificate the computers need to trust the portal" : '';
        return <<<TXT
SohobOTP - Group Policy kit
===========================
Made on $made by the portal $portal
Computer policy: {$about['group']}
Enrolment token: works until $until, for up to {$about['max_uses']} computers.
$approval

What this does
--------------
Every Windows computer that gets this Group Policy installs the SohobOTP agent by itself the
next time it starts, and joins the computer policy above. No visit to the computer, nothing to
type. Computers that already have the agent are left alone.

$signin

$tamper

In this folder
--------------
  Install-SohobOTP.cmd      the startup script you name in the Group Policy
  Install-SohobOTP.ps1      what it runs (portal address, pin and token are inside)
  $programs$ca

Steps
-----
1. Copy this whole folder to a share every domain computer can read. The usual place:
       \\\\<your domain>\\NETLOGON\\SohobOTP
   (on a domain controller that is C:\\Windows\\SYSVOL\\sysvol\\<your domain>\\scripts\\SohobOTP)

2. On a domain controller open "Group Policy Management". Right-click the OU that holds the
   computers (start with a test OU with one or two computers), choose
   "Create a GPO in this domain, and Link it here...", name it "SohobOTP agent".

3. Right-click the new GPO, Edit. Go to
       Computer Configuration > Policies > Windows Settings > Scripts (Startup/Shutdown) > Startup
   On the "Scripts" tab press Add, and as Script Name type the full network path:
       \\\\<your domain>\\NETLOGON\\SohobOTP\\Install-SohobOTP.cmd
   Leave Script Parameters empty. OK.

4. In the same GPO, so the network is ready when the script runs:
       Computer Configuration > Policies > Administrative Templates > System > Logon >
       "Always wait for the network at computer startup and logon" = Enabled

5. Restart a test computer (startup scripts only run at start; "gpupdate /force" first makes
   it pick up the new policy sooner). After a minute or two it appears in the portal under
   Computers. On the computer, the result is in C:\\ProgramData\\SohobOTP\\gpo-install.log

6. When the test computer works (sign out, sign in with password and code), link the GPO to
   the other OUs.

Good to know
------------
- The script only installs. Updates come from the portal: the agent updates itself (computer
  policy, "Agent version") and updates SohobOTP Sign-in.
- The token is readable by every domain user (it is in a startup script). That is why new
  computers should need approval. To stop it: portal, Computers, Enrolment tokens, Revoke.
- After $until new computers can no longer enrol with this kit: make a new kit in the portal
  (Add a computer, Group Policy kit) and replace the folder on the share. Computers that are
  already enrolled are not affected.
- Removing the GPO does not uninstall the agent. To remove it from a computer:
      "C:\\Program Files\\SohobOTP\\Agent\\sohobotp-agent.exe" uninstall
  (with tamper protection: add  --code  and the computer's uninstall code from the portal).
- The portal must be reachable from the computers at $portal when they start.

TXT;
    }
}
