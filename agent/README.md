# SohobOTP agent

The agent runs on each managed Linux or Windows machine. It enrols once with a token, then
checks in with the SohobOTP portal over HTTPS, applies the signed configuration of its
endpoint group, and reports inventory and the result. Protocol:
[portal/docs/agent-protocol.md](../portal/docs/agent-protocol.md); design:
[portal/docs/endpoints.md](../portal/docs/endpoints.md).

## Install

Simplest: the portal's **Download agent** page gives an agent with the portal address, a new
enrolment token, the pin and the CA certificate built in. Run it on the machine: `install`
with no options (Windows: double-click). The settings sit at the end of the downloaded file
(`internal/bundle`); the installed copy is the plain program, without the token.

Or create an enrolment token on the portal's **Enrol endpoints** page; it shows the commands.

```sh
# Linux, as root
sohobotp-agent install --portal https://portal.example.com --token <TOKEN> --pin <PIN>
```

```powershell
# Windows, administrator PowerShell (install SohobOTP Sign-in (SohobOTPSignIn.msi) first)
.\sohobotp-agent.exe install --portal https://portal.example.com --token <TOKEN> --pin <PIN>
```

Add `--ca-file ca.pem` when the portal certificate is not publicly trusted (the appliance's
self-signed one). Verification is never switched off.

**Windows, by hand:** double-click `sohobotp-agent.msi` (as an administrator). The setup window
asks for the portal address, the enrolment token, the pin and, if the portal uses its own
certificate, the CA file; **Install** stays disabled until the first three are filled in.
Install SohobOTP Sign-in first.

![MSI setup window](docs/msi-setup-window.png)

**Group Policy (Windows):** deploy `sohobotp-agent.msi` silently (Computer Configuration →
Software Installation, with a transform setting the properties, or a startup script); silent
installs skip the windows:

```powershell
msiexec /i sohobotp-agent.msi /qn PORTAL=https://portal.example.com TOKEN=<TOKEN> PIN=<PIN> [CAFILE=C:\path\ca.pem]
```

The MSI installs the agent and the `SohobOTPAgent` service and writes PORTAL, PIN and CAFILE
to `HKLM\SOFTWARE\SohobOTP\Agent`. The token is **not** written there (every user can read
that key, and Windows Installer logs registry values): a custom action hidden from the log
runs `sohobotp-agent.exe save-token`, which keeps it in the agent's state folder (SYSTEM and
Administrators only). The service enrols on its first start and **deletes the token**. Use an enrolment token with *Active Directory
approval*: anyone can read a GPO's files, so a copied token must not admit unknown machines.
Build: `sh agent/packaging/windows/build-msi.sh` (msitools in Docker; the installer windows
are tables in `packaging/windows/ui/` added with msibuild). `check-msi-ui.sh` shows them under
Wine and takes screenshots. **Upgrades**: a newer MSI (`AGENT_VERSION=x.y.z`, the version
must grow) installed over an older one, by hand or by Group Policy, replaces it in place and
keeps the machine's identity; an older MSI over a newer one is refused (tables added by
build-msi.sh, see `packaging/windows/tables/README.md`). Self-update works as well.

Other commands: `status`, `run --once` (check in now), `apply --dry-run --config FILE`
(Linux: show what a policy would change), `uninstall [--code CODE]`, `upgrade`, `version`.

**Upgrade by hand:** run a newer agent program on an enrolled machine (`sohobotp-agent
upgrade`, `install`, or a double-click on a newer download from the portal): it replaces the
installed program, restarts the service and keeps the enrolment. Refused when the installed
agent is not older, and on a machine with tamper protection (there the agent updates itself).

**Many Windows computers:** the portal's *Add a computer* page makes a **Group Policy kit**: a
zip with a computer startup script (`Install-SohobOTP.cmd` / `.ps1`), the plain agent programs,
the portal certificate and a README with the Group Policy steps (`portal/src/GpoKit.php`).

## Tamper protection

Computer policy **Tamper protection** in the portal (agent 0.3.0 or later). The signed
configuration then carries the switch and the hash of the computer's own **uninstall code**
(the code itself stays in the portal: Computers → the computer → *Show the uninstall code*).

| | Linux | Windows |
|---|---|---|
| Uninstall | `sohobotp-agent uninstall --code XXXX-XXXX-XXXX` (`.deb`: `sudo SOHOBOTP_UNINSTALL_CODE=... apt remove sohobotp-agent`) | the same command (an MSI install is then removed by Windows Installer), or `msiexec /x {…} UNINSTALLCODE=XXXX-XXXX-XXXX` |
| Without the code | refused; five wrong codes block codes for 15 minutes | the same; Windows Installer ends with an error before anything is removed (custom action `CheckUninstall`) |
| Service | — (root can always stop it; a stop is reported) | administrators cannot stop, disable, reconfigure or delete `SohobOTPAgent`, nor change its permissions (service DACL; SYSTEM keeps full control, so MSI upgrades and self-update work) |
| Files | — | program folder and state folder read-only for administrators (state folder owned by SYSTEM) |
| Programs list | — | *Uninstall* and *Change* hidden for SohobOTP Agent and SohobOTP Sign-in (`NoRemove`, `NoModify`; previous values restored) |
| Watch (every minute) | the configuration is applied again: PAM, sshd and RADIUS files changed by hand are put back | the same for the Sign-in settings; SohobOTP Sign-in removed by hand is installed again when the policy has its installers; start type and permissions of the service put back |
| Reported to the portal | uninstall attempts, the code accepted, settings put back, the service stopped by hand (`systemctl stop`, not a shutdown), the process killed | the same |

How the code is checked: the command (or the MSI) leaves a request in the requests folder
(`/etc/sohobotp-agent/requests`, `%ProgramData%\SohobOTP\agent-requests`); the **running
service** checks the code against the hash, answers, reports the attempt, and on the right code
unlocks the machine for 10 minutes. The command never decides by itself; when the service is not
running it checks the code directly (needs root, or SYSTEM on Windows). Turning the policy off
in the portal (or moving the computer to a policy without it) lifts everything at the next
check-in.

**Limits.** A local administrator who is determined can still get around it: take ownership of
the service or the folders, run a program as SYSTEM, start the computer from other media, or
remove SohobOTP Sign-in while the computer cannot reach the portal and the policy does not
install it automatically. Tamper protection makes that deliberate work, visible in the portal
when the computer is online; it is not a replacement for taking administrator rights away from
users. A computer that stays **Offline** in the portal deserves a look.

## What it changes

**Linux** (PAM → RADIUS, `libpam-radius-auth` / `pam_radius`, installed if missing):

| File | Content |
|---|---|
| `/etc/pam.d/sshd`, `sudo`, `login`, `su` (as the policy says) | two lines added after the password step: a marker and `auth include sohobotp-2fa`. On RHEL an `auth include system-auth` step becomes `auth substack system-auth` (its `sufficient pam_unix` would otherwise end the stack before the code); the original line is kept in the marker and restored |
| `/etc/pam.d/sohobotp-2fa` | exclusions (root always; users; groups) that skip **only** the code, then `pam_radius_auth.so ... prompt=code force_prompt` |
| `/etc/pam_radius_auth.conf` (Debian/Ubuntu), `/etc/pam_radius.conf` (RHEL/Rocky 9) or `/etc/raddb/server` (older RHEL) | RADIUS servers and this machine's own secret, root 0600; a pre-existing file is kept as `.sohobotp-orig` |
| `/etc/ssh/sshd_config.d/00-sohobotp.conf` (sorts first: sshd keeps the first value, and RHEL's `50-redhat.conf` turns keyboard-interactive off) | `KbdInteractiveAuthentication yes`, `PasswordAuthentication no` (passwords go through PAM so the code is asked), optional `AuthenticationMethods publickey,keyboard-interactive` |

Every apply is snapshotted; any failure (including `sshd -t`) restores all files. Turning
2FA off in the portal restores the files byte for byte.

**Windows**: the registry values of SohobOTP Sign-in (Sohobcom fork of the multiOTP Credential Provider)
(`HKCR\CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}`): the machine's own gateway URL
(`portal/cp.php?e=<id>`) and secret, sign-in / unlock / UAC modes, break-glass account,
offline cache and texts. Existing value types are kept; the agent refuses to run without
the Credential Provider; failures restore the previous values.

## Files and service

| | Linux | Windows |
|---|---|---|
| State and keys | `/etc/sohobotp-agent/` (0700, files 0600) | `%ProgramData%\SohobOTP\agent\` (SYSTEM and Administrators only) |
| Binary | `/usr/local/sbin/sohobotp-agent` | `%ProgramFiles%\SohobOTP\Agent\sohobotp-agent.exe` |
| Service | `sohobotp-agent.service` (systemd, restart always) | `SohobOTPAgent` ("SohobOTP Agent", automatic, restart on failure) |
| Log | journal (`journalctl -u sohobotp-agent`) | `agent.log` in the state folder |

## Security choices

- The portal key is pinned at install (`--pin`); configurations signed by another key, for
  another endpoint or OS, or not newer than the applied version are never applied.
- Each request is signed with the machine's Ed25519 key (time + nonce, no replay); secrets
  in configurations are sealed to its X25519 key. Private keys never leave the machine.
- When the portal is unreachable, refuses the machine (disabled) or keeps it pending, the
  last applied configuration stays: 2FA is never removed by a failure.
- Windows private keys are encrypted with DPAPI (machine scope) inside a folder readable by
  SYSTEM and Administrators only: a copied state file is useless on another machine.
- Self-update (below) only installs releases signed with the offline release key built into
  the agent, never older versions, and only if size and SHA-256 match.

## Self-update (signed releases)

**In one step:** `AGENT_VERSION=x.y.z sh agent/packaging/release.sh` does 1 and 2 below: it
creates the release key in `~/SohobOTP-release-key` the first time (override with
`RELEASE_KEY_DIR`), builds and signs the four programs (Linux and Windows, Intel/AMD and ARM) and
the Windows MSI into `agent/dist/release-x.y.z/`. Then step 3 with `--dir`. Back the key folder
up; never copy `release-private.key` to the portal or into the repository. `sohobotp-agent
version` shows the release key an agent was built with; an agent built without one (0.2.0 and
older downloads) cannot update itself and needs one `upgrade` by hand.

1. Once, on an offline machine: `sohobotp-agent release keygen --out /secure/folder`. Keep
   `release-private.key` there; build agents with the printed public key:
   `AGENT_VERSION=x.y.z RELEASE_PUBLIC_KEY=<key> sh agent/tests/run-in-docker.sh`.
2. For each release and platform: `sohobotp-agent release sign --key release-private.key
   --file sohobotp-agent-linux-amd64 --version x.y.z --os linux --arch amd64 --out manifest.json`.
3. On the portal: `portal-admin.php release-key-set --key=<public key>` once (the portal then
   refuses uploads signed with another key, and each computer's page says whether its agent can
   update itself), then `portal-admin.php agent-release-add --dir=<release folder>` (or
   `--file=... --manifest=...` for one program).
4. Choose the version as the endpoint group's **Agent version**. Older agents download it
   through the signed agent API and verify it, then:
   - **self-test**: the new binary is run once (`selftest --expect-version x.y.z`: right
     version, opens this agent's keys); a release that does not start is never installed;
   - the running binary is kept as `<binary>.previous`, the new one takes its place, and the
     agent restarts (systemd `Restart=always`; Windows recovery actions);
   - **roll back**: if the new version stops 3 times before its first successful check-in, it
     puts `.previous` back and exits, so the old version runs again; that version is then
     never installed again on this machine (`status`: "Update blocked"; publish a fixed
     version with a new number). The first successful check-in confirms the update.
   A refused release is retried after an hour at the earliest; the reason is in `status`.

## Tests

```sh
sh agent/tests/run-in-docker.sh   # gofmt, go vet (Linux + Windows), race tests, builds into agent/dist/
sh agent/tests/e2e-linux.sh       # production image + Debian endpoint, real FreeRADIUS and SSH
```

The end-to-end test (51 checks; `DISTRO=rocky` runs it on Rocky Linux 9) covers:
- enrolment (wrong pin refused, TLS with a test CA);
- password + code over SSH and sudo, wrong code, wrong password, a real SSH session;
- excluded user, break-glass group, root;
- RADIUS down (only users needing a code refused) and back;
- a policy change from the portal (sudo restored byte for byte), 2FA off (all files restored);
- self-update: a release signed with another key refused, a signed one installed and
  reported, the updated agent still enforcing the policy; a signed release that does not
  start refused by the self-test; a release that crashes after starting rolled back by
  itself after 3 starts and not installed again;
- tamper protection: uninstall without the code and with a wrong code refused, both attempts
  shown in the portal, the computer shown as protected;
- uninstall (with the computer's code from the portal).

Unit tests reproduce every libsodium protocol vector and cover the PAM and registry appliers
(rollback, refusals, RHEL layout).

## Windows: automatic test on real Windows, then the manual test

`.github/workflows/windows.yml` (in a **private** GitHub repository) compiles SohobOTP Sign-in
on Windows and, on a Windows Server 2022 machine, runs the agent's Go tests (real registry,
DPAPI) and `tests/windows/e2e.ps1`: both MSIs installed silently, enrolment against
`tests/fakeportal`, the registry values and their types, the token never in the registry or
the installer log and deleted after enrolment, DPAPI keys, the state folder ACL, service
recovery, uninstall, and tamper protection: the service an administrator cannot stop, disable,
delete or re-permission, read-only state and program, hidden Uninstall buttons, uninstall
refused without or with a wrong code (command and Windows Installer), a setting changed by hand
put back, the killed agent restarted and reported, SohobOTP Sign-in removed by hand installed
again, uninstall with the right code both ways. `e2e.ps1` also runs by hand on a test machine.

What it cannot do is sign in at the Windows sign-in screen. Before production, on a
Windows 11 / Server 2022 test machine:

1. Install SohobOTP Sign-in (SohobOTPSignIn.msi), then the agent with a token.
   `sohobotp-agent.exe status` shows version 1 applied; the portal shows the inventory.
2. `reg query "HKCR\CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}"`: `multiOTPServers`
   is the `cp.php?e=` URL, the secret is not `ClientServerSecret`, types are unchanged.
3. Sign in (console and RDP) with password + code; wrong code refused; break-glass account
   needs no code; unlock and UAC follow the group's modes.
4. Offline: unplug the network after one successful login; the cached login works if the
   group allows the offline cache, and stops after the lifetime.
5. Change the group in the portal; after `run --once` (or 60 s) the new values are in the
   registry. Disable the endpoint; sign-in through the gateway is refused.
6. `services.msc`: SohobOTP Agent running, restarts after being killed; `uninstall` removes
   it.
7. MSI by double-click: the setup window, Install disabled until filled, the finish window,
   and `msiexec /i ... /l*v log.txt` does not contain the token (MsiHiddenProperties and the
   hidden SaveToken action; Wine ignores them, Windows does not). Silently: `msiexec /i sohobotp-agent.msi /qn PORTAL=...
   TOKEN=... PIN=...` enrols on its own;
   `HKLM\SOFTWARE\SohobOTP\Agent` never has `Token`, and `enrol-token` is gone from
   `C:\ProgramData\SohobOTP\agent` afterwards; the key fields in
   `agent.json` start with `dpapi:`.
8. Self-update: set a newer signed version as the group's target; the service restarts on it.

## Not done yet

- Windows: signing in with password + code at the sign-in screen (manual test above); the
  rest is tested automatically on Windows Server 2022.
- Roll back after a self-update is tested on Linux end to end; on Windows its code is the
  same and unit-tested, the MSI upgrade itself is tested on Windows Server 2022.
