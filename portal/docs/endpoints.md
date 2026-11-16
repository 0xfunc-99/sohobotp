# Stage 4: endpoints, endpoint groups and the agent

The product is called **SohobOTP** (company: Sohobcom). The agent is the **SohobOTP agent**:
binary `sohobotp-agent` (`sohobotp-agent.exe` on Windows), systemd unit
`sohobotp-agent.service`, Windows service `SohobOTPAgent` (display name "SohobOTP Agent"),
state in `/etc/sohobotp-agent/` and `%ProgramData%\SohobOTP\agent\`. Wire-protocol
identifiers (`multiotp-agent-v1`, `multiotp-config-v1`, ...) are internal constants and keep
their names. The Windows login itself is SohobOTP Sign-in (third-party,
Apache 2.0); its tile text defaults to "SohobOTP".

Goal: manage Windows and Linux machines from the portal. Each machine runs a small
agent that enrols once, checks in over HTTPS, receives its configuration, applies it,
reports inventory and health, and updates itself.

Decisions (2026-11-08): agent written in **Go** (one binary per OS, Windows service /
systemd unit); Linux logins use **PAM → RADIUS** (`pam_radius_auth` against the stage 3
FreeRADIUS servers); the portal can **push configuration**, show **inventory and
health**, and **self-update** the agent (no remote commands for now); Windows laptops
get the **offline cache** of SohobOTP Sign-in.

## Pieces

| Piece | Where | What |
|---|---|---|
| Endpoint groups | portal | Policy shared by many endpoints: Windows CP settings, Linux PAM settings, offline cache, check-in interval, agent version |
| Enrolment tokens | portal | Created per endpoint group, expire, limited uses, shown once, stored hashed |
| Agent API | `portal/agent.php?a=...` | `enroll`, `checkin` (later `release`); JSON, every request signed by the endpoint key; exact contract in [agent-protocol.md](agent-protocol.md) |
| CP gateway | `portal/cp.php` (`/portal/cp/<endpoint-id>`) | Front for the Credential Provider's multiOTP client: per-endpoint shared secret, then the engine's `XmlServer` |
| Agent | `agent/` (Go module) | `sohobotp-agent install/run/status/uninstall`; Windows and Linux appliers |

## Trust model

- **Install:** `sohobotp-agent install --portal https://portal.example --token <enrolment token> --pin <portal key fingerprint>`.
  The pin is the portal's Ed25519 config-signing public key, shown on the enrolment page.
- **Endpoint identity:** the agent generates an Ed25519 signing key and an X25519 box
  key on the machine. Private keys never leave it (Windows: file in `%ProgramData%`
  readable by SYSTEM/Administrators only and DPAPI machine-protected; Linux:
  `/etc/sohobotp-agent/` 0700, keys 0600 root). The portal stores only public keys.
- **Requests:** headers `X-Agent-Id`, `X-Agent-Time`, `X-Agent-Nonce`,
  `X-Agent-Signature` = Ed25519 over `METHOD\nPATH\nTIME\nNONCE\nSHA256(body)`.
  Time window ±300 s, nonces remembered for the window, so no replay.
- **Configuration:** a JSON document `{endpoint_id, version, issued_at, policy, secrets}`
  signed by the portal key. The agent checks the signature against the pinned key, its
  own endpoint id, and that `version` never goes backwards (no rollback).
  Secrets inside (CP shared secret, RADIUS secret) are sealed to the endpoint's X25519
  key (`crypto_box_seal`): a TLS-terminating proxy or a log never sees them.
- **Self-update:** agent binaries are signed with a **release key that is not on the
  portal** (`portal-admin.php agent-release add` takes an already-signed file). The
  agent verifies with the release public key compiled in. A compromised portal can
  change configuration but cannot make endpoints run new code.
- **Revocation:** disabling an endpoint rejects its signatures, revokes its CP secret and
  removes its RADIUS client on the next apply.

## Windows: SohobOTP Sign-in (fork of the multiOTP Credential Provider)

The agent installs the CP MSI if missing (hosted by the portal, signature checked) and
writes its registry values under
`HKEY_CLASSES_ROOT\CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}`:

| Policy field | Registry value |
|---|---|
| server URL (per endpoint, the CP gateway) | `multiOTPServers` |
| shared secret (per endpoint, random) | `multiOTPSharedSecret` in `HKLM\SOFTWARE\SohobOTP\SignIn` (SYSTEM and Administrators only; removed from the CLSID key) |
| failover timeout | `multiOTPServerTimeout` (DWORD) |
| logon / unlock / admin prompt (`[0-3][e/d]`) | `cpus_logon`, `cpus_unlock`, `cpus_credui` |
| excluded account (break-glass) | `excluded_account` |
| offline cache | `multiOTPCacheEnabled` |
| UPN format, default prefix | `multiOTPUPNFormat`, `multiOTPDefaultPrefix` |
| unlock grace period | `multiOTPTimeoutUnlock` |
| users without a token | `multiOTPWithout2FA` |
| two-step prompts, texts | `two_step_*`, `login_text`, `otp_text`, ... |

**Security problems in the legacy CP ↔ server protocol, and what we do:**

1. One global `server_secret` (default `ClientServerSecret`) for every machine.
   → **Done (4c):** the CP gateway `portal/cp.php?e=<id>` gives **each endpoint its own
   secret** (`SetServerSecret()` per request). One stolen laptop cannot impersonate the
   others, and disabling it replaces its secret. The legacy endpoint refuses client/server
   mode while the default secret is in use. Note: a disabled laptop that cannot reach the
   portal still accepts its offline-cached logins until the cache lifetime ends.
2. The bundled client does **not verify TLS** (`verify_peer => false` in the engine).
   → **Done:** SohobOTP Sign-in's bundled engine is patched at build time
   (`windows-signin/patch-engine.ps1`, byte for byte): it verifies the portal certificate
   with `portal-ca.pem` in the Sign-in folder, which the agent writes after every check-in
   (the root CA that verified the portal on the agent's own TLS connection). Sign-in then
   only talks to the portal this agent trusts; a man in the middle is refused. Tested on
   Windows: Sign-in's PHP connects with the pinned CA (IP address certificate) and refuses
   another CA.
4. The shared secret was in the CLSID key, which every local user can read.
   → **Done:** the agent writes it to `HKLM\SOFTWARE\SohobOTP\SignIn` (SYSTEM and
   Administrators only, protected DACL) and removes it from the CLSID key; Sign-in reads it
   there first (`MultiotpRegistry.cpp`). The sign-in screen (LogonUI, SYSTEM) and the
   administrator prompt (consent.exe, SYSTEM) read it; prompts running as the signed-in
   user (some "Windows Security" dialogs) cannot, and their code check fails closed.
3. Cached user data is "encrypted" with a repeating XOR of the shared secret.
   → Offline cache is opt-in per endpoint group, with a short cache lifetime (default
   7 days, max 30), only users who logged in on that machine are cached, and the
   group page states the risk. Full fix (authenticated encryption of cache data) needs
   both sides of the client; tracked as a later engine change.

## Linux: PAM → RADIUS

- On enrolment the portal creates a **RADIUS client** for the endpoint (stage 3) in the
  server group chosen by the endpoint group, with its own secret, and queues an apply.
- The agent installs `libpam-radius-auth` / `pam_radius` if missing, writes
  `/etc/pam_radius_auth.conf` (root 0600: servers, secret, timeout) and one PAM file
  `/etc/pam.d/multiotp-2fa`, then includes it in the services the policy names
  (`sshd`, `sudo`, `login`).
- **Lockout protection:** root and a local break-glass group are always excluded
  (`pam_succeed_if`); every change is validated and rolled back if the PAM stack or
  `sshd -t` fails; the agent never removes existing auth lines, it only adds its include.
- SSH needs `KbdInteractiveAuthentication yes`; the agent sets it in a drop-in file.
- Offline: `pam_radius` has no cache; Linux machines need a reachable RADIUS server
  (two servers for failover).

## Rollout from Active Directory (Group Policy)

0. **Simplest: the Group Policy kit.** *Add a computer* → *Group Policy kit* downloads a zip
   with a computer startup script, the agent programs, the portal certificate and a README
   with the steps (copy to NETLOGON, name `Install-SohobOTP.cmd` as startup script, link the
   GPO to the OU). The script installs the agent on computers that have none; with *Install and
   update SohobOTP Sign-in automatically* the agent installs Sign-in itself, and with *Tamper
   protection* local administrators cannot remove it. The points below are what the kit does.
1. **Install with GPO.** Deploy the agent MSI (`sohobotp-agent.msi`, properties `PORTAL`, `TOKEN`,
   `PIN`, optional `CAFILE`) with Computer Configuration → Software Installation, or a startup
   script that runs `sohobotp-agent.exe install ...`. The Credential Provider MSI is deployed
   the same way (stage 4c makes the agent install it).
2. **Token with Active Directory approval.** Everything in a GPO is readable by every domain
   user (SYSVOL), so the token can be copied. Create it with *Approved automatically when the
   computer is in Active Directory*: a new machine stays **pending** (no configuration, no
   secrets) until the portal's worker finds its computer account and approves it when
   - the account exists (sAMAccountName = host name + `$`) and is enabled;
   - its `dNSHostName` resolves (portal DNS) to the address the machine enrolled from;
   - no other active endpoint already uses that computer account.

   Otherwise it waits for an administrator (Approve / Reject on the endpoint page), with the
   reason shown. Residual risk: someone on the same network address as a real computer that
   is not yet enrolled could claim its name; use manual approval where that matters.
3. **Policy from AD.** Rules on the Endpoint groups page map a computer's **OU** (or any OU
   below it) or its **AD group** (nested membership included) to an endpoint group; the first
   matching rule wins. The worker re-checks every 15 minutes and right after an enrolment,
   so moving a computer to another OU or group changes its policy at the next check-in.
   A machine moved by an administrator is pinned until "Let AD rules choose the group".
4. **Identity binding.** The computer account found first stays bound to the endpoint: if
   the machine later reports another host name it keeps its account (shown as needing
   attention) and cannot take over another computer's policy.

The lookups use the Directory page's service account (read-only, LDAPS recommended) and
need Active Directory (server type 1).

## Inventory and health

Each check-in reports: hostname, OS and version, domain, IP addresses, agent version,
CP / pam_radius version, applied config version, last apply result and errors.
The portal marks an endpoint **offline** after 3 missed intervals and shows it on the
dashboard.

## Portal

- Pages: Endpoints (list, filters, offline), endpoint detail (inventory, applied config,
  history), Endpoint groups (policy editor), Enrolment (tokens and install commands),
  Agent releases.
- Permissions: `endpoints.view`, `endpoints.manage`, `endpoints.enroll`,
  `endpoints.releases`. Audit for every change; secrets redacted.

## Build order

- **4a** Portal: endpoint groups, enrolment tokens, agent API (signatures, nonces),
  signed configuration, inventory pages. Tests in the default suite.
- **4b** Go agent core + Linux applier. End-to-end test in Docker: a Debian container
  with sshd enrols against the appliance and an SSH login needs the code.
- **4c** Windows applier + CP gateway + offline cache. Cross-compiled and unit-tested
  here (registry behind an interface); a real Windows VM test is needed.
- **4d** Self-update with signed releases. **Done**: see agent/README.md.
