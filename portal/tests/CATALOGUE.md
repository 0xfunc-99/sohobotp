# SohobOTP test catalogue

Every case the system must handle, what should happen, and how it is tested. Status:

- **auto**: automated, runs in a suite listed below;
- **partial**: automated for part of the case only (the note says what is missing);
- **gap**: not tested yet, priority **P1** (security or lock-out risk), **P2** (likely in
  production), **P3** (rare);
- **manual**: needs real hardware or software (Windows, VPN appliance, phone), with steps.

Suites: `unit` = `tests/unit.php`, `e2e` = `tests/e2e.php`, `ad` = `tests/e2e-ad.php` +
`tests/e2e-ad-endpoints.php` (`MULTIOTP_TEST_AD=1`), `appliance` = `tests/run-appliance-test.sh`,
`agent` = `agent/tests/run-in-docker.sh` (unit) and `agent/tests/e2e-linux.sh` (end to end).

State on 2026-11-09 after the P1 round: about 600 automated checks (160 unit, 320 e2e,
114 AD, appliance). **No P1 gap left.** Of the 98 cases: 53 fully automated, 8 partial
(P2: 6, P3: 2), 26 gaps (P2: 18, P3: 8), 6 manual-only, 5 in Codex's agent tests.

## 1. Administrator access

| Case | Expected | Status |
|---|---|---|
| First sign-in: temporary password → MFA enrolment → own password | each step forced in order, other pages blocked | auto (e2e) |
| Wrong password, unknown user | same generic message, audit entry | auto (e2e) |
| 5 wrong passwords | account locked, even with the right password; unlock by super admin | auto (e2e) |
| Wrong / replayed MFA code | refused; a code is never accepted twice | auto (e2e, unit) |
| Session revoked, logout, strict session ids | signed out, foreign session id refused | auto (e2e) |
| Idle timeout (15 min) and absolute timeout (8 h) | signed out, back to sign-in | **gap P2** |
| Temporary password older than 24 h | refused, admin must get a new one | **gap P2** |
| MFA step left open > 5 min, more than 5 wrong MFA codes | back to the password step | **gap P2** |
| 20 failures from one IP in 15 min | that IP is blocked for every account, others unaffected | auto (e2e) |
| Super admin resets another admin's MFA / password | old factor stops working, audit entry | **gap P2** |
| Admin changes own password on My account | old password refused afterwards, other sessions signed out | partial (forced change only) |
| Last super admin demoted, disabled or deleted | refused | auto (e2e) |
| Roles: helpdesk and auditor on every POST route (23), auditor read pages | 403 and audit entry, nothing changed; auditor can read | auto (e2e) |
| CSRF missing / foreign Origin on every POST route | 400, nothing changed | auto (e2e) |

## 2. Users and tokens

| Case | Expected | Status |
|---|---|---|
| Create TOTP user, enrol by QR, code works in the engine | yes; seed never shown again | auto (e2e) |
| Without-2FA user, disabled user, locked user | refused / unlocked as set | auto (e2e) |
| Recovery codes | single use, accepted by the engine | auto (e2e) |
| Login formats: code only, PIN + code, directory password + code | each accepted, wrong part refused | auto (e2e, appliance) |
| HOTP token, resynchronisation after drift | accepted after resync, counter moves forward | partial (resync permission only) **P2** |
| Hardware token import: CSV/Yubico | imported, assigned, removed | auto (e2e) |
| Hardware token import: **PSKC** (plain and password-protected) | imported with the right seeds | **gap P2** |
| User locked after N wrong codes (engine max failures), auto-unlock delay | locked, then usable again | **gap P2** |
| Bulk disable / delete, deleting a user with an assigned token | as selected; token released | partial (bulk only) P3 |
| Names with accents, spaces, uppercase | normalised the same everywhere (portal, RADIUS, CP) | **gap P2** |

## 3. Directory (AD / LDAP)

| Case | Expected | Status |
|---|---|---|
| Connection test, LDAPS with trusted / untrusted certificate | accepted / refused | auto (ad) |
| Preview, sync, users created with DN, name, e-mail | exact | auto (ad, e2e) |
| Group scope, nested groups, several groups | only members synced | auto (ad) |
| Disabled in AD, re-enabled, removed from group | disabled / re-enabled / disabled | auto (ad) |
| Directory password + code (AD and OpenLDAP) | accepted, wrong password refused | auto (ad, e2e) |
| **Directory server unreachable during a sync** | sync fails, **no user is disabled or deleted** | auto (e2e, OpenLDAP) |
| Wrong service password during a sync | job fails, admin sees it, nothing changed | auto (e2e; scheduled syncs run the same job) |
| Several domain controllers, first one down | second one used | **gap P2** |
| More than 1000 users (AD paging) | all synced | **gap P2** (stage 6 load test) |
| User renamed or moved to another OU in AD | same multiOTP user updated, not duplicated | **gap P2** |
| AD password expired / account expired / locked in AD | directory password login refused | **gap P2** |
| Delete retention: user gone from AD for N days | deleted after N days, not before | **gap P3** |

## 4. RADIUS (FreeRADIUS)

| Case | Expected | Status |
|---|---|---|
| Server groups, clients, secrets shown once, rotation | as designed | auto (e2e, appliance) |
| Apply: helper whitelist, config check, restart, rollback | invalid file rejected, previous config kept | auto (e2e, appliance) |
| PAP login: right / wrong code, wrong secret, unknown source | accept / reject / no answer | auto (appliance) |
| Challenge-response (PIN, then code) | Access-Challenge, then accept | auto (appliance) |
| Catch-all client `myfirstpass` | detected, disabled with one click | auto (appliance) |
| **MS-CHAPv2 and CHAP** (many VPNs) | accepted with the right code, refused otherwise | **gap P2** |
| Result cache per group (Wi-Fi roaming) | same login accepted again without code until timeout, never after | **gap P2** |
| Group attribute sent / not sent in the reply | as set per group | **gap P3** |
| Challenge state reused, forged, or answered after it expired | refused | auto (appliance) |
| Wrong codes over RADIUS (3 → delayed, more → locked) | right code refused until unlocked; other users unaffected | auto (appliance) |
| Message-Authenticator required, client does not send it | request dropped | **gap P2** |
| Two applies at the same time | one runs, the other is merged or waits | partial (job de-duplication) P3 |
| IPv6 RADIUS client | works like IPv4 | **gap P3** |
| Real VPN / firewall / Wi-Fi controller | login with code, challenge prompt shown | **manual** (FortiGate, Cisco, …) |

## 5. Endpoints and the agent API

| Case | Expected | Status |
|---|---|---|
| Protocol vectors (enrolment proof, request and config signatures, sealed secrets) | byte-identical in PHP and Go | auto (unit; agent unit) |
| Enrolment: wrong / used-up token, bad key proof | refused | auto (unit, e2e) |
| Enrolment token **expired** or **revoked** over HTTP | refused | partial (unit, via store edit) **P2** |
| Signed check-in: replay, tampered body, other URI, other key, old timestamp | refused | auto (unit, e2e) |
| Clock skew exactly at 300 s / 301 s | accepted / refused | **gap P3** |
| Body over 256 KiB, invalid JSON, unknown action, GET | 413 / 400 / 404 / 405 | auto (e2e) |
| 20 bad tokens or signatures from one IP | 429 for that IP, even with a valid signature | auto (e2e) |
| Config versions: new on policy change, not resent, failed not retried, restored backup | as designed | auto (unit) |
| Secrets sealed at rest and in transit, never in the audit trail | yes | auto (unit, e2e) |
| Linux endpoint becomes a RADIUS client; removed on disable / delete / move | yes, and FreeRADIUS really refuses it | auto (unit, appliance) |
| Endpoint deleted, then the agent checks in | `unknown_endpoint`, agent keeps last config; not counted by the IP throttle | auto (e2e, portal side) |
| Disabled or deleted Windows machine, users keep signing in | cp.php 403, IP not blocked (other machines behind the same NAT keep working) | auto (e2e) |
| Two check-ins at the same time from one endpoint | both answered, nonces not lost | **gap P3** |
| Pages: escaping of every inventory field and apply error | escaped | auto (e2e) |
| 5000 endpoints: list page, check-ins per second | page under 2 s, no lock contention errors | **gap P2** (stage 6) |

## 6. Rollout from Active Directory

| Case | Expected | Status |
|---|---|---|
| Approval: none / administrator / Active Directory | as designed | auto (unit, e2e, ad) |
| Unknown, disabled, wrong-address, duplicate computer | stays pending with the reason | auto (ad) |
| OU and nested-group rules, order, AD changes, admin pinning, name binding | as designed | auto (ad) |
| Real DNS (`dns_get_record`) against AD DNS | the computer's address resolves | partial (test uses a resolver map) **P2** |
| Domain controller down during the 15-minute check | job fails, nothing moved or approved, no loop | partial (AD not configured case) **P2** |
| Host name longer than 15 characters | matched on the 15-character NetBIOS name | **gap P3** |
| MSI contents (service, registry values, hidden token) | as designed | auto (build-msi.sh table check) |
| Real GPO deployment of the MSI | installs, enrols, token deleted, approved, policy from OU | **manual** (Windows) |

## 7. Windows sign-in (Credential Provider gateway)

| Case | Expected | Status |
|---|---|---|
| Right / wrong code through `cp.php` with the endpoint secret | accepted / refused | auto (e2e, appliance) |
| Other secret, Linux id, disabled endpoint | refused | auto (e2e) |
| Offline cache only when the group allows it, expiring within its lifetime | yes | auto (e2e, appliance) |
| Legacy URL with the default secret | refused; works with a private global secret or the override variable | partial (refusal only) **P2** |
| Unknown endpoint ids from one IP | throttled (429) | auto (e2e) |
| Gateway request without `<multiOTP`, over 64 KiB | 400 | **gap P3** |
| `ReadUserData` from a managed laptop for another user | never the seed, PIN or recovery codes | auto (e2e); kept because the CP calls it at sign-in. Non-secret fields (e-mail, phone, description) stay readable with a laptop's secret: filter them after the real-Windows test **P2** |
| Real Windows: sign-in, unlock, RDP, UAC prompt, excluded break-glass account | as the group policy says | **manual** |
| Real Windows offline: cached login works, expires after the lifetime | yes | **manual** |
| Real Windows: endpoint disabled while offline | cached logins still work until expiry (documented) | **manual** |

## 8. Linux sign-in (PAM → RADIUS, agent)

| Case | Expected | Status |
|---|---|---|
| SSH and sudo with password + code, wrong code, wrong password, real SSH session | as designed | auto (agent e2e) |
| Excluded user, break-glass group, root | password only, never locked out | auto (agent e2e) |
| RADIUS servers all down, then back | only users needing a code are refused; back to normal | auto (agent e2e) |
| Policy change from the portal, 2FA off | files follow; restored byte for byte | auto (agent e2e) |
| Broken config / `sshd -t` fails, unknown PAM layout | rolled back / refused, files untouched | auto (agent unit) |
| SSH key + code (`ssh_keys_need_code`) | both required | partial (drop-in unit-tested) P2 |
| RHEL family (Rocky 9): `include system-auth` turned into a substack, drop-in sorted first | same behaviour as Debian | auto (agent e2e `DISTRO=rocky`, agent unit) |

## 8b. Agent self-update

| Case | Expected | Status |
|---|---|---|
| Release signed with the release key, newer version | downloaded, checked, installed, reported | auto (agent e2e) |
| Release signed with another key / tampered manifest / wrong size or hash | refused, nothing installed | auto (agent e2e, agent unit) |
| Older or same version offered | ignored (no downgrade) | auto (agent unit, portal unit) |
| Release download for another platform, disabled endpoint | refused by the portal | auto (portal unit) |
| Upload of a release with a bad signature when the portal knows the release key | refused | auto (portal unit) |
| Windows: running exe replaced, service restarts on the new version | yes | **manual** (Windows) |
| Portal knows the release key: fingerprint as agents report it, other keys refused, Windows on ARM releases | as designed | auto (portal unit) |

## 8b. Tamper protection and Group Policy kit

| Case | Expected | Status |
|---|---|---|
| Policy switch on: policy carries the switch and the hash of the computer's code (same vector in Go and PHP); off: nothing added | as designed | auto (portal unit, agent unit) |
| Uninstall without the code / wrong code / `forget` | refused, reported to the portal | auto (agent unit, agent e2e Linux, Windows e2e) |
| Five wrong codes | codes refused for 15 minutes | auto (agent unit) |
| Right code | agent removable for 10 minutes, then protected again | auto (agent unit, agent e2e Linux, Windows e2e) |
| Windows: administrator stops / disables / deletes / re-permissions the service; edits the state; deletes the program | access denied | auto (Windows e2e) |
| Windows Installer uninstall without or with a wrong code | fails before anything is removed; code not in the log | auto (Windows e2e) |
| Setting changed by hand; SohobOTP Sign-in removed by hand | put back / installed again, reported | auto (agent unit, Windows e2e) |
| Agent killed; service stopped by hand; power loss; upgrade | first two reported, last two not | auto (agent unit), killed: Windows e2e |
| Events: unknown kinds, repeats, oversized, absurd time | ignored / stored once / cut / corrected; audit trail once each | auto (portal unit, e2e) |
| Uninstall code page: shown once, not cached, audited without the code, not for help desk, CSRF | as designed | auto (e2e) |
| Group Policy kit: zip readable, script values quoted, token limits, audited, not for help desk | as designed | auto (portal unit, e2e) |
| Group Policy kit on a real domain (startup script from NETLOGON) | computers enrol at start | **manual** (needs Active Directory) |
| Sign-in screen still asks for the code after an agent self-update / with tamper protection on | yes | **manual** (Windows) |

## 9. Web security

| Case | Expected | Status |
|---|---|---|
| Headers (CSP, HSTS, nosniff, frame), cookies (`__Host-`, HttpOnly, SameSite) | present | auto (e2e, appliance) |
| nginx allowlist: only index.php, agent.php, cp.php, assets | everything else 404 | auto (appliance) |
| XSS payload in every stored text field (user, RADIUS group/client, endpoint group texts, token label, inventory, apply error), 17 pages crawled | escaped on every page | auto (e2e) |
| Path traversal in ids (`../`, encoded) on routes, agent API and gateway | 404/400/403, nothing read | auto (e2e) |
| Legacy CORS / session fixation fixes | as fixed | auto (e2e) |
| Audit trail: chain, tamper detection, redaction | as designed | auto (unit, e2e) |

## 10. Appliance and operations

| Case | Expected | Status |
|---|---|---|
| Worker runs as www-data, helper root-only with fixed commands | yes | auto (appliance) |
| Worker killed during a job | job marked failed on restart, can be re-run | **gap P2** |
| Reboot: services back, data kept | yes | **gap P2** (appliance restart test) |
| Backup and restore of `/etc/multiotp` + portal data | admins sign in, agents and sealed secrets work, user codes work; without `portal.key` secrets are unusable (500, nothing leaked) | auto (e2e) |
| Upgrade from a stock multiOTP appliance with existing users | users and tokens kept, portal added | **gap P2** |
| Clock wrong on the server | codes refused; visible on the dashboard | **gap P3** |
| Raspberry Pi image boots and passes the appliance test | yes | **manual** (stage 7) |

## 11. Not built yet (tested in their stage)

REST API (stage 5), MariaDB backend, 100,000 users and master-slave HA (stage 6), signed
agent self-update (4d), push notifications (deferred).

## Manual test sheets

For each **manual** case, record: date, versions (portal commit, agent version, CP
version, OS), steps, result, screenshots. Minimum set before production:

1. Windows 11 domain-joined laptop: install the MSI by GPO, approval from AD, sign-in,
   unlock, RDP into it, UAC prompt, break-glass account, offline login, cache expiry.
2. Windows Server 2022 with RDP-only mode.
3. One VPN (FortiGate or equivalent): PAP and MS-CHAPv2, challenge prompt.
4. One Wi-Fi controller with result cache (roaming).
5. Ubuntu 24.04 and Rocky 9 servers: SSH, sudo, console, RADIUS outage.
6. Phones: Google / Microsoft Authenticator, FreeOTP; clock-drift handling.
7. Appliance: reboot, backup/restore, upgrade from stock multiOTP.
