# Task: Samba AD test directory and end-to-end AD sync verification

**Branch:** create `portal/ad-test-directory` from `portal/stage1-admin-access`.

## Why

Stage 2 added AD/LDAP synchronisation (`portal/src/Directory.php`, worker jobs in
`portal/bin/worker.php` / `portal/src/Jobs.php`). It has only been tested against OpenLDAP
(`portal/tests/docker/ldap/`, server type 2 "Generic LDAP"). The Active Directory paths
(server type 1) have never run: group scope (`in_groups`), nested groups
(LDAP_MATCHING_RULE_IN_CHAIN), the `userAccountControl` disabled flag, LDAPS, and
"directory password + code" logins. Production will use Active Directory.

## Goals

1. **Samba AD test container** in `portal/tests/docker/samba/` (test only, never production):
   - realm `EXAMPLE.TEST`, domain `EXAMPLE`, test-only passwords;
   - LDAPS on 636 with a self-signed certificate (export the CA so tests can trust it);
   - `OU=Staff`: users alice, bob, carol, dave, and erin (disabled account);
   - groups: `MFA-Users` (alice, bob); `VPN-Users` (carol, plus the group `MFA-Users` nested);
   - service account `svc-multiotp` (read-only use).
   - Document Docker requirements (xattrs, capabilities) in the Dockerfile header.

2. **Optional test run**: when `MULTIOTP_TEST_AD=1`, `portal/tests/run-in-docker.sh` also starts
   the Samba container and runs a new `portal/tests/e2e-ad.php`. Without the variable the run
   must behave exactly as today and keep passing.

3. **Checks** (through the portal's `Directory` class and worker jobs; confirm results with the
   multiOTP engine):
   - connection test over LDAPS with `tls_reqcert` = `never`, and with `demand` once the test CA
     is trusted;
   - preview counts match the directory;
   - sync creates the users with DN, display name and email;
   - `in_groups=MFA-Users` syncs only alice and bob;
   - nested groups on: carol is included through `VPN-Users`;
   - erin (disabled in AD) is disabled in multiOTP;
   - disable bob in AD → next sync disables him; re-enable → re-enabled, and the
     "do not re-enable" setting is respected;
   - a user removed from the group scope is disabled;
   - password + code: for a synced user with `request_ldap_password` on,
     `CheckToken($adPassword . $otp)` returns 0; a wrong password is refused;
   - the service-account password never appears in multiOTP config files or the audit trail.

4. **Engine bugs**: list every one you find. Fix only narrow, clearly correct ones, in **every
   copy** (see `AGENTS.md`), each with a test. Known already: group lists crash the engine in
   generic-LDAP mode (the portal refuses them there) — report whether the AD path works.

## Do not touch

Another agent is building the RADIUS stage at the same time:

- `portal/src/App.php`, `portal/src/View.php`, `portal/src/Roles.php`
- `portal/src/Radius*`, `portal/templates/radius*`
- `raspberry/boot-part/install.sh`, `raspberry/boot-part/newvm.sh`

If you believe one of these must change, stop and describe the change instead of making it.

## Done when

- `MULTIOTP_TEST_AD=1 sh portal/tests/run-in-docker.sh` passes;
- `sh portal/tests/run-in-docker.sh` still passes unchanged;
- `portal/README.md` has a short "Active Directory tests" section;
- your final report lists which AD behaviours work, which do not, and the engine bugs found
  or fixed (with file names).
