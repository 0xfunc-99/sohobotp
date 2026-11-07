# multiOTP management portal

Server-rendered PHP portal that replaces the legacy multiOTP admin page. It reuses the
multiOTP engine (`multiotp.class.php`) for users, tokens and LDAP, and adds named
administrators, roles, administrator MFA, hardened sessions, CSRF protection and a
tamper-evident audit trail.

Served at `https://<host>/portal/`. Only `portal/index.php` and `portal/assets/` are public;
nginx refuses `portal/src`, `portal/templates`, `portal/bin` and `portal/tests`, and every file
in those folders also refuses to run on its own.

## Status

| Stage | Content | State |
|---|---|---|
| 1 | Admin accounts, roles, admin MFA, sessions, CSRF, audit trail, dashboard counts | **done** |
| 2 | AD/LDAP connection settings, sync now/scheduled, history, background worker | next |
| 3 | FreeRADIUS clients, shared secrets, validation, reloads, diagnostics | |
| 4 | Endpoint (multiOTP Credential Provider) enrolment, inventory, policies | |
| 5 | Integration testing on test systems | |

The visual design is interim and will follow the supplied mockup.

## First administrator

There is no default password. Create the first super administrator from the command line:

```sh
# Docker
docker exec -it <container> php /usr/local/bin/multiotp/portal/bin/portal-admin.php create --username=alice --role=superadmin --display-name="Alice Example"
# Appliance / source tree
php portal/bin/portal-admin.php create --username=alice --role=superadmin
```

It prints a temporary password (valid 24 h). At first sign-in the administrator scans a QR
code with an authenticator app, then must choose a new password.

Other commands: `list`, `reset-password`, `reset-mfa`, `unlock`, `enable`, `disable`
(all with `--username=`), and `verify-audit`. Use them to recover when no super
administrator can sign in. Every command is written to the audit trail as `cli:<system user>`.

## Roles

| Role | Can do |
|---|---|
| Super administrator | Everything, including administrator accounts |
| Administrator | Users, tokens, directory sync, RADIUS, endpoints, audit trail (not administrator accounts) |
| Helpdesk | Look up users, unlock accounts, resync and enrol tokens |
| Auditor | Read-only, including the audit trail |

Permissions for stages 2–4 are already defined in `src/Roles.php`; their pages arrive with those stages.

## Administrator MFA

Every administrator needs a second factor; there is no way to skip it.

- **Authenticator app** (default): a TOTP secret enrolled in the portal and stored
  encrypted (libsodium, key in `portal.key`). It is *not* a multiOTP user, so it can never be
  used to sign in over RADIUS.
- **Existing multiOTP user**: the administrator's own multiOTP token (for example their
  directory account), checked by the multiOTP engine with its PIN, lockout and replay rules.
  without2FA users are refused.

## Security behaviour

- HTTPS only (plain HTTP is refused unless `MULTIOTP_PORTAL_ALLOW_HTTP=1`, for local tests).
- Session cookie `__Host-motp_portal`: Secure, HttpOnly, SameSite=Strict; strict mode; new id at
  every privilege change; 15 min idle and 8 h absolute timeout.
- Changing a password, resetting MFA, disabling an account or "Sign out" bumps the account's
  session version, which ends all its other sessions immediately.
- CSRF token on every POST plus an Origin/Referer same-host check.
- 5 wrong passwords or codes lock the account for 15 min; 20 failures from one IP in 15 min
  block that IP. Error messages never reveal whether an account exists.
- Passwords: Argon2id, at least 12 characters, not containing the username.
- The last active super administrator cannot be disabled or demoted; nobody can disable
  themselves or reset their own second factor.
- Strict Content-Security-Policy (no inline script), `X-Frame-Options: DENY`, `no-store`.

## Audit trail

`audit.jsonl` in the data folder: one JSON object per line, each with the SHA-256 hash of
the previous one. The Audit trail page (and `portal-admin.php verify-audit`) re-checks the
chain and reports the first modified or deleted line. Fields named like passwords, secrets,
seeds, OTPs, PINs or keys are written as `[redacted]`.

## Files and settings

Data folder: `/etc/multiotp/portal/` on the appliance and in Docker (inside the persistent
`/etc/multiotp` volume), `config/portal/` in a source checkout. It holds `admins.json`,
`audit.jsonl`, `throttle.json` and `portal.key`, all mode 0600. **Back up `portal.key`
together with `admins.json`**: without it, authenticator-app enrolments cannot be read and
administrators must re-enrol.

Environment variables (all optional): `MULTIOTP_PORTAL_DATA`, `MULTIOTP_ETC_DIR`,
`MULTIOTP_LOG_DIR`, `MULTIOTP_PORTAL_ISSUER`, `MULTIOTP_PORTAL_IDLE_TIMEOUT`,
`MULTIOTP_PORTAL_ABSOLUTE_TIMEOUT`, `MULTIOTP_PORTAL_MAX_FAILURES`, `MULTIOTP_PORTAL_LOCKOUT`,
`MULTIOTP_PORTAL_IP_MAX_FAILURES`, `MULTIOTP_PORTAL_IP_WINDOW`,
`MULTIOTP_PORTAL_TEMP_PASSWORD_LIFETIME`, `MULTIOTP_PORTAL_MIN_PASSWORD_LENGTH`,
`MULTIOTP_PORTAL_ALLOW_HTTP` (tests only). Requires PHP 8.1+ with sodium and mbstring.

## Changes to the legacy code in this stage

- `multiotp.server.php`: CORS no longer reflects any origin with credentials; only origins
  listed in `MULTIOTP_CORS_ORIGINS` get CORS headers.
- `ApiVueJsPreAuth()`: no longer adopts a session id sent in the request body (session
  fixation); SameSite=Strict, strict mode.
- `ApiLogin()`: the OTP-administrator path used an undefined variable and never selected the
  user; fixed (OTP read from `password`), and the session id is regenerated after login.

These are applied to every copy: `multiotp.class.php`, the generated `multiotp.php`, and
the appliance bundles under `raspberry/boot-part/multiotp-tree/usr/local/bin/multiotp/`.

## Tests

```sh
sh portal/tests/run-in-docker.sh
```

Runs PHP lint, `tests/unit.php` (TOTP RFC 6238 vectors, crypto, audit chain and redaction,
lockout, multiOTP-linked MFA) and `tests/e2e.php` (full sign-in, enrolment, forced password
change, roles, CSRF, lockout/unlock, session revocation, TOTP replay, audit page, legacy
CORS and session fixation fixes) in a throwaway `php:8.4-cli` container.
