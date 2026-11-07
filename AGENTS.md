# Agent guide for this repository

This is a fork of **multiOTP open source** (PHP two-factor authentication server) that is being
turned into a central management portal. Read `portal/README.md` for the portal's design,
security model, roadmap and current status.

## Layout

- `multiotp.class.php` — the multiOTP engine (one large class). `contrib/` — bundled libraries
  (LDAP: `contrib/MultiotpAdLdap.php`).
- `multiotp.php` — **generated bundle** (CLI header + engine + contrib). Do not edit by hand
  except to mirror an engine fix (see below).
- `multiotp.server.php` — legacy web/XML/SOAP entry point.
- `portal/` — the new management portal (server-rendered PHP 8.1+, no framework):
  `index.php` (front controller), `src/` (classes, namespace `Portal\`), `templates/`,
  `assets/`, `bin/portal-admin.php` (CLI), `bin/worker.php` (background jobs), `tests/`.
- `raspberry/boot-part/` — appliance/Docker install scripts and the file tree copied into the
  image (`multiotp-tree/`). `Dockerfile` builds the production image.

## Rules

- **Engine fixes go into every copy**: `multiotp.class.php` (or `contrib/*.php`), the bundle
  `multiotp.php`, and `raspberry/boot-part/multiotp-tree/usr/local/bin/multiotp/`
  `index.php`, `multiotp.class.php`, `multiotp.proxy.php`. Some of these contain latin-1 bytes
  and CRLF line endings: patch byte-for-byte (e.g. Python with `encoding="latin-1", newline=""`),
  never re-save them as UTF-8/LF.
- Portal security conventions: every POST checks CSRF (`Portal\Csrf`), every page checks a
  permission (`Roles`), every state change writes `Portal\Audit` (secrets are redacted by key
  name — never put passwords, seeds or codes in audit details), output is escaped with `e()`.
- Secrets the portal generates use `random_bytes()` / `random_int()`, not the engine's
  md5/mt_rand helpers.
- Keep the default test run green: `sh portal/tests/run-in-docker.sh`.
- Work on your own branch; commit with clear messages; do not push unless asked.

## Running things

PHP is **not** installed on the host; use Docker.

- Tests: `sh portal/tests/run-in-docker.sh` (builds `tests/docker/php.Dockerfile` with
  ldap/bcmath and a throwaway OpenLDAP in `tests/docker/ldap/`).
- Local preview: `sh portal/tests/dev-server.sh start`, then
  `sh portal/tests/dev-server.sh admin <name>` → http://localhost:8080/portal/.
- If `docker build` fails with a permission error on `~/.docker/buildx`, set `BUILDX_CONFIG`
  to a writable temporary folder.

## Parallel work

Several agents may work at the same time. Task files in `portal/tasks/` say which files each
task may and may not touch; respect those boundaries.
