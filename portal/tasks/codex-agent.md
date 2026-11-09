# Task: SohobOTP agent in Go (stage 4b, Linux first, then Windows)

**Branch:** create `portal/agent-go` from `portal/stage3-radius`
(`git switch -c portal/agent-go portal/stage3-radius`).

## Why

Stage 4 lets the portal control Windows and Linux machines: enrol them, push configuration,
see inventory and health, and later update the agent. Another agent is building the portal
side (`portal/agent.php`, endpoint groups, enrolment tokens) at the same time. **You build the
agent that runs on the machines.** The two halves meet only at the protocol.

Read first, in this order:

1. `portal/docs/agent-protocol.md`: the exact contract. **Follow it byte for byte.** If
   something is unclear or wrong, write it under "Questions" at the end of this file; do not
   change the protocol on your own.
2. `portal/docs/agent-protocol-vectors.json`: test vectors generated with the portal's
   libsodium. Your Go tests must reproduce and verify every one of them.
3. `portal/docs/endpoints.md`: the overall design and the security model.

## Naming

The product is **SohobOTP**. Binary `sohobotp-agent` (`sohobotp-agent.exe`), systemd unit
`sohobotp-agent.service`, Windows service name `SohobOTPAgent`, display name
"SohobOTP Agent", user-visible messages say "SohobOTP agent". Keep the wire-protocol
identifiers (`multiotp-agent-v1`, `multiotp-agent-enroll-v1`, `multiotp-config-v1`) exactly
as in the protocol: they are internal constants covered by the test vectors.

## Files

- **May create/change:** `agent/**` only, plus the "Status" and "Questions" sections at the
  end of this file.
- **Must not touch:** anything else, in particular `portal/**` (except this file), the
  engine (`multiotp*.php`, `contrib/`), `raspberry/`, `Dockerfile`, `AGENTS.md`.

## Goals

### Phase 1: core + Linux (do this first, fully tested)

1. Go module in `agent/` (module path `multiotp-portal/agent`, Go 1.22+), command
   `cmd/sohobotp-agent`, standard library plus `golang.org/x/crypto` and `golang.org/x/sys`
   only. No other dependencies.
2. Commands:
   - `install --portal URL --token TOKEN --pin HEX [--ca-file PATH]`: create keys, enrol,
     check the portal key against the pin, save state, install and start the service;
   - `run`: the service loop (check in every `checkin_interval` seconds, apply configs);
   - `status`: endpoint id, portal, last check-in, applied version, last error;
   - `apply --dry-run --config FILE`: show what a configuration would change (for testing);
   - `uninstall`: remove the PAM include and agent files, stop the service.
3. Protocol: enrol, signed requests, check-in, signed configuration checks (signature with
   the pinned key, own endpoint id and OS, version strictly greater than the last applied,
   all secrets open or nothing applies), backoff on errors. TLS verification always on;
   `--ca-file` adds a CA, nothing disables verification.
4. Key and state storage on Linux: `/etc/sohobotp-agent/` mode 0700 root, files 0600.
   Never log secrets, tokens, private keys or sealed values.
5. Linux applier (Debian/Ubuntu `libpam-radius-auth` and RHEL-family `pam_radius`):
   - write the RADIUS server file (`/etc/pam_radius_auth.conf`, or `/etc/raddb/server` on
     RHEL), root 0600;
   - write one PAM file `/etc/pam.d/multiotp-2fa` and add a single include line to each
     service in `services`, **after** the existing password authentication;
   - exclusions (`root`, `excluded_users`, `excluded_groups`) may only skip the
     `pam_radius_auth` line (`[success=N default=ignore] pam_succeed_if.so ...`). They must
     never end the PAM stack with success: an excluded user still needs their normal password;
   - `ssh_keys_need_code`: drop-in file under `/etc/ssh/sshd_config.d/` with
     `KbdInteractiveAuthentication yes` and, when true,
     `AuthenticationMethods publickey,keyboard-interactive password,keyboard-interactive`;
     validate with `sshd -t` before reloading;
   - every apply is atomic (temporary file and rename), keeps backups, and **rolls back**
     if any step or validation fails; existing auth lines are never removed or reordered;
   - `enabled: false` removes exactly what the agent added.
6. Service: systemd unit (`Restart=always`, hardening options that still allow writing
   `/etc/pam.d`, `/etc/ssh/sshd_config.d`, the RADIUS file and the state directory).

### Phase 2: Windows (after phase 1 is green)

7. Windows service (`golang.org/x/sys/windows/svc`), state in `%ProgramData%\SohobOTP\agent`
   with an ACL allowing only SYSTEM and Administrators; private keys additionally protected
   with DPAPI (machine scope).
8. Credential Provider applier: write the registry values in the protocol's Windows table,
   with the right types (`multiOTPServerTimeout` and `multiOTPTimeoutUnlock` as DWORD,
   booleans as `1`/`0` as the CP expects; check the multiOTP Credential Provider README if
   unsure). Keep the previous values and restore them if a write fails. Registry access goes
   through an interface so it is unit-tested on Linux with a fake.
9. Inventory: Windows version, domain, CP version (from the uninstall registry entry).
10. Cross-compile `windows/amd64` in Docker. Real Windows testing will be done later by the
   user on a VM; write down exactly what to check in `agent/README.md`.

### Phase 3: Group Policy rollout (after phase 2)

11. Windows MSI `sohobotp-agent.msi` buildable in Docker (e.g. `msitools`/`wixl`, or WiX if
    you can run it in a container): installs `sohobotp-agent.exe` under
    `%ProgramFiles%\SohobOTP\Agent`, registers the service, and runs the enrolment with the
    public properties `PORTAL`, `TOKEN`, `PIN` and optional `CAFILE` (silent install:
    `msiexec /i sohobotp-agent.msi /qn PORTAL=... TOKEN=... PIN=...`). The token is used
    once and never written to disk or logs; repair/upgrade keeps the existing enrolment;
    uninstall runs `sohobotp-agent uninstall`. Document a GPO startup-script alternative.
12. `state: "pending"` in the check-in reply (protocol section 3): keep checking in at the
    interval without applying anything, and show "waiting for approval" in `status`.

## Tests (all in Docker; Go is not installed on the host)

- `agent/tests/run-in-docker.sh` (official `golang` image, pinned version): `gofmt` check,
  `go vet`, `go test -race ./...`, builds for `linux/amd64`, `linux/arm64`, `windows/amd64`.
- Unit tests:
  - every vector in `portal/docs/agent-protocol-vectors.json`: enrol proof, request
    signature, config signature, opening the sealed `radius_secret`;
  - refusals: wrong pin, bad config signature, other endpoint id, other OS, version replay
    or rollback, one secret that does not open;
  - PAM file generation (golden files) and the exclusion rule above.
- Linux end-to-end, in containers on a private Docker network:
  - a **fake portal** written in Go for the test (implements `enroll` and `checkin` exactly
    as the protocol says, signs configs with the vector portal key);
  - a FreeRADIUS container with a static test user;
  - a Debian container with `sshd`, `sudo`, `libpam-radius-auth` and the agent:
    install → check in → configuration applied → SSH login needs password **and** code;
    wrong code refused; excluded user needs only the password; root not locked out;
    `enabled: false` restores the original PAM files byte for byte; a broken config
    (e.g. bad `sshd -t`) is rolled back and reported as `failed`;
  - also on a RHEL-family image (Rocky or Alma) for the PAM/RADIUS paths.
  - **all RADIUS servers down** (stop the FreeRADIUS container): excluded users and the
    break-glass group still log in with their password, root is not locked out, everyone
    else is refused; logins work again when RADIUS is back.

## Done when

- `sh agent/tests/run-in-docker.sh` passes, including the Linux end-to-end tests.
- The Windows build compiles and its unit tests pass.
- `agent/README.md` explains install, files, security choices and the Windows manual test.
- `sh portal/tests/run-in-docker.sh` still passes (you should not have changed anything it uses).
- Commit on `portal/agent-go` with clear messages. Do not push. Do not merge.

## Status

(Codex: write progress, test results and anything unverified here.)

## Questions

(Codex: protocol questions or problems for the portal side.)
