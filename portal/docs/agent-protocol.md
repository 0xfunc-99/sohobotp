# Agent ↔ portal protocol, version 1

The contract between the SohobOTP agent (`agent/`, Go, binary `sohobotp-agent`) and the portal
(`portal/agent.php`, PHP). Both sides are tested against
[agent-protocol-vectors.json](agent-protocol-vectors.json), generated with the portal's
libsodium. Background: [endpoints.md](endpoints.md).

## Conventions

- Transport: HTTPS only. The agent verifies the certificate against the system roots or a
  CA file given at install (`--ca-file`, for the appliance's self-signed certificate).
  It never disables verification.
- Binary values (keys, signatures, nonces, sealed secrets) are **standard base64 with padding**.
- JSON is UTF-8. Unknown fields must be ignored by both sides (forward compatibility).
- Primitives (libsodium names / Go equivalents):
  - signatures: Ed25519 detached (`crypto_sign_detached` / `crypto/ed25519`);
  - sealed secrets: `crypto_box_seal` (X25519 + XSalsa20-Poly1305) /
    `golang.org/x/crypto/nacl/box.OpenAnonymous`;
  - hashes: SHA-256, lowercase hex.
- Endpoint id: 20 lowercase hex characters.
- Every request is `POST https://<portal>/portal/agent.php?a=<action>` with
  `Content-Type: application/json`. Maximum request body 256 KiB.
- Errors: HTTP 4xx/5xx with `{"error": "<code>", "message": "<text>"}`. Codes:
  `bad_request`, `bad_token` (enrolment), `bad_signature`, `clock_skew`, `replay`,
  `unknown_endpoint`, `disabled` (endpoint revoked), `rate_limited`, `server_error`.
  On any error the agent keeps enforcing its last applied configuration and retries
  with exponential backoff (max 15 minutes). It never removes 2FA because the portal is
  unreachable or answers with an error.

## Portal key pin

The portal has one Ed25519 **config-signing key**. Its pin is the lowercase hex SHA-256 of
the 32-byte public key (vector: `portal_key_pin`). The admin copies the pin from the
enrolment page into the install command; the agent refuses to enrol if the
`portal_key` returned by the portal does not match.

## 1. Enrol: `a=enroll` (not signed by an endpoint key)

The agent creates its keys first: an Ed25519 signing key pair and an X25519 box key pair.

Request:

```json
{
  "token": "<enrolment token>",
  "sign_key": "<base64 Ed25519 public key>",
  "box_key": "<base64 X25519 public key>",
  "proof": "<base64 Ed25519 signature>",
  "inventory": { ... see Inventory ... }
}
```

`proof` signs, with the new signing key, the exact bytes:

```
multiotp-agent-enroll-v1\n<token>\n<sign_key base64>\n<box_key base64>
```

(no trailing newline; vector `enroll`). It proves the agent holds the private key.

Response 200:

```json
{ "endpoint_id": "e8f2c1a9b4d7e6f5a3c2", "portal_key": "<base64 Ed25519 public key>", "checkin_interval": 60 }
```

The agent checks the pin, stores `endpoint_id`, `portal_key` and the portal URL, then checks
in immediately. An enrolment token is single- or multi-use with an expiry, set by the admin.

## 2. Signed requests (every action except `enroll`)

Headers:

| Header | Value |
|---|---|
| `X-Agent-Id` | endpoint id |
| `X-Agent-Time` | Unix time in seconds (decimal) |
| `X-Agent-Nonce` | base64 of 16 random bytes, new per request |
| `X-Agent-Signature` | base64 Ed25519 signature (endpoint signing key) |

Signed message, exact bytes, `\n` = LF, no trailing newline (vector `request`):

```
multiotp-agent-v1\n<METHOD>\n<request URI exactly as sent, path + query>\n<time>\n<nonce>\n<sha256 hex of the raw body>
```

The portal refuses: time more than 300 s away (`clock_skew`), a nonce seen in the last
600 s for that endpoint (`replay`), a bad signature, an unknown or disabled endpoint.

## 3. Check in: `a=checkin`

Request body:

```json
{
  "inventory": { ... },
  "applied": { "version": 3, "status": "applied", "error": "", "at": 1794150000 }
}
```

`applied.status`: `applied` | `failed` | `none` (nothing applied yet). `error` is a short text
without secrets.

Response 200:

```json
{ "checkin_interval": 60, "state": "active", "config": null, "update": null }
```

- `state`: `active`, or `pending` while the machine waits for approval (enrolment token with
  administrator or Active Directory approval). A pending machine gets no configuration; the
  agent keeps checking in at the interval and shows the state in `status`.

- `config`: `null` when the agent's applied version is current; otherwise a signed
  configuration envelope (section 4). After a `failed` apply of version N the portal
  sends N again only when it changes (version N+1).
- `update`: `null`, or a signed release offered for self-update when the endpoint group has a
  newer target version for this OS and architecture:
  `{"version", "os", "arch", "sha256", "size", "signature"}`. The signature (Ed25519, the
  OFFLINE release key built into the agent, never the portal key) covers
  `sohobotp-release-v1\n<os>\n<arch>\n<version>\n<sha256 lowercase hex>\n<size>`. The agent
  ignores versions not newer than its own, verifies the signature before downloading, then
  downloads with a signed `POST agent.php?a=release` body `{"version", "os", "arch"}`
  (answer: the binary, `application/octet-stream`) and checks size and SHA-256.

## 4. Signed configuration

Envelope:

```json
{ "payload": "<base64 of the payload JSON bytes>", "signature": "<base64 Ed25519 signature>" }
```

The signature (portal key) covers the bytes `multiotp-config-v1\n` followed by the decoded
payload bytes. The agent must:

1. verify the signature with the **pinned** portal key;
2. check `endpoint_id` is its own and `os` is its OS;
3. refuse a `version` lower than or equal to the last **applied** version (no rollback, no replay);
4. open each value of `secrets` with its box key (`OpenAnonymous`); any failure rejects the
   whole configuration;
5. apply it, and report the result in the next check-in.

Payload:

```json
{
  "endpoint_id": "e8f2c1a9b4d7e6f5a3c2",
  "version": 4,
  "issued_at": 1794150060,
  "os": "linux",
  "policy": { ... },
  "secrets": { "radius_secret": "<base64 sealed box>" }
}
```

### Linux policy (`os = linux`)

| Field | Type | Meaning |
|---|---|---|
| `enabled` | bool | false: remove the agent's PAM include and files (2FA off for this machine) |
| `radius_servers` | `[{host, port}]` | FreeRADIUS servers, in failover order |
| `timeout` | int | seconds per server |
| `services` | `[string]` | PAM services to protect, subset of `sshd`, `sudo`, `login`, `su` |
| `excluded_users` | `[string]` | never asked for a code (`root` always added by the agent) |
| `excluded_groups` | `[string]` | group members never asked for a code (break-glass) |
| `ssh_keys_need_code` | bool | SSH public-key logins also need the code (`AuthenticationMethods publickey,keyboard-interactive`) |

Secret: `radius_secret` (this endpoint's RADIUS shared secret).

### Windows policy (`os = windows`): SohobOTP Sign-in

| Field | Type | Registry value under `HKCR\CLSID\{B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}` |
|---|---|---|
| `server_url` | string | `multiOTPServers` (the endpoint's own CP gateway URL) |
| `server_timeout` | int | `multiOTPServerTimeout` (DWORD) |
| `cpus_logon` | string `[0-3][ed]` | `cpus_logon` |
| `cpus_unlock` | string | `cpus_unlock` |
| `cpus_credui` | string | `cpus_credui` |
| `excluded_account` | string | `excluded_account` |
| `cache_enabled` | bool | `multiOTPCacheEnabled` (`1`/`0`) |
| `upn_format` | bool | `multiOTPUPNFormat` |
| `default_prefix` | string | `multiOTPDefaultPrefix` |
| `timeout_unlock` | int (minutes) | `multiOTPTimeoutUnlock` |
| `without2fa` | bool | `multiOTPWithout2FA` |
| `two_step_hide_otp` | bool | `two_step_hide_otp` |
| `two_step_send_password` | bool | `two_step_send_password` |
| `login_text` | string | `login_text` |
| `otp_text` | string | `otp_text` |

Secret: `cp_shared_secret` → `multiOTPSharedSecret`.

## Inventory

```json
{
  "hostname": "lin-01", "os": "linux", "os_name": "Debian GNU/Linux", "os_version": "12",
  "kernel": "6.1.0-26-amd64", "arch": "amd64", "domain": "", "ips": ["10.0.0.21"],
  "agent_version": "0.1.0",
  "component": { "name": "pam_radius", "version": "2.0.0" }
}
```

Windows: `component.name` = `multiotp-cp`, `domain` = AD domain if joined. Strings are
limited to 255 characters, `ips` to 32 entries.
