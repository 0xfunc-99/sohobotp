# SohobOTP login gateway

A sign-in page **in front of** web sites that have no login of their own, or none you can
change: Prometheus, Alertmanager, Grafana, a VMware console, any internal dashboard.

```
browser ──► SohobOTP gateway ──(only after a right code)──► the site
                 │
                 └── POST /v1/auth/check ──► SohobOTP portal
```

1. Someone opens the site's address (the gateway's address).
2. Without a gateway session, they see **"Sign in"**: user name and the 6-digit code from their
   authenticator app. The gateway asks the portal (`POST /v1/auth/check`); the portal counts
   wrong codes and locks the user like any other sign-in, and the check is in its audit trail.
3. With a right code, and a user in the site's allowed list, the gateway sets a session cookie
   (8 hours by default) and every request goes through to the site, websockets too.
4. `/_sohobotp/logout` signs out of that site.

The site sees the user name in `X-SohobOTP-User` (and, if set, in `user_header`, e.g. Grafana's
`X-WEBAUTH-USER`, so Grafana signs the user in by itself). It never sees the gateway cookie.

**The site must only be reachable through the gateway.** Give it no public port (as in the demo)
or block direct access in the firewall; otherwise the gateway protects nothing.

## Configuration

Environment:

| Variable | |
|---|---|
| `SOHOBOTP_PORTAL` | the portal, e.g. `https://sohobotp.example.com` |
| `SOHOBOTP_API_KEY` or `SOHOBOTP_API_KEY_FILE` | an API key with the permission **Check a user's code** (portal → API keys). Limit it to the gateway's address. |
| `SOHOBOTP_CA` | the portal's CA certificate (PEM), when it is not publicly trusted |

`/etc/sohobotp-gateway/sites.json`, one entry per protected site:

```json
[
  {"id": "prometheus", "name": "Prometheus", "listen": 9091,
   "upstream": "http://prometheus:9090", "allow": ["alice", "bob"], "hours": 8},
  {"id": "vcenter", "name": "vCenter", "listen": 443, "tls_cert": "/certs/gw.pem", "tls_key": "/certs/gw.key",
   "upstream": "https://vcenter.example.local", "upstream_ca": "/certs/vcenter-ca.pem", "allow": ["*"]}
]
```

| Field | |
|---|---|
| `id` | lower-case name (letters, digits, dashes) |
| `name` | shown on the sign-in page |
| `listen` | the gateway's port for this site |
| `upstream` | where the site really is (`http://` or `https://`) |
| `allow` | SohobOTP user names allowed on this site, or `["*"]` for every SohobOTP user |
| `hours` | session length, 1–24 (default 8) |
| `user_header` | optional: header that carries the user name to the site |
| `tls_cert`, `tls_key` | optional: HTTPS on this port (**use HTTPS for anything real**) |
| `upstream_ca` | optional: check the site's certificate with this CA (otherwise not checked) |

The session cookie is signed with `/data/gateway.key` (made at the first start): keep `/data` on a
volume. Deleting the key signs everyone out. Ten wrong codes from one address within 15 minutes
make that address wait 15 minutes (the portal also locks the user).

## Try it: Prometheus and Grafana

```sh
sh gateway/demo/demo.sh start
```

Then open **http://172.16.196.1:9091** (Prometheus) or **http://172.16.196.1:3001** (Grafana),
from the Mac or a VM, and sign in with a SohobOTP user and the code from the phone. Grafana
opens already signed in as that user. `sh gateway/demo/demo.sh stop` removes it.

## Tests

```sh
sh gateway/tests/run.sh
```

Builds the gateway and checks it against a fake portal and a fake site: wrong, right and locked
codes, users not allowed, forged or changed cookies, forged user headers, redirects to other
sites, sign-out, and the limit on wrong codes.

## VMware consoles

- **VMware Horizon, NSX/Aria through Workspace ONE Access**: use RADIUS instead (portal →
  VPNs and devices); nothing in front.
- **vCenter, Cloud Director**: the gateway in front works; people type their code at the gateway,
  then their usual vCenter password. Scripts (PowerCLI, Terraform) cannot type a code: give them
  a separate, restricted path to the API.
