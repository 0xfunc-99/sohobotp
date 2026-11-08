# Disposable Samba AD fixture

Realm `EXAMPLE.TEST`, NetBIOS domain `EXAMPLE`, hostname `dc.example.test`.
Provisioned from scratch at container startup; no state or secrets are retained.
All passwords below are public **test-only** values:

| Account | Password | Purpose |
|---|---|---|
| Administrator | `Test-Admin-Password-42!` | Test mutations only |
| svc-multiotp | `Test-Service-Password-42!` | Ordinary read-only directory user used by the portal |
| alice, bob, carol, dave, erin | `Test-User-Password-42!` | Users in `OU=Staff,DC=example,DC=test`; erin starts disabled |

`MFA-Users` contains alice and bob. `VPN-Users` contains carol and the nested
`MFA-Users` group. Groups and the service account reside in `CN=Users`, outside
Staff so an unfiltered Staff sync finds exactly five accounts.

LDAPS listens on 636. Each run generates a new self-signed certificate with
`DNS:dc.example.test` in its SAN. Only the public certificate is copied to the
PHP container for trust; the private key stays in the DC. The readiness probe
uses the service account over LDAPS before the suite starts.

## Docker requirements

Use Linux Docker or Docker Desktop in Linux-container mode. Samba's SYSVOL
provisioning stores Windows ACLs in `security.NTACL` extended attributes and
requires `--cap-add SYS_ADMIN` and a filesystem supporting xattrs. The runner
uses the container's Linux writable layer, not a macOS/Windows bind mount for
Samba data. No `--privileged`, host networking, Docker socket mount, or published
ports are used. A restrictive/rootless runtime that cannot grant that capability
may not support this fixture. This is a test DC, not a production deployment.

See Samba's [ACL xattr documentation](https://www.samba.org/samba/docs/current/man-html/vfs_acl_xattr.8.html)
and [TLS settings](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html).

Run from the repository root:

```sh
MULTIOTP_TEST_AD=1 sh portal/tests/run-in-docker.sh
```

If buildx cannot write its settings, prefix the command with
`BUILDX_CONFIG="$(mktemp -d)"`. The normal OpenLDAP suite runs first, followed by
AD checks in a fresh PHP container and separate data directories. Containers,
network and temporary certificate copies are cleaned up on exit. The AD test
changes bob's enabled state and group membership; recreate the fixture before
rerunning it.
