# SohobOTP — licences

SohobOTP is a product of **Sohobcom**. The SohobOTP portal (`portal/`) and the SohobOTP agent
(`agent/`) are written by Sohobcom. SohobOTP also contains and uses open-source software; its
licences allow using, changing and selling it, and require that the notices below and the
licence texts stay available. Files that SohobOTP changed keep their original licence
(for LGPL files, their source code must stay available to those who receive SohobOTP).

## Included in SohobOTP

| Component | Where | Licence | Copyright |
|---|---|---|---|
| multiOTP engine and server (changed by Sohobcom) | `multiotp.class.php`, `multiotp.php`, `multiotp.server.php`, appliance bundle | LGPL-3.0 (`COPYING`, `COPYING.LESSER`) | SysCo systemes de communication sa |
| phpseclib (AES, RSA, X509, SSH2, SFTP, …) | `contrib/` | MIT | Jim Wigginton and contributors |
| Html MIME Mail (MAIL, MIME, SMTP, FUNC) | `contrib/` | LGPL | Tanase Laurentiu Iulian |
| NuSOAP | `contrib/nusoap.php` | LGPL-2.1 | NuSphere Corporation and contributors |
| adLDAP (LDAP/AD access, changed) | `contrib/MultiotpAdLdap.php` | as in the file header | adLDAP authors, SysCo |
| QR code library | `contrib/MultiotpQrcode.php` | MIT | as in the file header |
| Barcode library | `contrib/barcode.php` | MIT | Kreative Software |
| ShowStatus | `contrib/MultiotpShowStatus.php` | BSD | dealnews.com, Inc. |
| Other `contrib/` files | `contrib/` | as in each file header | their authors |
| Go standard library, golang.org/x/crypto, golang.org/x/sys | compiled into the SohobOTP agent | BSD-3-Clause | The Go Authors |
| Windows sign-in component (from the multiOTP Credential Provider) | Windows | Apache-2.0 | SysCo systemes de communication sa, NetKnights GmbH, ArcadeJust, Last Squirrel IT |
| PHP for Windows (embedded runtime, unchanged) | SohobOTP Sign-in installer | PHP License 3.01 | The PHP Group |
| SetACL (unchanged) | SohobOTP Sign-in installer (sets permissions during install) | LGPL-3.0 | Helge Klein |

## Used by the SohobOTP appliance (separate programs)

| Program | Licence |
|---|---|
| FreeRADIUS | GPL-2.0 |
| nginx | BSD-2-Clause |
| PHP | PHP License 3.01 |
| Debian GNU/Linux packages | their own licences |

The full licence texts are in this repository (`COPYING`, `COPYING.LESSER`) and in each
component's files.
