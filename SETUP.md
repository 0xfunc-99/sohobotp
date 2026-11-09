# SohobOTP — setup guide

SohobOTP adds a one-time code (two-factor authentication) to Windows sign-in, Linux SSH/sudo,
VPNs and other RADIUS devices. It has three parts:

| Part | Runs on | What it does |
|---|---|---|
| **SohobOTP portal** (with FreeRADIUS) | one Linux server | users, codes, policies, RADIUS; the admin website |
| **SohobOTP agent** | every protected Windows or Linux machine | gets its policy from the portal and applies it |
| **SohobOTP Sign-in** | every protected Windows machine | the code field on the Windows sign-in screen |

```
   Portal server (site A)              Linux machine (site B)        Windows machine (site C)
 ┌──────────────────────────┐      ┌───────────────────────┐     ┌───────────────────────┐
 │ SohobOTP portal          │◄─────│ SohobOTP agent        │     │ SohobOTP agent        │
 │ https://PORTAL_IP/portal │ 443  │ SSH / sudo ask a code │     │ SohobOTP Sign-in      │
 │ FreeRADIUS               │◄─────│ (pam_radius)          │     │                       │
 └──────────────────────────┘ 1812 └───────────────────────┘     └──────────┬────────────┘
              ▲                                                    443       │
              └──────────────────────────────────────────────────────────────┘
```

In this guide, replace **`PORTAL_IP`** with the IP address (or DNS name) of your portal server.

## Contents of this kit

| Folder / file | What |
|---|---|
| `SETUP.md` | this guide |
| `agent/linux-amd64/sohobotp-agent` | Linux agent for Intel/AMD machines |
| `agent/linux-arm64/sohobotp-agent` | Linux agent for ARM machines (Raspberry Pi 4/5, ARM servers) |
| `agent/windows/sohobotp-agent.msi` | Windows agent installer (setup window, or silent for Group Policy) |
| `agent/windows/sohobotp-agent.exe` | Windows agent without installer |
| `windows-signin/SohobOTPSignIn.msi` | SohobOTP Sign-in installer (the code field on the Windows sign-in screen) |
| `source/` | full source: portal, agent, SohobOTP Sign-in (`source/windows-signin`) |
| `SHA256SUMS` | checksums (`shasum -a 256 -c SHA256SUMS`, or `Get-FileHash` on Windows) |

Version: agent 0.1.0, SohobOTP Sign-in 1.0.0. The Windows installers were built and tested
on Windows Server 2022 (36 automatic checks, see step 5).

---

## Step 1 — Prepare the portal server

You need a **Linux server** (Debian/Ubuntu recommended) with **Docker**, 2 CPU, 2 GB RAM, 20 GB
disk, internet access during installation, and a **fixed IP address**.
Do not use Docker Desktop on Mac/Windows for the portal: it hides the machines' real IP
addresses, which the portal needs.

Install Docker (Debian/Ubuntu):

```bash
sudo apt-get update && sudo apt-get install -y docker.io unzip
```

Copy the kit to the server and unpack it:

```bash
scp SohobOTP-Setup-Kit.zip you@PORTAL_IP:~/
ssh you@PORTAL_IP
unzip SohobOTP-Setup-Kit.zip && cd SohobOTP-Setup-Kit
```

Open the firewall of the server (example with ufw):

```bash
sudo ufw allow 443/tcp     # portal website, agents, Windows sign-in
sudo ufw allow 1812/udp    # RADIUS: Linux machines and VPN devices
sudo ufw allow 80/tcp      # optional: redirects to https
```

## Step 2 — Build and start the portal

```bash
cd source
sudo docker build -t sohobotp-portal .
```

The first build downloads the Debian packages and takes 10–20 minutes. Then start it:

```bash
sudo docker run -d --name sohobotp --restart unless-stopped --network host \
  -v sohobotp-etc:/etc/multiotp -v sohobotp-radius:/etc/freeradius \
  -v sohobotp-log:/var/log/multiotp sohobotp-portal
```

Wait one minute, then check that it runs: `sudo docker logs sohobotp | tail`.

All data lives in the Docker volumes `sohobotp-etc`, `sohobotp-radius` and `sohobotp-log`;
back them up (including `/etc/multiotp/portal/portal.key`, without which encrypted secrets
cannot be read after a restore).

## Step 3 — Certificate for the portal address

The agents always check the portal's certificate. For a test, create your own small
certificate authority and a certificate for `PORTAL_IP` (replace both occurrences of
`192.168.10.5`):

```bash
sudo docker exec sohobotp sh -c 'cd /tmp && IP=192.168.10.5 &&
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=SohobOTP test CA" -keyout ca.key -out ca.pem -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign &&
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$IP" -keyout srv.key -out srv.csr &&
  printf "subjectAltName=IP:$IP\nextendedKeyUsage=serverAuth\n" > ext &&
  openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -extfile ext -out srv.crt &&
  cp srv.crt /etc/multiotp/certificates/multiotp.crt && cp srv.key /etc/multiotp/certificates/multiotp.key &&
  nginx -s reload'
sudo docker cp sohobotp:/tmp/ca.pem ./ca.pem
```

Keep `ca.pem`: every agent machine needs a copy. With a DNS name instead of an IP, use
`subjectAltName=DNS:portal.example.com`. With a certificate from a public authority (for a
DNS name), install it the same way and leave out `ca.pem` everywhere below.

## Step 4 — First administrator and portal settings

Create the first administrator; it prints a temporary password:

```bash
sudo docker exec -it sohobotp php /usr/local/bin/multiotp/portal/bin/portal-admin.php create --username=admin --role=superadmin
```

Open **`https://PORTAL_IP/portal/`** in a browser — always with the same address the machines
will use. The browser warns about the test certificate the first time (accept it, or import
`ca.pem` into the browser). Sign in, set up your authenticator app (QR code), choose your own
password.

Then, in the portal:

1. **Users** → *New user*: create test users and scan their QR codes with an authenticator app
   (Google/Microsoft Authenticator, FreeOTP). Linux users must have the **same user name** as on
   the Linux machines. Use the login format **Code only** for a first test.
2. **RADIUS servers** → *New group*, e.g. "Linux servers" (defaults are fine).
3. **Endpoints** → *Endpoint groups* → *New group*:
   - for Linux: **Require a code on Linux machines** on, RADIUS server group "Linux servers",
     protect **SSH** and **sudo**, keep `mfa-breakglass` as excluded group, leave
     "RADIUS servers" empty;
   - for Windows: sign-in "Local and remote desktop, other sign-in options too" for the first
     test, and a break-glass account such as `PC01\breakglass`.
4. **Endpoints** → *Enrol endpoints* → *Create token*: choose the group, "Maximum machines",
   and **"An administrator approves each machine"** for a test. The next page shows the
   **token** (only once — copy it) and the **pin**, and the ready install commands. The pin is
   also always at the bottom of the *Enrol endpoints* page.

## Step 5 — Windows: SohobOTP Sign-in installer (ready-built)

The kit contains **`windows-signin\SohobOTPSignIn.msi`**, ready to install (step 6). It was
compiled and tested on a Windows Server 2022 machine on GitHub (private repository
`0xfunc-99/sohobotp`, workflow *windows*): install, registration as a Windows sign-in provider,
the agent writing its settings, uninstall — 36 checks, all passed.

The installers are not code-signed yet: Windows may show *"Windows protected your PC"* or
*unknown publisher*. Check the file with `SHA256SUMS` (`Get-FileHash`), then *More info* →
*Run anyway*.

To build it yourself instead (only after changing its source): push the source to your
private GitHub repository and download *signin-windows* from the *windows* run under
*Actions*, or on a Windows PC with **Visual Studio 2022** ("Desktop development with C++",
plus the v142 build tools with ATL and Spectre-mitigated libraries), **Git** and the
**WiX Toolset 3.14**, in **Developer PowerShell for VS 2022** inside `source\windows-signin`:

```powershell
.\get-php.ps1
msbuild SohobOTPSignIn.sln /m /p:Configuration=Release /p:Platform=x64
```

The installer is then `WixInstall\multiOTPCredentialProviderInstaller\bin\x64\Release\SohobOTPSignIn.msi`.

## Step 6 — Windows machine

**Use a test virtual machine with a snapshot first** — this changes the Windows sign-in screen.
Create the break-glass account (`net user breakglass <password> /add` as administrator), keep a
second session open while testing.

1. Install **Microsoft Visual C++ Redistributable 2015–2022 x64**
   (https://aka.ms/vs/17/release/vc_redist.x64.exe).
2. Install **SohobOTP Sign-in**: run `windows-signin\SohobOTPSignIn.msi` from the kit. Its own settings pages
   can be left as they are: the agent replaces them with the right values.
3. Copy `ca.pem` to `C:\SohobOTP\ca.pem`.
4. Install the **SohobOTP agent**: double-click `agent\windows\sohobotp-agent.msi` and fill in the
   window (portal address `https://PORTAL_IP`, token, pin, `C:\SohobOTP\ca.pem`) — or silently,
   as administrator:

   ```powershell
   msiexec /i sohobotp-agent.msi /qn PORTAL=https://PORTAL_IP TOKEN=<token> PIN=<pin> CAFILE=C:\SohobOTP\ca.pem
   ```

5. In the portal, **Endpoints** → the new machine → **Approve**.
6. Check: `& "C:\Program Files\SohobOTP\Agent\sohobotp-agent.exe" status` shows
   "Configuration: version 1, applied". Sign out and sign in with password + code.

For many machines: deploy both MSIs with Group Policy (silent command above, or Software
Installation with a transform), and use a token with **Active Directory approval**.

## Step 7 — Linux machine

Debian/Ubuntu or RHEL/Rocky 8/9 with systemd. **Keep a root session open** and put your own
account in the break-glass group before installing:

```bash
sudo groupadd -f mfa-breakglass && sudo usermod -aG mfa-breakglass $USER
```

Copy `agent/linux-amd64/sohobotp-agent` (or `linux-arm64`; `uname -m` says `x86_64` or
`aarch64`) and `ca.pem` to the machine, then:

```bash
sudo install -m 0755 sohobotp-agent /usr/local/sbin/sohobotp-agent
sudo sohobotp-agent install --portal https://PORTAL_IP --token <token> --pin <pin> --ca-file ./ca.pem
```

Approve the machine in the portal (**Endpoints** → machine → **Approve**), then:

```bash
sudo sohobotp-agent run --once
sudo sohobotp-agent status
```

It shows "version 1, applied". From another terminal: `ssh <user>@<machine>` asks for the
password, then **code:**. The agent installs `libpam-radius-auth` (Debian/Ubuntu) or
`pam_radius` (RHEL/Rocky, from EPEL) if missing.

## Step 8 — Test checklist

- [ ] Right code accepted, wrong code refused (Windows sign-in, SSH, sudo)
- [ ] Break-glass account / group gets in without a code
- [ ] Portal → **Endpoints**: machine online, inventory shown, configuration "up to date"
- [ ] Change the endpoint group (e.g. untick sudo): applied within 60 s (`run --once` to force)
- [ ] **RADIUS servers** → *Diagnostics*: test login and recent logins
- [ ] Disable the machine in the portal: its check-ins are refused
- [ ] Windows: unlock, Remote Desktop, offline login (if the group allows the offline cache)

## Troubleshooting

| Problem | What to check |
|---|---|
| Agent: "portal's key does not match the pin" | wrong address or pin; delete the half-enrolled endpoint in the portal and install again |
| Agent: certificate error | `--ca-file` / `CAFILE` missing, or the certificate is not for `PORTAL_IP` |
| Machine "waiting for approval" | approve it in **Endpoints** |
| Linux: everyone refused | UDP 1812 blocked between the machine and the portal; **RADIUS servers** → *Diagnostics* |
| "clock skew" | set up NTP; clocks must be within 5 minutes |
| Logs | Linux: `journalctl -u sohobotp-agent`; Windows: `C:\ProgramData\SohobOTP\agent\agent.log`; portal: `sudo docker logs sohobotp` |
| Locked out of Linux | use the open root session or a break-glass account; `sudo sohobotp-agent uninstall` removes the PAM changes |
| Locked out of Windows | break-glass account, or restore the VM snapshot |

## Limitations of this version

- **Windows is tested automatically, not yet by a person at the sign-in screen**: the
  installers, the agent and the settings it writes passed on Windows Server 2022, but
  signing in with password + code has to be tried on your test machine (step 6, with a
  snapshot and a break-glass account).
- The Windows installers are **not code-signed** (Windows warns about an unknown publisher).
- **Linux machines are identified by their IP address for RADIUS**: two Linux machines behind
  the same NAT address cannot both be protected; RADIUS across the internet needs a VPN.
- SSH passwords go through the keyboard-interactive prompt: scripts that send a password
  directly stop working on protected machines.
- The agents in this kit are built **without self-update** (no release key).
- Changes reach machines at their next check-in (60 s by default), not instantly.
- A disabled or deleted machine keeps its last configuration; uninstall the agent to remove 2FA.
- Data is stored in files: fine for hundreds of machines; MariaDB/HA, REST API and the
  Raspberry Pi image are not built yet.

## Licences

SohobOTP is a Sohobcom product built with open-source software (multiOTP engine LGPL-3.0,
SohobOTP Sign-in derived from the multiOTP Credential Provider Apache-2.0, and others). The list
is in `source/LICENSES.md` and on the portal page **Licences**; keep these notices when
distributing SohobOTP.
