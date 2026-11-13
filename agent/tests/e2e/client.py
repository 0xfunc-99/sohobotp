#!/usr/bin/env python3
"""Linux endpoint side of the agent end-to-end test. Runs INSIDE the Debian test container.

  client.py <phase> <seeds.json>

Each check prints "ok   name" or "FAIL name  [detail]"; the exit code is the number of
failures. TOTP codes are computed here; a code is never reused (the portal refuses replays),
so the helper waits for the next 30-second step when needed.
"""
import hashlib, hmac, json, os, struct, subprocess, sys, time

import pexpect

STEPS = "/tmp/totp-steps.json"
RADIUS_FILE = next(f for f in ("/etc/raddb/server", "/etc/pam_radius.conf", "/etc/pam_radius_auth.conf") if os.path.exists(f))
failures = 0


def check(name, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else "  [" + str(detail)[:400] + "]"), flush=True)


def code(seeds, user):
    used = json.load(open(STEPS)) if os.path.exists(STEPS) else {}
    while int(time.time()) // 30 <= used.get(user, -1):
        time.sleep(0.5)
    step = int(time.time()) // 30
    used[user] = step
    json.dump(used, open(STEPS, "w"))
    digest = hmac.new(bytes.fromhex(seeds[user]), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000)


def wrong(seeds, user):
    right = code(seeds, user)
    return "%06d" % ((int(right) + 1) % 1000000)


def pam(service, user, *answers, timeout=60):
    p = subprocess.run(["pamtester", service, user, "authenticate"], input="\n".join(answers) + "\n",
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def pw(user):
    return user + "-Local-Pass-1"


def ssh_login(user, password, otp):
    child = pexpect.spawn("ssh", ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                                  "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=keyboard-interactive",
                                  user + "@localhost", "echo", "LOGIN-OK-" + user], encoding="utf-8", timeout=40)
    try:
        child.expect("(?i)password:")
        child.sendline(password)
        child.expect("(?i)code:")
        child.sendline(otp)
        i = child.expect(["LOGIN-OK-" + user, "(?i)password:", "(?i)denied", pexpect.EOF])
        return i == 0, child.before
    except pexpect.TIMEOUT:
        return False, "timeout: " + str(child.before)


def same_tree(a, b):
    p = subprocess.run(["diff", "-r", a, b], capture_output=True, text=True)
    return p.returncode == 0, p.stdout


def main():
    phase, seeds = sys.argv[1], json.load(open(sys.argv[2]))
    if phase == "logins":
        ok, out = pam("sshd", "alice", pw("alice"), code(seeds, "alice"))
        check("sshd: password + right code accepted", ok, out)
        ok, out = pam("sshd", "alice", pw("alice"), wrong(seeds, "alice"))
        check("sshd: wrong code refused", not ok, out)
        ok, out = pam("sshd", "alice", "not-the-password", code(seeds, "alice"))
        check("sshd: wrong password with a right code refused", not ok, out)
        ok, out = pam("sshd", "deploy", pw("deploy"))
        check("sshd: excluded user needs only the password", ok, out)
        ok, out = pam("sshd", "deploy", "wrong-password")
        check("sshd: excluded user still needs the right password", not ok, out)
        ok, out = pam("sshd", "ops", pw("ops"))
        check("sshd: break-glass group member needs only the password", ok, out)
        ok, out = pam("sshd", "root", "root-Local-Pass-1")
        check("sshd: root is never asked for a code", ok, out)
        ok, out = pam("sudo", "bob", pw("bob"), code(seeds, "bob"))
        check("sudo: password + code accepted", ok, out)
        ok, out = pam("sudo", "bob", pw("bob"))
        check("sudo: password alone refused", not ok, out)
        ok, out = ssh_login("carol", pw("carol"), code(seeds, "carol"))
        check("real SSH session: password then code", ok, out)
        ok, out = ssh_login("carol", pw("carol"), wrong(seeds, "carol"))
        check("real SSH session: wrong code refused", not ok, out)
        check("sshd -t accepts the generated configuration", subprocess.run(["sshd", "-t"]).returncode == 0)
        check("RADIUS file readable by root only", oct(os.stat(RADIUS_FILE).st_mode & 0o777) == "0o600")
    elif phase == "radius-down":
        ok, out = pam("sshd", "alice", pw("alice"), code(seeds, "alice"), timeout=120)
        check("RADIUS down: users needing a code are refused", not ok, out)
        ok, out = pam("sshd", "deploy", pw("deploy"))
        check("RADIUS down: excluded user still gets in", ok, out)
        ok, out = pam("sshd", "ops", pw("ops"))
        check("RADIUS down: break-glass group still gets in", ok, out)
        ok, out = pam("sshd", "root", "root-Local-Pass-1")
        check("RADIUS down: root not locked out", ok, out)
    elif phase == "radius-back":
        ok, out = pam("sshd", "alice", pw("alice"), code(seeds, "alice"))
        check("RADIUS back: password + code accepted again", ok, out)
    elif phase == "per-user":
        ok, out = pam("sudo", "bob", pw("bob"))
        check("per user: bob uses sudo with his password only (unticked for admin actions)", ok, out)
        ok, out = pam("sshd", "bob", pw("bob"))
        check("per user: bob still needs the code for SSH (ticked at sign-in)", not ok, out)
        ok, out = pam("sudo", "alice", pw("alice"))
        check("per user: other users still need the code for sudo", not ok, out)
    elif phase == "sudo-removed":
        same = open("/etc/pam.d/sudo").read() == open("/etc/pam.d.orig/sudo").read()
        check("policy change: sudo restored byte for byte", same)
        ok, out = pam("sudo", "bob", pw("bob"))
        check("policy change: sudo needs only the password again", ok, out)
        ok, out = pam("sshd", "alice", pw("alice"))
        check("policy change: SSH still needs the code", not ok, out)
    elif phase == "disabled":
        same, diff = same_tree("/etc/pam.d", "/etc/pam.d.orig")
        check("2FA off: /etc/pam.d identical to before the agent", same, diff)
        check("2FA off: package RADIUS file restored, SSH drop-in removed",
              open(RADIUS_FILE).read() == open(RADIUS_FILE + ".test-orig").read()
              and not os.path.exists(RADIUS_FILE + ".sohobotp-orig")
              and not os.path.exists("/etc/ssh/sshd_config.d/00-sohobotp.conf"))
        ok, out = pam("sshd", "alice", pw("alice"))
        check("2FA off: password alone works", ok, out)
    else:
        print("unknown phase", phase)
        sys.exit(99)
    sys.exit(failures)


if __name__ == "__main__":
    main()
