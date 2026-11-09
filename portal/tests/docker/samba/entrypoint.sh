#!/bin/sh
set -eu
# All credentials in this fixture are public TEST-ONLY values.
samba-tool domain provision --realm=EXAMPLE.TEST --domain=EXAMPLE \
  --server-role=dc --dns-backend=SAMBA_INTERNAL --use-rfc2307 \
  --adminpass='Test-Admin-Password-42!' --host-name=dc
mkdir -p /var/lib/samba/private/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=dc.example.test' \
  -addext 'subjectAltName=DNS:dc.example.test' \
  -keyout /var/lib/samba/private/tls/key.pem \
  -out /var/lib/samba/private/tls/cert.pem
chmod 600 /var/lib/samba/private/tls/key.pem
# Explicit paths avoid Samba generating a different certificate on startup.
sed -i '/\[global\]/a\
\ttls enabled = yes\n\ttls keyfile = /var/lib/samba/private/tls/key.pem\n\ttls certfile = /var/lib/samba/private/tls/cert.pem\n\ttls cafile = /var/lib/samba/private/tls/cert.pem' /etc/samba/smb.conf
samba-tool ou create 'OU=Staff,DC=example,DC=test'
for user in alice bob carol dave erin; do
  samba-tool user create "$user" 'Test-User-Password-42!' \
    --userou=OU=Staff --given-name="$user" --surname=Example \
    --use-username-as-cn --mail-address="$user@example.test"
done
samba-tool user disable erin
samba-tool user create svc-multiotp 'Test-Service-Password-42!' --use-username-as-cn
samba-tool group add MFA-Users
samba-tool group add VPN-Users
samba-tool group addmembers MFA-Users alice,bob
samba-tool group addmembers VPN-Users carol,MFA-Users
# Computer accounts for the endpoint tests (tests/e2e-ad-endpoints.php)
samba-tool ou create 'OU=Laptops,DC=example,DC=test'
samba-tool ou create 'OU=Servers,DC=example,DC=test'
samba-tool computer create PC01 --computerou='OU=Laptops'
samba-tool computer create PC02 --computerou='OU=Laptops'
samba-tool computer create SRV01 --computerou='OU=Servers'
samba-tool group add MFA-Servers
samba-tool group add All-Servers
samba-tool group addmembers MFA-Servers 'SRV01$'
samba-tool group addmembers All-Servers MFA-Servers
exec samba --foreground --no-process-group
