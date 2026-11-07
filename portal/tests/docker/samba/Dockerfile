# Test fixture only: disposable Samba Active Directory, never a production DC.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba samba-ad-dc winbind ldap-utils openssl attr \
 && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
EXPOSE 636
ENTRYPOINT ["sh", "/entrypoint.sh"]
