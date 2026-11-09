# Test-only Linux endpoint: SSH, sudo, pam_radius, pamtester. Public test passwords only.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client sudo libpam-radius-auth pamtester \
      python3 python3-pexpect ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd \
 && groupadd mfa-breakglass \
 && for u in alice bob carol; do useradd -m -s /bin/bash "$u" && echo "$u:$u-Local-Pass-1" | chpasswd; done \
 && useradd -m -s /bin/bash deploy && echo 'deploy:deploy-Local-Pass-1' | chpasswd \
 && useradd -m -s /bin/bash -G mfa-breakglass ops && echo 'ops:ops-Local-Pass-1' | chpasswd \
 && echo 'root:root-Local-Pass-1' | chpasswd \
 && cp -a /etc/pam.d /etc/pam.d.orig && cp -a /etc/ssh /etc/ssh.orig \
 && cp -a /etc/pam_radius_auth.conf /etc/pam_radius_auth.conf.test-orig
CMD ["/usr/sbin/sshd", "-D", "-e"]
