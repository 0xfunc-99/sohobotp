# Test-only RHEL-family endpoint (Rocky Linux 9): SSH, sudo, pam_radius (EPEL), pamtester.
# Public test passwords only.
FROM rockylinux:9
RUN dnf install -y epel-release \
 && dnf install -y openssh-server openssh-clients sudo pam_radius pamtester python3 python3-pexpect \
      procps-ng diffutils shadow-utils hostname \
 && dnf clean all
RUN ssh-keygen -A \
 && groupadd mfa-breakglass \
 && for u in alice bob carol; do useradd -m -s /bin/bash "$u" && echo "$u:$u-Local-Pass-1" | chpasswd; done \
 && useradd -m -s /bin/bash deploy && echo 'deploy:deploy-Local-Pass-1' | chpasswd \
 && useradd -m -s /bin/bash -G mfa-breakglass ops && echo 'ops:ops-Local-Pass-1' | chpasswd \
 && echo 'root:root-Local-Pass-1' | chpasswd \
 && cp -a /etc/pam.d /etc/pam.d.orig && cp -a /etc/ssh /etc/ssh.orig \
 && cp -a /etc/pam_radius.conf /etc/pam_radius.conf.test-orig
CMD ["/usr/sbin/sshd", "-D", "-e"]
