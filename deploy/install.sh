#!/bin/sh
# Idempotent installer. Run as root from the repository root.
set -eu
umask 022   # sudo may preserve a restrictive umask; installed program files must be world-readable
# Group that may read published tokens/TLS files. Must equal publish_group in config.toml.
# Custom group: sudo env AGENT_GROUP=<group> ./deploy/install.sh
AGENT_GROUP="${AGENT_GROUP:-sber-agents}"
. deploy/_install_lib.sh
check_prereqs   # before any account/group is created
[ "$(id -u)" = 0 ] || { echo "нужны права root (sudo)" >&2; exit 1; }

getent group "$AGENT_GROUP" >/dev/null || groupadd --system "$AGENT_GROUP"
getent passwd sber-cert-master >/dev/null || \
  useradd --system --home-dir /var/lib/sber-cert-master --shell /usr/sbin/nologin --user-group sber-cert-master
usermod -a -G "$AGENT_GROUP" sber-cert-master

install -d -o root -g root -m 0755 /opt/sber-cert-master
# The staged version must be runnable by the service account before it replaces the live one.
verify_launcher() {
  if command -v runuser >/dev/null; then
    runuser -u sber-cert-master -- "$1" --version >/dev/null
  else
    su -s /bin/sh sber-cert-master -c '"$0" --version' "$1" >/dev/null
  fi
}
install_package /opt/sber-cert-master /usr/local/bin/sber-cert-master

install -d -o root -g sber-cert-master -m 0750 /etc/sber-cert-master
if [ ! -f /etc/sber-cert-master/config.toml ]; then
  sed "s/^publish_group = .*/publish_group = \"$AGENT_GROUP\"         # группа пользователей, от которых работают агенты/" \
    deploy/config.example.toml > /etc/sber-cert-master/config.toml
  chown root:sber-cert-master /etc/sber-cert-master/config.toml
  chmod 0640 /etc/sber-cert-master/config.toml
fi
install -d -o sber-cert-master -g sber-cert-master -m 0755 /var/lib/sber-cert-master
# Private drop box for bootstrap secrets (.p12, client_secret, refresh_token): readable by the service only.
install -d -o sber-cert-master -g sber-cert-master -m 0700 /var/lib/sber-cert-master/incoming

install -m 0644 deploy/sber-cert-master.service deploy/sber-cert-master-check.service \
  deploy/sber-cert-master-check.timer /etc/systemd/system/
systemctl daemon-reload
echo "Установлено. Дальше: отредактируйте /etc/sber-cert-master/config.toml и выполните init (см. README)."
