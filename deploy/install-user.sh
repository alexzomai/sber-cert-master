#!/bin/sh
# Install without root: systemd --user units, state under ~/.local/state. Run from the repository root.
set -eu
. deploy/_install_lib.sh
check_prereqs

PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/sber-cert-master"
BIN="$HOME/.local/bin/sber-cert-master"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sber-cert-master"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/sber-cert-master"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

install_package "$PREFIX" "$BIN"
mkdir -p "$UNITS"

install -d -m 0700 "$CONF_DIR" "$STATE"
if [ ! -f "$CONF_DIR/config.toml" ]; then
  sed -e "s#^state_dir = .*#state_dir = \"$STATE/state\"#" \
      -e "s#^publish_dir = .*#publish_dir = \"$STATE/public\"#" \
      -e 's/^publish_group = .*/# publish_group = "sber-agents"/' \
      deploy/config.example.toml > "$CONF_DIR/config.toml"
  chmod 0600 "$CONF_DIR/config.toml"
fi
# Units get the resolved config/binary paths (XDG_CONFIG_HOME may differ from ~/.config).
case "$CONF_DIR$BIN" in *[\"\\%\$\#\&]*|*"
"*) echo "недопустимые символы в путях: $CONF_DIR $BIN" >&2; exit 1;; esac
for u in sber-cert-master.service sber-cert-master-check.service; do
  sed -e "s#@CONFIG@#$CONF_DIR/config.toml#g" -e "s#@BIN@#$BIN#g" \
    "deploy/user/$u" > "$UNITS/$u"
  chmod 0644 "$UNITS/$u"
done
install -m 0644 deploy/user/sber-cert-master-check.timer "$UNITS/"
systemctl --user daemon-reload
echo "Установлено (user mode). Конфиг: $CONF_DIR/config.toml"
echo "export SBER_CERT_MASTER_CONFIG=$CONF_DIR/config.toml"
echo "Чтобы служба работала без входа пользователя: loginctl enable-linger $(id -un)"
