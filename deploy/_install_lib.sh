# Shared by install.sh / install-user.sh. No pip, no venv, no network: the package is pure stdlib.

check_prereqs() {
  PY="$(command -v python3 || true)"
  [ -n "$PY" ] || { echo "нужен python3 >= 3.11" >&2; exit 1; }
  "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 11))' || { echo "нужен python3 >= 3.11" >&2; exit 1; }
  "$PY" -c 'import ssl, tomllib, fcntl' || { echo "в python3 нет модулей ssl/tomllib/fcntl" >&2; exit 1; }
  command -v openssl >/dev/null || { echo "нужен openssl" >&2; exit 1; }
  command -v systemctl >/dev/null || { echo "нужен systemd" >&2; exit 1; }
  [ -f sber_cert_master/cli.py ] || { echo "запускайте из корня репозитория" >&2; exit 1; }
}

# install_package <base dir> <launcher path>
# Each install goes to a fresh <base>/releases/<id>/ and is validated there; the launcher is then
# switched with one atomic rename. An interruption at any point leaves the previous launcher and the
# package it points to intact (including a legacy venv layout under <base>).
install_package() {
  base="$1"; bin="$2"
  case "$base" in *\'*|*\\*) echo "недопустимые символы в пути: $base" >&2; exit 1;; esac
  rel="$base/releases/$(date +%Y%m%d%H%M%S)-$$"
  mkdir -p "$base/releases"
  chmod u=rwx,go=rx "$base" "$base/releases"   # explicit: do not inherit a restrictive umask
  mkdir -p "$rel/sber_cert_master/ca"
  cp sber_cert_master/*.py "$rel/sber_cert_master/"
  cp sber_cert_master/ca/*.pem "$rel/sber_cert_master/ca/"
  chmod -R u=rwX,go=rX "$base/releases"
  mkdir -p "$(dirname "$bin")"
  tmp="$bin.new.$$"
  cat > "$tmp" <<LAUNCHER
#!$PY
import sys
sys.path.insert(0, '$rel')
from sber_cert_master.cli import main
sys.exit(main())
LAUNCHER
  chmod 0755 "$tmp"
  # Validate the staged release through the staged launcher before anything is switched.
  if ! "$tmp" --version >/dev/null; then
    rm -rf "$tmp" "$rel"
    echo "новая версия не запускается; прежняя установка не тронута" >&2
    exit 1
  fi
  # Optional extra check supplied by the caller (system mode: run as the service account).
  if command -v verify_launcher >/dev/null 2>&1 && ! verify_launcher "$tmp"; then
    rm -rf "$tmp" "$rel"
    echo "новая версия не запускается от имени службы (права на $base?); прежняя установка не тронута" >&2
    exit 1
  fi
  # Release the previous launcher points to (kept for rollback), resolved before the switch.
  prev="$(sed -n "s/^sys.path.insert(0, '\(.*\)')\$/\1/p" "$bin" 2>/dev/null || true)"
  sync 2>/dev/null || true
  mv -f "$tmp" "$bin"   # atomic: replaces the old launcher (or legacy symlink) in one rename
  # Prune by identity, not by name order: never touch the active release or the previous one.
  for old in "$base"/releases/*; do
    [ -d "$old" ] || continue
    [ "$old" = "$rel" ] && continue
    [ -n "$prev" ] && [ "$old" = "$prev" ] && continue
    rm -rf "$old"
  done
}
