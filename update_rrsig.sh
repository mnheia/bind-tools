#!/usr/bin/env bash
set -Eeuo pipefail

LOCK="${LOCK:-/run/lock/update-rrsig.lock}"
LOG="${LOG:-/var/log/update_rrsig.log}"
DNS_ROOT="${DNS_ROOT:-/etc/bind/zones/external}"
BIND_CONF="${BIND_CONF:-/etc/bind/named.conf}"
BIND_GROUP="${BIND_GROUP:-bind}"
VALID_DAYS="${VALID_DAYS:-35}"
VALID_SECONDS="$((VALID_DAYS * 86400))"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERIAL_SCRIPT="${SERIAL_SCRIPT:-${SCRIPT_DIR}/update_zone_serial.sh}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <zone> [zone ...]" >&2
  echo "Example: $0 example.com example.net" >&2
  exit 1
fi

exec >>"$LOG" 2>&1

echo
echo "===== $(date -Is) starting DNSSEC RRSIG update ====="

exec 200>"$LOCK"
flock -n 200 || {
  echo "Another instance is already running. Exiting."
  exit 0
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1" >&2
    exit 1
  }
}

need_cmd dnssec-signzone
need_cmd named-checkzone
need_cmd named-checkconf
need_cmd rndc
need_cmd openssl

[ -x "$SERIAL_SCRIPT" ] || {
  echo "ERROR: zone serial helper not executable: $SERIAL_SCRIPT" >&2
  exit 1
}

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

for DOM_NAME in "$@"; do
  DOM_NAME="${DOM_NAME%.}"
  DOM_PATH="${DNS_ROOT}/${DOM_NAME}"
  DOM_FILE="${DOM_PATH}/${DOM_NAME}"
  SIGNED_FILE="${DOM_FILE}.signed"
  TMP_SIGNED="${WORKDIR}/${DOM_NAME}.signed"
  SALT="$(openssl rand -hex 8)"

  echo
  echo "Processing zone: ${DOM_NAME}"
  echo "Zone file: ${DOM_FILE}"

  [ -d "$DOM_PATH" ] || { echo "ERROR: zone directory not found: $DOM_PATH" >&2; exit 1; }
  [ -s "$DOM_FILE" ] || { echo "ERROR: zone file missing or empty: $DOM_FILE" >&2; exit 1; }

  echo "Validating unsigned zone before serial update"
  ( cd "$DOM_PATH" && named-checkzone "$DOM_NAME" "$DOM_NAME" )

  echo "Updating SOA serial"
  "$SERIAL_SCRIPT" "$DOM_FILE"

  echo "Validating unsigned zone after serial update"
  ( cd "$DOM_PATH" && named-checkzone "$DOM_NAME" "$DOM_NAME" )

  echo "Signing zone ${DOM_NAME}"
  (
    cd "$DOM_PATH"
    dnssec-signzone       -A       -3 "$SALT"       -e "+${VALID_SECONDS}"       -o "$DOM_NAME"       -f "$TMP_SIGNED"       -t "$DOM_NAME"
  )

  [ -s "$TMP_SIGNED" ] || { echo "ERROR: signed zone was not created: $TMP_SIGNED" >&2; exit 1; }

  echo "Validating signed zone"
  named-checkzone "$DOM_NAME" "$TMP_SIGNED"

  if [ -s "$SIGNED_FILE" ]; then
    cp -a "$SIGNED_FILE" "${SIGNED_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
  fi

  echo "Installing signed zone: $SIGNED_FILE"
  install -o root -g "$BIND_GROUP" -m 0644 "$TMP_SIGNED" "$SIGNED_FILE"
done

echo
echo "Validating complete BIND config"
named-checkconf "$BIND_CONF"

echo "Reloading BIND"
rndc reload

echo "DNSSEC RRSIG update completed successfully"
echo "===== $(date -Is) finished DNSSEC RRSIG update ====="
