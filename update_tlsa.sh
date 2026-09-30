#!/usr/bin/env bash
set -Eeuo pipefail

LOCK="${LOCK:-/run/lock/update-tlsa.lock}"
LOG="${LOG:-/var/log/update_tlsa.log}"
DNS_ROOT="${DNS_ROOT:-/etc/bind/zones/external}"
BIND_GROUP="${BIND_GROUP:-bind}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RRSIG_SCRIPT="${RRSIG_SCRIPT:-${SCRIPT_DIR}/update_rrsig.sh}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <hostname:port> [hostname:port ...]" >&2
  echo "Example: $0 mail.example.com:25 cloud.example.com:443" >&2
  exit 1
fi

exec >>"$LOG" 2>&1

echo
echo "===== $(date -Is) starting TLSA update ====="

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

need_cmd tlsa
need_cmd named-checkzone

[ -x "$RRSIG_SCRIPT" ] || {
  echo "ERROR: RRSIG helper not executable: $RRSIG_SCRIPT" >&2
  exit 1
}

find_zone() {
  local name="${1%.}"
  local candidate="$name"

  while [[ "$candidate" == *.* ]]; do
    if [[ -d "${DNS_ROOT}/${candidate}" && -s "${DNS_ROOT}/${candidate}/${candidate}" ]]; then
      echo "$candidate"
      return 0
    fi
    candidate="${candidate#*.}"
  done

  return 1
}

WORKDIR="$(mktemp -d)"
DOMAIN_LIST="${WORKDIR}/domains.list"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
: > "$DOMAIN_LIST"

for TLSA_ENTRY in "$@"; do
  DOM_NAME="${TLSA_ENTRY%%:*}"
  DOM_PORT="${TLSA_ENTRY##*:}"

  if [[ -z "$DOM_NAME" || ! "$DOM_PORT" =~ ^[0-9]+$ || "$DOM_PORT" -lt 1 || "$DOM_PORT" -gt 65535 ]]; then
    echo "ERROR: invalid hostname:port entry: $TLSA_ENTRY" >&2
    exit 1
  fi

  if ! DOMAIN="$(find_zone "$DOM_NAME")"; then
    echo "ERROR: could not find a matching zone under $DNS_ROOT for $DOM_NAME" >&2
    exit 1
  fi

  DOMAIN_DIR="${DNS_ROOT}/${DOMAIN}"
  DOMAIN_ZONE="${DOMAIN_DIR}/${DOMAIN}"
  TMP_FILE="${WORKDIR}/TLSA${DOMAIN}.key"
  ERR_FILE="${WORKDIR}/tlsa-${DOM_NAME//[^A-Za-z0-9_.-]/_}-${DOM_PORT}.err"

  echo
  echo "Generating TLSA for ${DOM_NAME}:${DOM_PORT}"
  echo "Base zone: ${DOMAIN}"

  touch "$TMP_FILE"
  echo "$DOMAIN" >> "$DOMAIN_LIST"

  if ! PYTHONWARNINGS=ignore tlsa     -4     --only-rr     --create "$DOM_NAME"     --usage 3     --selector 1     --mtype 1     --insecure     --port "$DOM_PORT"     --quiet     --output rfc     > "${WORKDIR}/record.raw" 2>"$ERR_FILE"; then
      echo "ERROR: tlsa command failed for ${DOM_NAME}:${DOM_PORT}" >&2
      cat "$ERR_FILE" >&2 || true
      exit 1
  fi

  sed     -e '/^Got/d'     -e '/^Warning:/d'     -e '/^[[:space:]]*$/d'     "${WORKDIR}/record.raw" >> "$TMP_FILE"

  if ! tail -n 1 "$TMP_FILE" | grep -Eq 'TLSA|TYPE52'; then
    echo "ERROR: generated TLSA record looks invalid for ${DOM_NAME}:${DOM_PORT}" >&2
    cat "${WORKDIR}/record.raw" >&2
    cat "$ERR_FILE" >&2 || true
    exit 1
  fi
done

echo
echo "Installing TLSA include files"

mapfile -t ZONES < <(sort -u "$DOMAIN_LIST")

for DOMAIN in "${ZONES[@]}"; do
  [ -n "$DOMAIN" ] || continue

  DOMAIN_DIR="${DNS_ROOT}/${DOMAIN}"
  DOMAIN_ZONE="${DOMAIN_DIR}/${DOMAIN}"
  DEST_FILE="${DOMAIN_DIR}/TLSA${DOMAIN}.key"
  TMP_FILE="${WORKDIR}/TLSA${DOMAIN}.key"
  TMP_SORTED="${WORKDIR}/TLSA${DOMAIN}.key.sorted"

  sort -u "$TMP_FILE" > "$TMP_SORTED"

  [ -s "$TMP_SORTED" ] || { echo "ERROR: generated TLSA file is empty for ${DOMAIN}" >&2; exit 1; }

  echo
  echo "Zone: ${DOMAIN}"
  echo "Destination: ${DEST_FILE}"
  echo "Records: $(wc -l < "$TMP_SORTED" | tr -d ' ')"

  if [ -s "$DEST_FILE" ]; then
    cp -a "$DEST_FILE" "${DEST_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
  fi

  install -o root -g "$BIND_GROUP" -m 0644 "$TMP_SORTED" "$DEST_FILE"

  echo "Validating zone after TLSA update: ${DOMAIN}"
  ( cd "$DOMAIN_DIR" && named-checkzone "$DOMAIN" "$DOMAIN" )
done

echo
echo "TLSA generation completed. Updating DNSSEC signatures."
"$RRSIG_SCRIPT" "${ZONES[@]}"

echo
echo "TLSA update completed successfully"
echo "===== $(date -Is) finished TLSA update ====="
