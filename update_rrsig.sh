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
ned_cmd rndc
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
  ( cd "$DOM_PATH""bbæÖVBÖ6V6·¦öæR"DDôÕôäÔR""DDôÕôäÔR" ¢V6ò%WFFær4ô6W&Â ¢"E4U$Åõ45$B""DDôÕôdÄR  ¢V6ò%fÆFFærVç6væVB¦öæRgFW"6W&ÂWFFR ¢6B"DDôÕõD"bbæÖVBÖ6V6·¦öæR"DDôÕôäÔR""DDôÕôäÔR" ¢V6ò%6væær¦öæRG´DôÕôäÔWÒ ¢¢6B"DDôÕõD ¢Fç76V2×6vç¦öæRÔÓ2"E4ÅB"ÖR"²GµdÄEõ4T4ôäE7Ò"Öò"DDôÕôäÔR"Öb"EDÕõ4täTB"×B"DDôÕôäÔR ¢ ¢²×2"EDÕõ4täTB"ÒÇÂ²V6ò$U%$õ#¢6væVB¦öæRv2æ÷B7&VFVC¢EDÕõ4täTB"âc#²WB²Ð ¢V6ò%fÆFFær6væVB¦öæR ¢æÖVBÖ6V6·¦öæR"DDôÕôäÔR""EDÕõ4täTB  ¢b²×2"E4täTEôdÄR"Ó²FVà¢7Ö"E4täTEôdÄR""Gµ4täTEôdÄWÒæ&²âBFFR²UVÒVEòTTÒU2 ¢f ¢V6ò$ç7FÆÆær6væVB¦öæS¢E4täTEôdÄR ¢ç7FÆÂÖò&ö÷BÖr"D$äEôu$õU"ÖÒcCB"EDÕõ4täTB""E4täTEôdÄR ¦FöæP ¦V6ð¦V6ò%fÆFFær6ö×ÆWFR$äB6öæfr ¦æÖVBÖ6V6¶6öæb"D$äEô4ôäb  ¦V6ò%&VÆöFær$äB §&æF2&VÆö@ ¦V6ò$Då54T2%%4rWFFR6ö×ÆWFVB7V66W76gVÆÇ ¦V6ò#ÓÓÓÓÒBFFRÔ2fæ6VBDå54T2%%4rWFFRÓÓÓÓÒ 