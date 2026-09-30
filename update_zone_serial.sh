#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <zone-file> [zone-file ...]" >&2
  exit 1
fi

for ZONE_FILE in "$@"; do
  if [ ! -f "$ZONE_FILE" ]; then
    echo "ERROR: zone file not found: $ZONE_FILE" >&2
    exit 1
  fi

  OLD_SERIAL="$(
    awk '
      BEGIN { in_soa = 0 }

      /[[:space:]]SOA[[:space:]]/ {
        in_soa = 1
      }

      in_soa {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9]+$/ && length($i) >= 10) {
            print $i
            exit
          }
        }
      }
    ' "$ZONE_FILE"
  )"

  if [ -z "${OLD_SERIAL:-}" ]; then
    echo "ERROR: could not find SOA serial in $ZONE_FILE" >&2
    exit 1
  fi

  NEXT_SERIAL="$((OLD_SERIAL + 1))"
  TODAY_SERIAL="$(date +%Y%m%d)01"

  if [ "$NEXT_SERIAL" -lt "$TODAY_SERIAL" ]; then
    NEW_SERIAL="$TODAY_SERIAL"
  else
    NEW_SERIAL="$NEXT_SERIAL"
  fi

  echo "Updating SOA serial in $ZONE_FILE: $OLD_SERIAL > $NEW_SERIAL"

  perl -0pi -e "s/\Q${OLD_SERIAL}\E/${NEW_SERIAL}/" "$ZONE_FILE"
done
