#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

LOCK="${LOCK:-/run/lock/dns-block-list.lock}"
LOG="${LOG:-/var/log/dns_block_list.log}"

CONF="${CONF:-/etc/bind/named.conf.blocked}"
ZONE_FILE="${ZONE_FILE:-/etc/bind/blocked.zone}"
ALLOWLIST="${ALLOWLIST:-/etc/bind/dns-block-allowlist.txt}"
DENYLIST="${DENYLIST:-/etc/bind/dns-block-denylist.txt}"

SERVICE="${SERVICE:-named}"
BIND_CONF="${BIND_CONF:-/etc/bind/named.conf}"
BIND_GROUP="${BIND_GROUP:-bind}"
MIN_TOTAL="${MIN_TOTAL:-100}"
BACKUP_RETENTION="${BACKUP_RETENTION:-10}"

exec >>"$LOG" 2>&1

echo
echo "===== $(date -Is) starting DNS block list update ====="

exec 200>"$LOCK"
flock -n 200 || {
    echo "Another instance is already running. Exiting."
    exit 0
}

WORKDIR="$(mktemp -d)"
TMP_DOMAINS="${WORKDIR}/domains.all"
TMP_FILTERED="${WORKDIR}/domains.filtered"
TMP_CONF="${WORKDIR}/named.conf.blocked"
OLD_DOMAINS="${WORKDIR}/domains.old"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [[ ! -s "$ZONE_FILE" ]]; then
    echo "ERROR: blocked zone file missing or empty: $ZONE_FILE" >&2
    exit 1
fi

echo "Validating shared blocked zone file"

if ! named-checkzone blocked.invalid "$ZONE_FILE"; then
    echo "ERROR: invalid blocked zone file: $ZONE_FILE" >&2
    exit 1
fi

declare -a SOURCES=(
    "someonewhocares|https://someonewhocares.org/hosts/zero/hosts"
    "adaway|https://adaway.org/hosts.txt"
    "pgl-yoyo|https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
    "urlhaus|https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"
)

normalize_hosts_file() {
    local input_file="$1"
    local output_file="$2"

    awk '
        BEGIN {
            IGNORECASE = 1
        }

        /^[[:space:]]*($|#)/ {
            next
        }

        {
            ip = tolower($1)
            host = tolower($2)

            if (ip != "0.0.0.0" && ip != "127.0.0.1") {
                next
            }

            sub(/\.$/, "", host)

            if (host == "" ||
                host == "localhost" ||
                host == "localhost.localdomain") {
                next
            }

            if (host ~ /[*_]/) {
                next
            }

            if (host !~ /^[a-z0-9.-]+$/) {
                next
            }

            if (host !~ /\./) {
                next
            }

            if (host ~ /^\./ ||
                host ~ /\.$/ ||
                host ~ /\.\./) {
                next
            }

            if (!seen[host]++) {
                print host
            }
        }
    ' "$input_file" | sort -u > "$output_file"
}

download_source() {
    local label="$1"
    local url="$2"
    local raw_file="${WORKDIR}/${label}.raw"
    local domain_file="${WORKDIR}/${label}.domains"

    echo "Downloading ${label}: ${url}"

    if ! wget \
        --quiet \
        --timeout=30 \
        --tries=3 \
        --https-only \
        --output-document="$raw_file" \
        "$url"; then
        echo "WARN: download failed for ${label}" >&2
        return 1
    fi

    if [[ ! -s "$raw_file" ]]; then
        echo "WARN: empty response from ${label}" >&2
        return 1
    fi

    normalize_hosts_file "$raw_file" "$domain_file"

    local count
    count="$(wc -l < "$domain_file" | tr -d ' ')"

    if (( count < 1 )); then
        echo "WARN: source ${label} produced no valid domains" >&2
        return 1
    fi

    echo "Source ${label}: ${count} valid domains"
    cat "$domain_file" >> "$TMP_DOMAINS"
}

: > "$TMP_DOMAINS"

SUCCESSFUL_SOURCES=0

for source in "${SOURCES[@]}"; do
    IFS='|' read -r label url <<< "$source"

    if download_source "$label" "$url"; then
        ((SUCCESSFUL_SOURCES += 1))
    fi
done

if (( SUCCESSFUL_SOURCES == 0 )); then
    echo "ERROR: all downloads failed or produced invalid data." >&2
    echo "Keeping the existing BIND configuration." >&2
    exit 1
fi

# Optional manual denylist: one domain per line.
if [[ -s "$DENYLIST" ]]; then
    echo "Adding manual denylist entries"

    awk '
        BEGIN {
            IGNORECASE = 1
        }

        /^[[:space:]]*($|#)/ {
            next
        }

        {
            host = tolower($1)
            sub(/\.$/, "", host)

            if (host ~ /^[a-z0-9.-]+\.[a-z0-9-]+$/ &&
                host !~ /^\./ &&
                host !~ /\.$/ &&
                host !~ /\.\./) {
                print host
            }
        }
    ' "$DENYLIST" >> "$TMP_DOMAINS"
fi

sort -u "$TMP_DOMAINS" -o "$TMP_DOMAINS"

# Allowlist supports domains and all their subdomains.
if [[ -s "$ALLOWLIST" ]]; then
    echo "Applying allowlist: $ALLOWLIST"

    awk '
        function is_allowed(host, i, suffix) {
            for (i = 1; i <= allow_count; i++) {
                if (host == allowed[i]) {
                    return 1
                }

                suffix = "." allowed[i]

                if (length(host) > length(suffix) &&
                    substr(host, length(host) - length(suffix) + 1) == suffix) {
                    return 1
                }
            }

            return 0
        }

        NR == FNR {
            line = tolower($1)

            if (line == "" || line ~ /^#/) {
                next
            }

            sub(/\.$/, "", line)

            if (line ~ /^[a-z0-9.-]+$/ &&
                line ~ /\./ &&
                line !~ /^\./ &&
                line !~ /\.$/ &&
                line !~ /\.\./) {
                allowed[++allow_count] = line
            }

            next
        }

        !is_allowed($0) {
            print
        }
    ' "$ALLOWLIST" "$TMP_DOMAINS" > "$TMP_FILTERED"
else
    cp "$TMP_DOMAINS" "$TMP_FILTERED"
fi

sort -u "$TMP_FILTERED" -o "$TMP_FILTERED"

COUNT="$(wc -l < "$TMP_FILTERED" | tr -d ' ')"

echo "Generated ${COUNT} unique blocked domains"

if (( COUNT < MIN_TOTAL )); then
    echo "ERROR: generated list is suspiciously small." >&2
    echo "Keeping the existing configuration." >&2
    exit 1
fi

awk -v zone_file="$ZONE_FILE" '
    {
        printf "zone \"%s\" { type master; notify no; file \"%s\"; };\n", $0, zone_file
    }
' "$TMP_FILTERED" > "$TMP_CONF"

# Extract the currently configured domains for comparison.
if [[ -s "$CONF" ]]; then
    sed -n 's/^zone "\([^"]*\)".*/\1/p' "$CONF" |
        sort -u > "$OLD_DOMAINS"
else
    : > "$OLD_DOMAINS"
fi

if cmp -s "$CONF" "$TMP_CONF" 2>/dev/null; then
    echo "No block-list changes detected. Reload not required."
    echo "===== $(date -Is) finished without changes ====="
    exit 0
fi

ADDED="$(
    comm -13 "$OLD_DOMAINS" "$TMP_FILTERED" |
        wc -l |
        tr -d ' '
)"

REMOVED="$(
    comm -23 "$OLD_DOMAINS" "$TMP_FILTERED" |
        wc -l |
        tr -d ' '
)"

echo "Changes: ${ADDED} added, ${REMOVED} removed"

BACKUP="${CONF}.bak.$(date +%Y%m%d_%H%M%S)"

if [[ -e "$CONF" ]]; then
    echo "Backing up current configuration to ${BACKUP}"
    cp -a "$CONF" "$BACKUP"
fi

echo "Installing candidate configuration"

install \
    -o root \
    -g "$BIND_GROUP" \
    -m 0644 \
    "$TMP_CONF" \
    "${CONF}.new"

mv -f "${CONF}.new" "$CONF"

echo "Validating BIND configuration"

if ! named-checkconf "$BIND_CONF"; then
    echo "ERROR: named-checkconf failed." >&2

    if [[ -e "$BACKUP" ]]; then
        echo "Restoring previous configuration"
        cp -a "$BACKUP" "$CONF"
    fi

    exit 1
fi

echo "Reloading BIND"

RELOAD_OK=0

if command -v rndc >/dev/null 2>&1 && rndc reload; then
    echo "Reloaded BIND using rndc"
    RELOAD_OK=1
elif systemctl reload "$SERVICE"; then
    echo "Reloaded ${SERVICE} using systemctl"
    RELOAD_OK=1
fi

if (( RELOAD_OK == 0 )); then
    echo "ERROR: BIND reload failed. Rolling back." >&2

    if [[ -e "$BACKUP" ]]; then
        cp -a "$BACKUP" "$CONF"

        rndc reload 2>/dev/null ||
            systemctl reload "$SERVICE" 2>/dev/null ||
            true
    fi

    exit 1
fi

if ! systemctl is-active --quiet "$SERVICE"; then
    echo "ERROR: ${SERVICE} is not active after reload. Rolling back." >&2

    if [[ -e "$BACKUP" ]]; then
        cp -a "$BACKUP" "$CONF"
        systemctl restart "$SERVICE" || true
    fi

    exit 1
fi

# Keep only the newest configured number of backups.
mapfile -t OLD_BACKUPS < <(
    find "$(dirname "$CONF")" \
        -maxdepth 1 \
        -type f \
        -name "$(basename "$CONF").bak.*" \
        -printf '%T@ %p\n' |
        sort -rn |
        tail -n "+$((BACKUP_RETENTION + 1))" |
        cut -d' ' -f2-
)

if (( ${#OLD_BACKUPS[@]} > 0 )); then
    echo "Removing ${#OLD_BACKUPS[@]} old backups"
    rm -f -- "${OLD_BACKUPS[@]}"
fi

echo "DNS block-list update completed successfully"
echo "Successful sources: ${SUCCESSFUL_SOURCES}/${#SOURCES[@]}"
echo "Active blocked domains: ${COUNT}"
echo "Added: ${ADDED}"
echo "Removed: ${REMOVED}"
echo "===== $(date -Is) finished ====="
