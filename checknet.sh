#!/data/data/com.termux/files/usr/bin/env bash
# checknet — Zero-Trust network status display
#
# Visual status panel for the full DNS + anonymizing proxy enclave.
# Integrates with: doh-pin-proxy, cloudflared, anon-proxy, nextdns-zero-trust-locked.sh
#
# Install to PATH:
#   cp checknet $PREFIX/bin/checknet && chmod 755 $PREFIX/bin/checknet
#
# Usage:
#   checknet           — full status panel
#   checknet --watch   — refresh every 5 seconds
#   checknet --json    — machine-readable output (for scripting)

set -euo pipefail
IFS=$'\n\t'

export PATH="/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/sbin:/system/bin"

# ── ANSI colors and box drawing ───────────────────────────────────────────────

R='\033[0;31m'   # red    — critical failure
Y='\033[0;33m'   # yellow — degraded / warning
G='\033[0;32m'   # green  — OK
B='\033[0;34m'   # blue   — informational
W='\033[1;37m'   # bold white — headers
D='\033[2;37m'   # dim white — secondary info
NC='\033[0m'     # reset
BOLD='\033[1m'
DIM='\033[2m'

# ── State paths (must match nextdns-zero-trust-locked.sh) ─────────────────────

readonly CONFIG_DIR="$HOME/.cloudflared"
readonly PIN_FILE="$CONFIG_DIR/ephemeral_pin/nextdns_cf_pin.txt"
readonly PERSIST_STATE="$CONFIG_DIR/nzt-locked-state"
readonly LOCKED_FLAG="$CONFIG_DIR/nzt-locked"
readonly CONFIG_FILE="$CONFIG_DIR/config.yml"
readonly RESOLV="$PREFIX/etc/resolv.conf"
readonly TOFU_HASH_FILE="$CONFIG_DIR/cloudflared.tofu_sha256"
readonly AUDIT_LOG="$CONFIG_DIR/audit.log"

readonly DOH_PROXY_URL="http://127.0.0.1:8888"
readonly ANON_PROXY_URL="http://127.0.0.1:8890"
readonly CA_BUNDLE="$PREFIX/etc/tls/cert.pem"

# Width of the status panel
readonly WIDTH=66

# ── Score tracking ────────────────────────────────────────────────────────────

SCORE_GREEN=0
SCORE_YELLOW=0
SCORE_RED=0
CRITICAL_FAIL=0   # DNS or proxy completely down — auto-F
WEAKEST_LINK=""

# ── Helpers ───────────────────────────────────────────────────────────────────

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

_pad() {
    # _pad "text" width → right-pad with spaces to width
    local text="$1" width="$2"
    local visible
    # Strip ANSI for length calculation
    visible=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#visible}
    local pad=$(( width - len ))
    printf '%b' "$text"
    printf '%*s' "$pad" ''
}

_hline() {
    local char="${1:-═}"
    printf '║ '
    printf '%0.s'"$char" $(seq 1 $((WIDTH - 4)))
    printf ' ║\n'
}

_row() {
    # _row "label" "value" COLOR
    local label="$1" value="$2" color="${3:-$NC}"
    printf "║ ${W}%-22s${NC} ${color}%-$((WIDTH - 27))s${NC} ║\n" "$label" "$value"
}

_section() {
    local title="$1"
    printf "╠%s╣\n" "$(printf '%0.s═' $(seq 1 $((WIDTH - 2))))"
    printf "║ ${BOLD}${B}%-$((WIDTH - 4))s${NC} ║\n" "$title"
    printf "╠%s╣\n" "$(printf '%0.s─' $(seq 1 $((WIDTH - 2))))"
}

check() {
    # check LABEL VALUE STATUS [NOTE]
    # STATUS: ok | warn | fail | info
    local label="$1" value="$2" status="$3" note="${4:-}"
    local icon color
    case "$status" in
        ok)   icon="✓"; color=$G; SCORE_GREEN=$((SCORE_GREEN+1)) ;;
        warn) icon="⚠"; color=$Y; SCORE_YELLOW=$((SCORE_YELLOW+1))
              if [[ -z "$WEAKEST_LINK" ]]; then WEAKEST_LINK="$label: $value"; fi ;;
        fail) icon="✗"; color=$R; SCORE_RED=$((SCORE_RED+1))
              WEAKEST_LINK="$label: $value" ;;
        info) icon="·"; color=$D ;;
    esac
    if [[ -n "$note" ]]; then
        printf "║ ${color}${icon}${NC} ${W}%-20s${NC} ${color}%-$((WIDTH - 28))s${NC} ${D}%-3s${NC}║\n" \
            "$label" "$value" "$note"
    else
        printf "║ ${color}${icon}${NC} ${W}%-20s${NC} ${color}%-$((WIDTH - 25))s${NC} ║\n" \
            "$label" "$value"
    fi
}

is_hex64() { [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]; }

# ── Component checks ──────────────────────────────────────────────────────────

check_enclave_lock() {
    if [[ -f "$LOCKED_FLAG" ]]; then
        local locked_at
        locked_at=$(grep '^locked_at=' "$PERSIST_STATE" 2>/dev/null | cut -d= -f2 || echo "unknown")
        check "Enclave lock" "LOCKED since $locked_at" ok
    else
        check "Enclave lock" "NOT LOCKED — enclave not provisioned" fail
        CRITICAL_FAIL=1
    fi
}

check_doh_proxy() {
    local pid
    pid=$(pgrep -f "doh-pin-proxy" 2>/dev/null | head -1 || true)
    if [[ -n "$pid" ]]; then
        local health
        health=$(curl -sf --max-time 2 "$DOH_PROXY_URL/health" 2>/dev/null || true)
        if [[ "$health" == ok* ]]; then
            check "DoH pin proxy" "RUNNING  pid=$pid" ok
        else
            check "DoH pin proxy" "RUNNING pid=$pid (health fail)" warn
        fi
    else
        check "DoH pin proxy" "NOT RUNNING" fail
        CRITICAL_FAIL=1
    fi
}

check_cloudflared() {
    local pid
    pid=$(pgrep -f "cloudflared.*proxy-dns" 2>/dev/null | head -1 || true)
    if [[ -n "$pid" ]]; then
        check "cloudflared" "RUNNING  pid=$pid" ok
    else
        check "cloudflared" "NOT RUNNING" fail
        CRITICAL_FAIL=1
    fi
}

check_anon_proxy() {
    local pid
    pid=$(pgrep -f "anon-proxy" 2>/dev/null | head -1 || true)
    if [[ -n "$pid" ]]; then
        local health
        health=$(curl -sf --max-time 2 "$ANON_PROXY_URL/health" 2>/dev/null || true)
        if [[ "$health" == ok* ]]; then
            # Parse jitter range from health response
            local jitter
            jitter=$(echo "$health" | grep -o 'jitter=[^ ]*' || echo "jitter=?")
            check "Anon proxy" "RUNNING  pid=$pid  ($jitter)" ok
        else
            check "Anon proxy" "RUNNING pid=$pid (health fail)" warn
        fi
    else
        check "Anon proxy" "NOT RUNNING — run anon-proxy" fail
    fi
}

check_resolv() {
    if [[ ! -f "$RESOLV" ]]; then
        check "resolv.conf" "MISSING" fail
        CRITICAL_FAIL=1
        return
    fi
    local ns
    ns=$(grep '^nameserver' "$RESOLV" | awk '{print $2}' | head -1 || true)
    if [[ "$ns" == "127.0.0.1" ]]; then
        check "DNS resolver" "127.0.0.1 (loopback isolated)" ok
    else
        check "DNS resolver" "EXPOSED: pointing to $ns" fail
        CRITICAL_FAIL=1
    fi
}

check_tls_pin() {
    if [[ ! -f "$PIN_FILE" ]]; then
        check "TLS SPKI pin" "PIN FILE MISSING" fail
        CRITICAL_FAIL=1
        return
    fi

    local pin age_s age_label
    pin=$(cat "$PIN_FILE" 2>/dev/null || true)

    if ! is_hex64 "$pin"; then
        check "TLS SPKI pin" "MALFORMED (not 64-char hex)" fail
        return
    fi

    # Check pin file age
    if command -v stat >/dev/null 2>&1; then
        local mtime now
        mtime=$(stat -c %Y "$PIN_FILE" 2>/dev/null || echo 0)
        now=$(date +%s)
        age_s=$(( now - mtime ))
        local age_h=$(( age_s / 3600 ))
        local age_d=$(( age_s / 86400 ))

        if (( age_d >= 80 )); then
            # Let's Encrypt certs expire at 90 days — warn at 80
            age_label="${age_d}d (ROTATE SOON)"
            check "TLS SPKI pin" "${pin:0:16}… age=${age_label}" warn
        elif (( age_d >= 1 )); then
            age_label="${age_d}d ${age_h}h"
            check "TLS SPKI pin" "${pin:0:16}… age=${age_label}" ok
        else
            age_label="${age_h}h"
            check "TLS SPKI pin" "${pin:0:16}… age=${age_label}" ok
        fi
    else
        check "TLS SPKI pin" "${pin:0:16}… (age unknown)" ok
    fi
}

check_live_pin_match() {
    # Fetch live cert and compare SPKI to stored pin — detects silent cert rotation
    if [[ ! -f "$PIN_FILE" ]]; then return; fi

    local stored_pin live_pin cert_tmp
    stored_pin=$(cat "$PIN_FILE" 2>/dev/null || true)
    if ! is_hex64 "$stored_pin"; then return; fi

    cert_tmp=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$cert_tmp'" RETURN

    openssl s_client \
        -servername dns.nextdns.io \
        -connect dns.nextdns.io:443 \
        -CAfile "$CA_BUNDLE" \
        -verify_return_error \
        2>/dev/null < /dev/null \
        | openssl x509 -out "$cert_tmp" 2>/dev/null || true

    if [[ ! -s "$cert_tmp" ]]; then
        check "Live pin verify" "CANNOT FETCH (offline?)" warn
        return
    fi

    live_pin=$(
        openssl x509 -in "$cert_tmp" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -pubout -outform DER 2>/dev/null \
        | openssl dgst -sha256 2>/dev/null \
        | awk '{print $2}'
    )

    if ! is_hex64 "$live_pin"; then
        check "Live pin verify" "PARSE ERROR" warn
        return
    fi

    if [[ "$live_pin" == "$stored_pin" ]]; then
        check "Live pin verify" "MATCH — cert unchanged" ok
    else
        check "Live pin verify" "MISMATCH — cert rotated! Re-provision" fail
        CRITICAL_FAIL=1
    fi
}

check_doh_resolution() {
    # Test DoH via the local proxy — RFC 8484 GET with Accept header
    local result
    result=$(curl -sf --max-time 5 \
        -H "Accept: application/dns-message" \
        "${DOH_PROXY_URL}/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
        --output /dev/null \
        -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ "$result" == "200" ]]; then
        check "DoH query" "HTTP 200 OK (example.com A)" ok
    elif [[ "$result" == "000" ]]; then
        check "DoH query" "NO RESPONSE from proxy" fail
        CRITICAL_FAIL=1
    else
        check "DoH query" "HTTP $result (unexpected)" warn
    fi
}

check_dns_resolution() {
    # Test DNS via 127.0.0.1 using available tool
    local target="cloudflare.com"
    local result=""

    if command -v nslookup >/dev/null 2>&1; then
        result=$(nslookup "$target" 127.0.0.1 2>/dev/null | grep -c 'Address' || echo "0")
        if (( result > 1 )); then
            check "DNS resolution" "${target} → OK via 127.0.0.1" ok
        else
            check "DNS resolution" "${target} FAILED via 127.0.0.1" fail
            CRITICAL_FAIL=1
        fi
    elif command -v dnslookup >/dev/null 2>&1; then
        if dnslookup "$target" 127.0.0.1 >/dev/null 2>&1; then
            check "DNS resolution" "${target} → OK via 127.0.0.1" ok
        else
            check "DNS resolution" "${target} FAILED via 127.0.0.1" fail
            CRITICAL_FAIL=1
        fi
    else
        check "DNS resolution" "No test tool (install dnsutils)" warn
    fi
}

check_proxy_env() {
    local http_set=0 https_set=0
    [[ "${http_proxy:-}${HTTP_PROXY:-}" == *"127.0.0.1:8890"* ]] && http_set=1
    [[ "${https_proxy:-}${HTTPS_PROXY:-}" == *"127.0.0.1:8890"* ]] && https_set=1

    if (( http_set && https_set )); then
        check "Proxy env vars" "http_proxy + https_proxy → 8890" ok
    elif (( http_set || https_set )); then
        check "Proxy env vars" "PARTIAL — only one of http/https set" warn
    else
        check "Proxy env vars" "NOT SET in this shell" warn
        # Not critical — proxy may be set in other ways
    fi
}

check_egress_ip() {
    local ip
    # Try to get external IP via anon-proxy if running, otherwise direct
    local pid
    pid=$(pgrep -f "anon-proxy" 2>/dev/null | head -1 || true)

    if [[ -n "$pid" ]]; then
        ip=$(curl -sf --max-time 8 \
            --proxy "$ANON_PROXY_URL" \
            "https://api.ipify.org" 2>/dev/null || echo "")
        if [[ -n "$ip" ]]; then
            check "Egress IP (proxy)" "$ip" ok
        else
            check "Egress IP (proxy)" "TIMEOUT — upstream unreachable?" warn
        fi
    else
        ip=$(curl -sf --max-time 8 "https://api.ipify.org" 2>/dev/null || echo "")
        if [[ -n "$ip" ]]; then
            check "Egress IP (direct)" "$ip  (proxy not in use)" warn
        else
            check "Egress IP" "TIMEOUT — no connectivity" warn
        fi
    fi
}

check_cloudflared_binary() {
    local cf_bin="$PREFIX/bin/cloudflared"
    if [[ ! -f "$cf_bin" ]]; then
        check "cloudflared binary" "MISSING at $cf_bin" fail
        return
    fi
    if [[ ! -f "$TOFU_HASH_FILE" ]]; then
        check "cloudflared TOFU pin" "NO PIN FILE — run provisioner" warn
        return
    fi
    local stored actual
    stored=$(cat "$TOFU_HASH_FILE" 2>/dev/null || true)
    actual=$(sha256sum "$cf_bin" 2>/dev/null | awk '{print $1}' || true)
    if ! is_hex64 "$stored" || ! is_hex64 "$actual"; then
        check "cloudflared TOFU pin" "MALFORMED hash" warn
        return
    fi
    if [[ "$actual" == "$stored" ]]; then
        check "cloudflared TOFU pin" "${stored:0:16}… MATCH" ok
    else
        check "cloudflared TOFU pin" "MISMATCH — binary tampered?" fail
        CRITICAL_FAIL=1
    fi
}

check_anon_proxy_binary() {
    local bin="$HOME/anon-proxy"
    if [[ -f "$bin" ]]; then
        check "anon-proxy binary" "present at $bin" ok
    else
        check "anon-proxy binary" "MISSING — build from anon-proxy.go" warn
    fi
}

check_config_integrity() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        check "cloudflared config" "MISSING" fail
        return
    fi
    local perms
    perms=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || echo "???")
    if [[ "$perms" == "444" ]]; then
        check "cloudflared config" "read-only (444) ✓" ok
    else
        check "cloudflared config" "permissions $perms (expected 444)" warn
    fi
}

check_tmux_session() {
    if tmux has-session -t "nzt_locked" 2>/dev/null; then
        check "tmux session" "nzt_locked ACTIVE" ok
    else
        check "tmux session" "nzt_locked NOT FOUND — services may be detached" warn
    fi
}

check_last_audit() {
    if [[ ! -f "$AUDIT_LOG" ]]; then
        check "Audit log" "MISSING" warn
        return
    fi
    local last
    last=$(tail -1 "$AUDIT_LOG" 2>/dev/null | cut -c1-60 || echo "(empty)")
    check "Last audit entry" "$last" info
}

# ── Grade calculator ──────────────────────────────────────────────────────────

calculate_grade() {
    local grade color
    if (( CRITICAL_FAIL )); then
        grade="F"
        color=$R
    elif (( SCORE_RED >= 2 )); then
        grade="F"
        color=$R
    elif (( SCORE_RED == 1 )); then
        grade="C"
        color=$R
    elif (( SCORE_YELLOW >= 3 )); then
        grade="B"
        color=$Y
    elif (( SCORE_YELLOW >= 1 )); then
        grade="B+"
        color=$Y
    else
        grade="A"
        color=$G
    fi
    echo "${color}${grade}${NC}"
}

# ── JSON output ───────────────────────────────────────────────────────────────

output_json() {
    local grade
    grade=$(calculate_grade | sed 's/\x1b\[[0-9;]*m//g')
    cat <<EOF
{
  "timestamp": "$(_ts)",
  "grade": "$grade",
  "checks": {
    "green": $SCORE_GREEN,
    "yellow": $SCORE_YELLOW,
    "red": $SCORE_RED,
    "critical_fail": $CRITICAL_FAIL
  },
  "weakest_link": "$(echo "${WEAKEST_LINK}" | sed 's/"/\\"/g')"
}
EOF
}

# ── Main status display ───────────────────────────────────────────────────────

run_checks() {
    # DNS layer
    check_enclave_lock
    check_doh_proxy
    check_cloudflared
    check_cloudflared_binary
    check_resolv
    check_tls_pin
    check_live_pin_match
    check_doh_resolution
    check_dns_resolution

    # Proxy layer
    check_anon_proxy
    check_anon_proxy_binary
    check_proxy_env

    # Config integrity
    check_config_integrity
    check_tmux_session

    # Network
    check_egress_ip

    # Audit
    check_last_audit
}

display_status() {
    clear
    echo
    printf "╔%s╗\n" "$(printf '%0.s═' $(seq 1 $((WIDTH - 2))))"
    printf "║ ${BOLD}${W}%-$((WIDTH - 4))s${NC} ║\n" "  ZERO-TRUST NETWORK STATUS"
    printf "║ ${D}%-$((WIDTH - 4))s${NC} ║\n" "  $(_ts)"
    printf "╠%s╣\n" "$(printf '%0.s═' $(seq 1 $((WIDTH - 2))))"

    # ── Layer 1: DNS enclave ──────────────────────────────────────────────────
    _section "  LAYER 1 — DNS ENCLAVE"

    check_enclave_lock
    check_resolv
    check_tls_pin
    check_live_pin_match
    check_doh_proxy
    check_cloudflared
    check_cloudflared_binary
    check_config_integrity
    check_tmux_session

    # ── Layer 2: DoH query path ───────────────────────────────────────────────
    _section "  LAYER 2 — DOH QUERY PATH"

    check_doh_resolution
    check_dns_resolution

    # ── Layer 3: Anonymizing proxy ────────────────────────────────────────────
    _section "  LAYER 3 — ANONYMIZING PROXY"

    check_anon_proxy
    check_anon_proxy_binary
    check_proxy_env

    # ── Layer 4: Egress ───────────────────────────────────────────────────────
    _section "  LAYER 4 — NETWORK EGRESS"

    check_egress_ip

    # ── Audit ─────────────────────────────────────────────────────────────────
    _section "  AUDIT"

    check_last_audit

    # ── Grade ─────────────────────────────────────────────────────────────────
    printf "╠%s╣\n" "$(printf '%0.s═' $(seq 1 $((WIDTH - 2))))"

    local grade_colored
    grade_colored=$(calculate_grade)

    printf "║ ${BOLD}%-20s${NC} %-$((WIDTH - 25))b ${NC}║\n" \
        "  SECURITY GRADE:" "$grade_colored  (✓=${SCORE_GREEN} ⚠=${SCORE_YELLOW} ✗=${SCORE_RED})"

    if [[ -n "$WEAKEST_LINK" ]]; then
        printf "║ ${R}%-$((WIDTH - 4))s${NC} ║\n" \
            "  ⬆ WEAKEST: ${WEAKEST_LINK:0:$((WIDTH - 16))}"
    fi

    printf "╠%s╣\n" "$(printf '%0.s─' $(seq 1 $((WIDTH - 2))))"
    printf "║ ${D}%-$((WIDTH - 4))s${NC} ║\n" \
        "  Proxy env: export http_proxy=http://127.0.0.1:8890"
    printf "║ ${D}%-$((WIDTH - 4))s${NC} ║\n" \
        "             export https_proxy=http://127.0.0.1:8890"
    printf "║ ${D}%-$((WIDTH - 4))s${NC} ║\n" \
        "  Rotate pin: kill -HUP \$(pgrep doh-pin-proxy)"
    printf "║ ${D}%-$((WIDTH - 4))s${NC} ║\n" \
        "  Logs:       tmux attach -t nzt_locked"
    printf "╚%s╝\n" "$(printf '%0.s═' $(seq 1 $((WIDTH - 2))))"
    echo
}

# ── Entry point ───────────────────────────────────────────────────────────────

case "${1:-}" in
    --watch)
        while true; do
            # Reset counters each cycle
            SCORE_GREEN=0; SCORE_YELLOW=0; SCORE_RED=0; CRITICAL_FAIL=0; WEAKEST_LINK=""
            display_status
            sleep 5
        done
        ;;
    --json)
        run_checks >/dev/null 2>&1 || true
        output_json
        ;;
    --help|-h)
        echo "Usage: checknet [--watch | --json | --help]"
        echo "  (no args)  — one-shot status panel"
        echo "  --watch    — refresh every 5 seconds"
        echo "  --json     — machine-readable output"
        ;;
    *)
        display_status
        ;;
esac
