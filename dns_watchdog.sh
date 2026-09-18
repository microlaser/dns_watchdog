#!/usr/bin/env bash
#
# dns_watchdog.sh — Cross-platform (macOS + Linux) DNS poisoning / spoofing monitor
#
# Watches ALL DNS traffic (UDP + TCP port 53) crossing the network interface(s)
# of the machine it runs on. Because a typical host has one interface carrying
# both local-network (LAN) and internet-bound (WAN) traffic, this naturally
# covers both without needing separate capture paths.
#
# Detects, in real time:
#   1. Conflicting answers to the same DNS query (classic poisoning "race" pattern)
#   2. DNS responses arriving from a server your machine never configured/asked
#   3. DNS responses with no matching outstanding query
#   4. Changes to your default gateway's MAC address (ARP spoofing precursor
#      to on-LAN DNS poisoning)
#
# Every alert is printed with a [TECHNICAL] line (raw packet detail) and a
# [WHAT THIS MEANS] line (plain-language explanation).
#
# Usage:
#   sudo ./dns_watchdog.sh [-i interface] [-o logfile]
#
# Requires: tcpdump, awk, root/sudo privileges (raw packet capture).

set -u

OS="$(uname -s)"
IFACE=""
LOGFILE=""
GATEWAY_MAC_CHECK_INTERVAL=5

usage() {
    cat <<'USAGE'
dns_watchdog.sh — monitor this machine's traffic for signs of DNS poisoning

Usage:
  sudo ./dns_watchdog.sh [-i INTERFACE] [-o LOGFILE]
  sudo ./dns_watchdog.sh -h

Options:
  -i INTERFACE   Network interface to capture on (default: auto-detected
                  default-route interface, which carries both LAN and WAN
                  traffic on most single-NIC machines)
  -o LOGFILE     Path to write the session log (default: ./dns_watchdog_<timestamp>.log)
  -h             Show this help and exit

Press Ctrl+C to stop monitoring; a session summary is printed on exit.
USAGE
}

while getopts "i:o:h" opt; do
    case "$opt" in
        i) IFACE="$OPTARG" ;;
        o) LOGFILE="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this script needs root privileges to capture raw packets."
    echo "Re-run as:  sudo $0 $*"
    exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "ERROR: tcpdump not found."
    case "$OS" in
        Linux) echo "  Install it with: sudo apt install tcpdump   (or your distro's equivalent)" ;;
        Darwin) echo "  tcpdump ships with macOS by default; check your PATH." ;;
    esac
    exit 1
fi

if ! command -v awk >/dev/null 2>&1; then
    echo "ERROR: awk not found. This script requires awk (present on macOS and Linux by default)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Interface / gateway / DNS server discovery
# ---------------------------------------------------------------------------

detect_interface() {
    case "$OS" in
        Darwin) route -n get default 2>/dev/null | awk '/interface: / {print $2}' ;;
        Linux)  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' ;;
    esac
}

detect_gateway() {
    case "$OS" in
        Darwin) route -n get default 2>/dev/null | awk '/gateway: / {print $2}' ;;
        Linux)  ip route show default 2>/dev/null | awk '/default/ {print $3; exit}' ;;
    esac
}

get_gw_mac() {
    gw="$1"
    case "$OS" in
        Darwin) arp -n "$gw" 2>/dev/null | awk '{print $4}' ;;
        Linux)
            if command -v ip >/dev/null 2>&1; then
                ip neigh show "$gw" 2>/dev/null | awk '{print $5}'
            else
                arp -n "$gw" 2>/dev/null | awk 'NR==2{print $3}'
            fi
            ;;
    esac
}

get_dns_servers() {
    servers=""
    if [ -r /etc/resolv.conf ]; then
        servers="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ',' | sed 's/,$//')"
    fi
    if [ -z "$servers" ] && [ "$OS" = "Darwin" ] && command -v scutil >/dev/null 2>&1; then
        servers="$(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/ {print $3}' | sort -u | tr '\n' ',' | sed 's/,$//')"
    fi
    echo "$servers"
}

if [ -z "$IFACE" ]; then
    IFACE="$(detect_interface)"
fi
if [ -z "$IFACE" ]; then
    echo "ERROR: could not auto-detect a network interface. Specify one with -i."
    exit 1
fi

GATEWAY="$(detect_gateway)"
ping -c1 -W1 "$GATEWAY" >/dev/null 2>&1
GATEWAY_MAC="$(get_gw_mac "$GATEWAY" 2>/dev/null)"
DNS_SERVERS="$(get_dns_servers)"

if [ -z "$LOGFILE" ]; then
    LOGFILE="./dns_watchdog_$(date +%Y%m%d_%H%M%S).log"
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

cat <<BANNER | tee -a "$LOGFILE"
=========================================================================
 DNS Watchdog — DNS poisoning / spoofing monitor
=========================================================================
Interface:        ${IFACE}  (carries this host's LAN + WAN traffic)
Default gateway:  ${GATEWAY:-unknown}  (MAC baseline: ${GATEWAY_MAC:-unknown})
Configured DNS:    ${DNS_SERVERS:-none detected}
Log file:          ${LOGFILE}

What this does, in plain terms:
  Every time this machine looks up a website's address, it sends a DNS
  question and gets a DNS answer back. This tool watches that traffic and
  flags patterns that don't happen during normal, honest DNS activity —
  such as getting two different answers to the same question, or an
  answer from a server you never asked. It also watches whether the
  hardware (MAC) address of your router suddenly changes, which is how
  attackers commonly position themselves to tamper with DNS on a LAN.

Each alert below has two parts:
  [TECHNICAL]       — the raw packet detail, for someone investigating
  [WHAT THIS MEANS] — a plain-language explanation of why it matters

Press Ctrl+C to stop. A summary prints when you do.
=========================================================================
BANNER

# ---------------------------------------------------------------------------
# Background: watch the gateway's MAC address for ARP-spoofing precursors
# ---------------------------------------------------------------------------

arp_watch() {
    gw="$1"
    baseline="$2"
    while true; do
        sleep "$GATEWAY_MAC_CHECK_INTERVAL"
        ping -c1 -W1 "$gw" >/dev/null 2>&1
        current="$(get_gw_mac "$gw" 2>/dev/null)"
        if [ -n "$current" ] && [ -n "$baseline" ] && [ "$current" != "$baseline" ]; then
            ts="$(date '+%H:%M:%S')"
            {
                printf "\n[%s] [ALERT] Default gateway MAC address changed\n" "$ts"
                printf "  [TECHNICAL] gateway=%s  baseline_mac=%s  new_mac=%s\n" "$gw" "$baseline" "$current"
                printf "  [WHAT THIS MEANS] The hardware address answering for your router just changed. On most home or office networks this almost never happens by itself. It is the classic sign of ARP spoofing — attackers use it on a local network to insert themselves between you and your router, which is often the first step before rewriting DNS answers. If you did not just switch networks or replace your router, investigate immediately.\n"
            } | tee -a "$LOGFILE"
            baseline="$current"
        fi
    done
}

if [ -n "$GATEWAY" ] && [ -n "$GATEWAY_MAC" ]; then
    arp_watch "$GATEWAY" "$GATEWAY_MAC" &
    ARP_WATCH_PID=$!
else
    echo "NOTE: could not establish a gateway/MAC baseline; ARP-spoofing checks are disabled for this session." | tee -a "$LOGFILE"
    ARP_WATCH_PID=""
fi

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------

AWK_SCRIPT="$(mktemp)"

cleanup() {
    echo "" | tee -a "$LOGFILE"
    echo "Stopping DNS Watchdog..." | tee -a "$LOGFILE"
    [ -n "$ARP_WATCH_PID" ] && kill "$ARP_WATCH_PID" >/dev/null 2>&1
    rm -f "$AWK_SCRIPT"
    exit 0
}
trap cleanup INT TERM

# ---------------------------------------------------------------------------
# DNS packet analysis (POSIX awk only — no gawk-specific features, so this
# runs unmodified on macOS's default awk and Linux's gawk/mawk alike)
# ---------------------------------------------------------------------------

cat > "$AWK_SCRIPT" <<'AWKEOF'
BEGIN {
    n = split(dns_servers, dsarr, ",")
    for (i = 1; i <= n; i++) {
        gsub(/^[ \t]+|[ \t]+$/, "", dsarr[i])
        if (dsarr[i] != "") expected[dsarr[i]] = 1
    }
    queries = 0
    responses = 0
    alerts = 0
    if (grace == "") grace = 10
}

function stripport(full,    parts, np, port) {
    np = split(full, parts, ".")
    port = parts[np]
    return substr(full, 1, length(full) - length(port) - 1)
}

{
    nf = NF
    if (nf < 7) next
    if ($2 != "IP" && $2 != "IP6") next

    srcfull = $3
    dstfull = $5
    sub(/:$/, "", dstfull)
    src = stripport(srcfull)
    dst = stripport(dstfull)

    txnraw = $6
    txnid = txnraw
    sub(/[^0-9].*$/, "", txnid)
    if (txnid == "") next

    rest = ""
    for (i = 7; i <= nf; i++) {
        rest = rest (i > 7 ? " " : "") $i
    }

    if ($7 ~ /\?$/) {
        # --- QUERY ---
        queries++
        qseen[txnid] = 1
        qdata[txnid] = rest
    } else {
        # --- RESPONSE ---
        responses++
        already = (txnid in rcount) ? rcount[txnid] : 0
        rcount[txnid] = already + 1

        if (!(src in expected)) {
            alerts++
            printf "\n[%s] [ALERT] Unexpected DNS server responded\n", $1
            printf "  [TECHNICAL] txn=%s  src=%s  dst=%s  data=\"%s\"  (expected one of: %s)\n", txnid, src, dst, rest, dns_servers
            printf "  [WHAT THIS MEANS] Your machine received a DNS answer from a server it wasn't configured to ask (%s). This can be benign (a VPN, a secondary resolver, split-horizon DNS), but it is also how off-path DNS spoofing presents itself. If %s isn't a server you recognize, investigate.\n", src, src
        }

        if (already >= 1) {
            if (rdata[txnid] != rest) {
                alerts++
                printf "\n[%s] [ALERT] Conflicting DNS responses for the same query\n", $1
                printf "  [TECHNICAL] txn=%s  query=\"%s\"  first_response=\"%s\"  conflicting_response(src=%s)=\"%s\"\n", txnid, qdata[txnid], rdata[txnid], src, rest
                printf "  [WHAT THIS MEANS] Your computer asked one DNS question but got two DIFFERENT answers back for it. Legitimate DNS servers don't normally do this. This is the textbook signature of a DNS poisoning attempt, where an attacker races a forged answer against the real one, hoping the forged one arrives first and gets cached.\n"
            }
        } else {
            rdata[txnid] = rest
        }

        if (!(txnid in qseen) && responses > grace) {
            alerts++
            printf "\n[%s] [ALERT] DNS response with no matching outstanding query\n", $1
            printf "  [TECHNICAL] txn=%s  src=%s  data=\"%s\"\n", txnid, src, rest
            printf "  [WHAT THIS MEANS] An answer arrived for a question this monitor never saw your machine ask. Occasionally that's just a query sent right before monitoring started, but repeated occurrences can indicate injected or spoofed DNS traffic on the network.\n"
        }
    }
}

END {
    printf "\n=== DNS Watchdog session summary ===\n"
    printf "Queries observed:   %d\n", queries
    printf "Responses observed: %d\n", responses
    printf "Alerts raised:      %d\n", alerts
    if (alerts == 0) {
        printf "No signs of DNS poisoning were observed during this session.\n"
    } else {
        printf "Review the [ALERT] lines above. Repeated or clustered alerts are far more meaningful than a single isolated one — an occasional lone alert can be a false positive from network reconfiguration, VPN changes, or multi-answer CDN responses.\n"
    }
}
AWKEOF

tcpdump -n -l -i "$IFACE" 'port 53' 2>>"$LOGFILE" \
    | awk -v dns_servers="$DNS_SERVERS" -v grace=10 -f "$AWK_SCRIPT" \
    | tee -a "$LOGFILE"

cleanup
