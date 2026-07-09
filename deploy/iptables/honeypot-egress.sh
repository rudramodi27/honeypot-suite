#!/bin/sh
# =====================================================================
# deploy/iptables/honeypot-egress.sh
# Deny-all egress from the honeypot Docker bridge (172.28.0.0/24),
# applied on the HOST's iptables (this is what Docker's `internal: true`
# network flag already mostly achieves at the bridge level — this script
# is the belt-and-suspenders host-firewall layer for anyone NOT using
# Docker's internal network flag, or running honeypots directly on bare
# metal/VMs via the systemd units in deploy/systemd/).
#
# NOT executed against a live host in this exercise — review and test
# in a non-production network namespace (`ip netns` or a throwaway VM)
# before applying to a real host; an egress rule mistake can also cut
# off the host's OWN management/SSH access if HONEYPOT_SUBNET is set
# wrong or if you apply this to the wrong interface.
#
# Usage:
#   sudo sh honeypot-egress.sh apply     # install rules
#   sudo sh honeypot-egress.sh remove    # tear down (also see 'flush')
#   sudo sh honeypot-egress.sh status    # show current honeypot chain
# =====================================================================
set -eu

HONEYPOT_SUBNET="172.28.0.0/24"     # must match docker-compose.hardened.yml honeypot-net
SIEM_IP="${SIEM_IP:-10.0.0.50}"      # set to your real log-shipping destination
SIEM_PORT="${SIEM_PORT:-5044}"       # Filebeat/Logstash default
UPDATE_PROXY_IP="${UPDATE_PROXY_IP:-}"   # optional: internal package-mirror/proxy IP for patching
CHAIN="HONEYPOT_EGRESS"

apply() {
    iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"

    # Always allow established/related return traffic (responses to inbound
    # attacker connections still need to leave — that's the honeypot itself
    # answering on 2222/8080/2121, not "egress" in the data-exfil sense).
    iptables -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow outbound ONLY to the SIEM/log-shipping destination...
    iptables -A "$CHAIN" -p tcp -d "$SIEM_IP" --dport "$SIEM_PORT" -j ACCEPT

    # ...and optionally an internal patch/update mirror (leave UPDATE_PROXY_IP
    # unset to deny package-manager egress entirely, which is the safer
    # default for a honeypot host — patch via a scheduled maintenance
    # window with rules temporarily relaxed, not an always-open path).
    if [ -n "$UPDATE_PROXY_IP" ]; then
        iptables -A "$CHAIN" -p tcp -d "$UPDATE_PROXY_IP" --dport 443 -j ACCEPT
    fi

    # Deny + log everything else originating from the honeypot subnet
    iptables -A "$CHAIN" -j LOG --log-prefix "HONEYPOT_EGRESS_DENY: " --log-level 4
    iptables -A "$CHAIN" -j DROP

    # Hook the chain into FORWARD (Docker bridge traffic) and OUTPUT
    # (if honeypots run as host processes via systemd instead of containers)
    iptables -C FORWARD -s "$HONEYPOT_SUBNET" -j "$CHAIN" 2>/dev/null \
        || iptables -I FORWARD -s "$HONEYPOT_SUBNET" -j "$CHAIN"
    iptables -C OUTPUT -s "$HONEYPOT_SUBNET" -j "$CHAIN" 2>/dev/null \
        || iptables -I OUTPUT -s "$HONEYPOT_SUBNET" -j "$CHAIN"

    echo "[honeypot-egress] Applied. Allowed: established/related, SIEM ${SIEM_IP}:${SIEM_PORT}$( [ -n "$UPDATE_PROXY_IP" ] && echo ", update-proxy ${UPDATE_PROXY_IP}:443" ). Everything else from ${HONEYPOT_SUBNET} is DROPPED + logged."
}

remove() {
    iptables -D FORWARD -s "$HONEYPOT_SUBNET" -j "$CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -s "$HONEYPOT_SUBNET" -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    echo "[honeypot-egress] Removed."
}

status() {
    iptables -L "$CHAIN" -n -v --line-numbers 2>/dev/null \
        || echo "[honeypot-egress] Chain not present (not applied)."
}

case "${1:-}" in
    apply)  apply ;;
    remove) remove ;;
    status) status ;;
    *) echo "Usage: $0 {apply|remove|status}"; exit 1 ;;
esac
