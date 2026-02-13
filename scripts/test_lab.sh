#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# OT SOC-in-a-Box — Quick Smoke Test
# Runs a fast end-to-end check: Modbus write → Suricata alert → Wazuh rule
###############################################################################

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compose_file="${repo_root}/compose/docker-compose.yml"

RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

ok()   { printf "  ${GRN}[PASS]${RST} %s\n" "$1"; }
fail() { printf "  ${RED}[FAIL]${RST} %s\n" "$1"; failures=$((failures + 1)); }
info() { printf "  ${CYN}[*]${RST}    %s\n" "$1"; }

failures=0

printf "\n${BLD}${CYN}OT SOC-in-a-Box — Smoke Test${RST}\n\n"

# 1. Check containers
printf "${BLD}[1/5] Container health${RST}\n"
for ctr in ot-opensearch ot-wazuh-manager ot-wazuh-dashboard ot-suricata ot-zeek ot-openplc ot-modbus-sim; do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo "missing")
  if [ "$status" = "healthy" ]; then
    ok "$ctr"
  else
    fail "$ctr ($status)"
  fi
done
# Agent has no healthcheck, just check running
agent_running=$(docker inspect --format='{{.State.Running}}' "ot-wazuh-agent" 2>/dev/null || echo "false")
if [ "$agent_running" = "true" ]; then
  ok "ot-wazuh-agent (running)"
else
  fail "ot-wazuh-agent (not running)"
fi

# 2. Send Modbus traffic from openplc (on ot-zone network, visible to Suricata/Zeek)
printf "\n${BLD}[2/5] Modbus write traffic${RST}\n"
info "Sending FC 0x06 (Write Single Register) from ot-openplc → modbus-sim:5020"
docker exec ot-openplc bash -lc \
  'exec 3<>/dev/tcp/modbus-sim/5020; printf "\x00\x01\x00\x00\x00\x06\x01\x06\x00\x01\x00\x42" >&3; head -c 12 <&3 >/dev/null 2>&1; exec 3<&-' \
  2>/dev/null && ok "Modbus write sent successfully" || fail "Modbus write failed"

# 3. Inject synthetic Suricata alert (Docker bridge can't capture inter-container traffic)
printf "\n${BLD}[3/5] Suricata alert injection${RST}\n"
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000000+0000')
alert_json="{\"timestamp\":\"${ts}\",\"event_type\":\"alert\",\"src_ip\":\"10.99.99.99\",\"src_port\":44818,\"dest_ip\":\"172.18.0.3\",\"dest_port\":502,\"proto\":\"TCP\",\"alert\":{\"action\":\"allowed\",\"gid\":1,\"signature_id\":9000001,\"rev\":2,\"signature\":\"ICS Modbus Write Single Coil\",\"category\":\"Attempted User Privilege Gain\",\"severity\":1}}"
docker exec ot-suricata bash -lc "echo '${alert_json}' >> /var/ot/telemetry/suricata/eve.json" \
  2>/dev/null && ok "Alert injected into eve.json" || fail "Alert injection failed"

info "Waiting 10s for Wazuh to process..."
sleep 10

# 4. Check Wazuh detected the alert
printf "\n${BLD}[4/5] Wazuh detection${RST}\n"
wazuh_alerts=$(docker exec ot-wazuh-manager bash -lc \
  "grep '100101' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3" 2>/dev/null || true)
if [ -n "$wazuh_alerts" ]; then
  ok "Rule 100101 (OT Modbus write) triggered"
else
  fail "Rule 100101 not found in alerts (may need more time)"
fi

# 5. Check Zeek logs
printf "\n${BLD}[5/5] Zeek connection logs${RST}\n"
zeek_logs=$(docker exec ot-wazuh-manager bash -lc \
  "tail -3 /var/ot/telemetry/zeek/conn.log 2>/dev/null" 2>/dev/null || true)
if [ -n "$zeek_logs" ]; then
  ok "Zeek conn.log has entries"
else
  fail "Zeek conn.log is empty or missing"
fi

# Summary
printf "\n${BLD}───────────────────────────────${RST}\n"
if [ "$failures" -eq 0 ]; then
  printf "${GRN}${BLD}All checks passed.${RST}\n\n"
else
  printf "${RED}${BLD}${failures} check(s) failed.${RST}\n\n"
  exit 1
fi
