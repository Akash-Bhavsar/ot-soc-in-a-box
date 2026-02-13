#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compose_file="${repo_root}/compose/docker-compose.yml"

compose_cmd="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    compose_cmd="docker-compose"
  else
    echo "ERROR: docker compose not found."
    exit 1
  fi
fi

failures=0

step() {
  printf "\n== %s ==\n" "$1"
}

ok() {
  printf "OK: %s\n" "$1"
}

warn() {
  printf "WARN: %s\n" "$1"
  failures=$((failures + 1))
}

step "Container status"
if ! ps_output=$(${compose_cmd} -f "${compose_file}" ps 2>&1); then
  warn "docker compose ps failed"
  echo "${ps_output}"
else
  echo "${ps_output}"
  if echo "${ps_output}" | grep -E -i "exit|exited|restart|unhealthy" >/dev/null; then
    warn "One or more containers look unhealthy or stopped"
  else
    ok "All containers appear running"
  fi
fi

step "Telemetry paths inside wazuh-manager"
if docker exec ot-wazuh-manager test -d /var/ot/telemetry >/dev/null 2>&1; then
  ok "Telemetry root present"
else
  warn "Telemetry root missing in wazuh-manager"
fi

if docker exec ot-wazuh-manager test -d /var/ot/telemetry/suricata >/dev/null 2>&1; then
  ok "Suricata telemetry path present"
else
  warn "Suricata telemetry path missing"
fi

if docker exec ot-wazuh-manager test -d /var/ot/telemetry/zeek >/dev/null 2>&1; then
  ok "Zeek telemetry path present"
else
  warn "Zeek telemetry path missing"
fi

step "Logcollector monitoring"
# Check logcollector stats for telemetry files (more reliable than grepping rotated logs)
lc_state="$(docker exec ot-wazuh-manager bash -lc "cat /var/ossec/var/run/wazuh-logcollector.state 2>/dev/null" 2>/dev/null || true)"
if echo "${lc_state}" | grep -q "eve.json"; then
  ok "Logcollector monitoring Suricata eve.json"
else
  warn "Logcollector not monitoring Suricata eve.json"
fi
if echo "${lc_state}" | grep -q "conn.log"; then
  ok "Logcollector monitoring Zeek conn.log"
else
  warn "Logcollector not monitoring Zeek conn.log"
fi

step "Wazuh status"
status_out="$(docker exec ot-wazuh-manager bash -lc "/var/ossec/bin/wazuh-control status || true" 2>&1 || true)"
if [ -z "${status_out}" ]; then
  warn "Unable to query wazuh-control status"
else
  echo "${status_out}"
  if echo "${status_out}" | grep -q "wazuh-analysisd is running"; then
    ok "wazuh-analysisd running"
  else
    warn "wazuh-analysisd not running"
  fi
fi

step "Rules and decoders mounted"
if docker exec ot-wazuh-manager test -f /var/ossec/etc/rules/ot-soc_rules.xml >/dev/null 2>&1; then
  ok "Custom rules file mounted"
else
  warn "Custom rules file missing"
fi

if docker exec ot-wazuh-manager test -f /var/ossec/etc/decoders/ot-soc_decoders.xml >/dev/null 2>&1; then
  ok "Custom decoders file mounted"
else
  warn "Custom decoders file missing"
fi

step "Wazuh Agent"
agent_running="$(docker inspect --format='{{.State.Running}}' ot-wazuh-agent 2>/dev/null || echo "false")"
if [ "$agent_running" = "true" ]; then
  ok "Wazuh Agent container running"
else
  warn "Wazuh Agent container not running"
fi

agent_list="$(docker exec ot-wazuh-manager bash -lc "/var/ossec/bin/agent_control -l 2>/dev/null | grep -i 'ot-soc-agent' || true" 2>/dev/null || true)"
if [ -n "${agent_list}" ]; then
  ok "Agent 'ot-soc-agent' registered with manager"
  echo "${agent_list}"
else
  warn "Agent 'ot-soc-agent' not yet registered (may still be connecting)"
fi

if [ "${failures}" -gt 0 ]; then
  printf "\nPreflight completed with %s issue(s).\n" "${failures}"
  exit 1
fi

printf "\nPreflight completed successfully.\n"
