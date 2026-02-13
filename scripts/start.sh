#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# OT SOC-in-a-Box — Unified Launcher
###############################################################################

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compose_file="${repo_root}/compose/docker-compose.yml"

ok()   { printf "  ${GRN}[+]${RST} %s\n" "$1"; }
warn() { printf "  ${YLW}[!]${RST} %s\n" "$1"; }
err()  { printf "  ${RED}[x]${RST} %s\n" "$1"; }
info() { printf "  ${CYN}[*]${RST} %s\n" "$1"; }

banner() {
  printf "\n${BLD}${CYN}===========================================================${RST}\n"
  printf "${BLD}${CYN}  %s${RST}\n" "$1"
  printf "${BLD}${CYN}===========================================================${RST}\n\n"
}

###############################################################################
banner "OT SOC-in-a-Box — Starting Lab"

# 1. Check prerequisites
info "Checking prerequisites..."

if ! command -v docker >/dev/null 2>&1; then
  err "Docker is not installed. Please install Docker first."
  exit 1
fi
ok "Docker found"

compose_cmd="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    compose_cmd="docker-compose"
  else
    err "Docker Compose not found. Please install Docker Compose."
    exit 1
  fi
fi
ok "Docker Compose found (${compose_cmd})"

if [ ! -f "${repo_root}/.env" ]; then
  warn ".env file not found — using default credentials"
fi

# 2. Pull images
info "Pulling container images (this may take a while on first run)..."
${compose_cmd} -f "${compose_file}" pull --quiet 2>/dev/null || \
  ${compose_cmd} -f "${compose_file}" pull

# 3. Start services
info "Starting all services..."
${compose_cmd} -f "${compose_file}" up -d

# 4. Wait for health checks
info "Waiting for services to become healthy..."

containers=(
  "ot-opensearch"
  "ot-wazuh-manager"
  "ot-wazuh-dashboard"
  "ot-openplc"
  "ot-modbus-sim"
  "ot-suricata"
  "ot-zeek"
)

max_wait=120
elapsed=0
interval=5

while [ $elapsed -lt $max_wait ]; do
  all_healthy=true
  for ctr in "${containers[@]}"; do
    status=$(docker inspect --format='{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo "missing")
    if [ "$status" != "healthy" ]; then
      all_healthy=false
      break
    fi
  done

  if $all_healthy; then
    break
  fi

  printf "\r  ${CYN}[*]${RST} Waiting for containers... (%ds / %ds)" "$elapsed" "$max_wait"
  sleep $interval
  elapsed=$((elapsed + interval))
done
printf "\n"

# Report status of each container
for ctr in "${containers[@]}"; do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo "not found")
  if [ "$status" = "healthy" ]; then
    ok "$ctr: healthy"
  else
    warn "$ctr: $status"
  fi
done

# Check agent (no healthcheck defined, just check running)
agent_running=$(docker inspect --format='{{.State.Running}}' "ot-wazuh-agent" 2>/dev/null || echo "false")
if [ "$agent_running" = "true" ]; then
  ok "ot-wazuh-agent: running"
else
  warn "ot-wazuh-agent: not running (manager may still be initializing)"
fi

# 5. Run preflight if available
if [ -x "${script_dir}/preflight.sh" ]; then
  printf "\n"
  info "Running preflight checks..."
  "${script_dir}/preflight.sh" || warn "Preflight reported issues (see above)"
fi

# 6. Print access info
banner "Lab Ready"

printf "  ${BLD}%-25s${RST} %s\n" "Service" "Access"
printf "  %-25s %s\n"              "-------" "------"
printf "  ${BLD}%-25s${RST} %s\n" "Wazuh Dashboard" "http://localhost:15601  (admin / SecureAdmin123!)"
printf "  ${BLD}%-25s${RST} %s\n" "Wazuh API" "https://localhost:15500 (admin / SecurePassword123!)"
printf "  ${BLD}%-25s${RST} %s\n" "OpenSearch" "https://localhost:19200 (admin / SecureAdmin123!)"
printf "  ${BLD}%-25s${RST} %s\n" "OpenPLC Web" "http://localhost:8080   (openplc / openplc)"
printf "  ${BLD}%-25s${RST} %s\n" "Modbus Simulator" "localhost:1502 (TCP)"

printf "\n"
info "Next steps:"
printf "  1. Import dashboard:     ${BLD}./scripts/create_dashboard.sh${RST}\n"
printf "  2. Run attack simulation: ${BLD}./scripts/attack_sim.sh${RST}\n"
printf "  3. Stop the lab:          ${BLD}docker compose -f compose/docker-compose.yml down${RST}\n"
printf "\n"
