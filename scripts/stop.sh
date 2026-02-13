#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# OT SOC-in-a-Box — Stop Lab
###############################################################################

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLD='\033[1m'
RST='\033[0m'

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compose_file="${repo_root}/compose/docker-compose.yml"

compose_cmd="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    compose_cmd="docker-compose"
  else
    printf "  ${RED}ERROR: docker compose not found.${RST}\n"
    exit 1
  fi
fi

remove_volumes=false
if [[ "${1:-}" == "-v" || "${1:-}" == "--volumes" ]]; then
  remove_volumes=true
fi

printf "\n${BLD}Stopping OT SOC-in-a-Box...${RST}\n\n"

if $remove_volumes; then
  printf "  ${YLW}[!]${RST} Removing containers AND volumes (all data will be deleted)\n\n"
  ${compose_cmd} -f "${compose_file}" down -v
else
  ${compose_cmd} -f "${compose_file}" down
fi

printf "\n  ${GRN}[+]${RST} All services stopped.\n"

if ! $remove_volumes; then
  printf "  ${YLW}[!]${RST} Data volumes preserved. Use ${BLD}./scripts/stop.sh -v${RST} to also remove stored data.\n"
fi

printf "\n"
