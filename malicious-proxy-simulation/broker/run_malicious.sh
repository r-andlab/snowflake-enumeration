#!/usr/bin/env bash
set -euo pipefail

# Run broker simulation with malicious standalone proxies enabled (two ghosts: unrestricted + restricted
# NAT; see broker/sim/steploop_bootstrap.go). From broker/: ./run_malicious.sh
#
# Override before running: SIM_DAYS=7 EPISODES=1 ./run_malicious.sh
# Filter scenarios: ONLY_REGEX='default' ./run_malicious.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

EPISODES="${EPISODES:-3}"
SIM_DAYS="${SIM_DAYS:-30}"
DEBUG_EVERY_SEC="${DEBUG_EVERY_SEC:-60}"
PROBER_START_HOURS="${PROBER_START_HOURS:-24}"
OUT_ROOT="${OUT_ROOT:-${SCRIPT_DIR}/logs/malicious-runs-$(date -u +%Y%m%dT%H%M%SZ)}"
ONLY_REGEX="${ONLY_REGEX:-}"

BASE_PROXY_TIMEOUT_SEC="${BASE_PROXY_TIMEOUT_SEC:-10}"
PERF_EVERY_REAL_SEC="${PERF_EVERY_REAL_SEC:-60}"
SNOWFLAKE_SIM_CLIENT_TARGET_COUNT="${SNOWFLAKE_SIM_CLIENT_TARGET_COUNT:-${CLIENT_COUNT:-}}"
CLIENT_BASELINE="${CLIENT_BASELINE:-61600}"
CLIENT_MAX_RETRIES="${CLIENT_MAX_RETRIES:-1000000}"
CONNECTION_MEAN_SEC="${CONNECTION_MEAN_SEC:-10800}"
CONNECTION_STDDEV_SEC="${CONNECTION_STDDEV_SEC:-1800}"

mkdir -p "${OUT_ROOT}"

should_run() {
  local name="$1"
  if [[ -z "${ONLY_REGEX}" ]]; then
    return 0
  fi
  [[ "${name}" =~ ${ONLY_REGEX} ]]
}

run_case() {
  local scenario="$1"
  local attack_mode="$2"
  shift 2
  local -a extra_env=()
  if [[ "$#" -gt 0 ]]; then
    extra_env=("$@")
  fi

  local scenario_client_target=""
  local -a forwarded_extra_env=()
  for kv in "${extra_env[@]}"; do
    case "${kv}" in
      SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=*)
        scenario_client_target="${kv#*=}"
        forwarded_extra_env+=("${kv}")
        ;;
      *)
        forwarded_extra_env+=("${kv}")
        ;;
    esac
  done

  local effective_client_target="${scenario_client_target:-${SNOWFLAKE_SIM_CLIENT_TARGET_COUNT:-}}"
  if [[ -z "${effective_client_target}" ]]; then
    effective_client_target="${CLIENT_BASELINE}"
  fi

  local -a client_target_env=()
  if [[ -n "${effective_client_target}" ]]; then
    client_target_env=("SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=${effective_client_target}")
  fi

  if ! should_run "${scenario}"; then
    echo "Skipping ${scenario} (ONLY_REGEX=${ONLY_REGEX})"
    return
  fi

  for ep in $(seq 1 "${EPISODES}"); do
    local episode_dir="${OUT_ROOT}/${scenario}/episode-${ep}"
    local log_file="${episode_dir}/sim.log"
    mkdir -p "${episode_dir}"

    echo "=== scenario=${scenario} episode=${ep} attack_mode=${attack_mode} attackers=0 malicious=1 ==="
    env \
      SNOWFLAKE_SIM_DEBUG="${SNOWFLAKE_SIM_DEBUG:-1}" \
      SNOWFLAKE_SIM_DEBUG_EVERY_SEC="${DEBUG_EVERY_SEC}" \
      SNOWFLAKE_SIM_EVENT_LOGS=0 \
      SNOWFLAKE_SIM_POLL_LOGS=0 \
      SNOWFLAKE_SIM_PERF_TARGET_DAYS=30 \
      SNOWFLAKE_SIM_PERF_EVERY_REAL_SEC="${PERF_EVERY_REAL_SEC}" \
      SNOWFLAKE_SIM_MAX_SIM_DAYS="${SIM_DAYS}" \
      SNOWFLAKE_SIM_PROBER_START_HOURS="${PROBER_START_HOURS}" \
      SNOWFLAKE_SIM_PROXY_TIMEOUT_SEC="${BASE_PROXY_TIMEOUT_SEC}" \
      SNOWFLAKE_SIM_ATTACK_MODE="${attack_mode}" \
      SNOWFLAKE_SIM_ATTACKER_COUNT=0 \
      SNOWFLAKE_SIM_CLIENT_MAX_RETRIES="${CLIENT_MAX_RETRIES}" \
      "${client_target_env[@]}" \
      SNOWFLAKE_SIM_CONNECTION_MEAN_SEC="${CONNECTION_MEAN_SEC}" \
      SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC="${CONNECTION_STDDEV_SEC}" \
      SNOWFLAKE_SIM_MALICIOUS_PROXY=1 \
      "${forwarded_extra_env[@]}" \
      go run . -simulate >"${log_file}" 2>&1

    echo "Wrote ${log_file}"
  done
}

# --- Scenarios (blocking attack mode = 1) with malicious proxies on ---
run_case "default_malicious" 1

echo "All requested malicious-proxy scenarios completed. Output root: ${OUT_ROOT}"
