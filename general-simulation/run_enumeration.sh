#!/usr/bin/env bash
set -euo pipefail

# Run from script's directory (broker/) so "go run ." works; paths relative to current script location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# --- Script-level environment (override before running: EPISODES=3 ./run_enumeration.sh) ---
# EPISODES: how many independent simulation runs per scenario (separate log/enum dirs).
EPISODES="${EPISODES:-3}"
# SIM_DAYS: simulated wall-clock span before auto-stop (SNOWFLAKE_SIM_MAX_SIM_DAYS).
SIM_DAYS="${SIM_DAYS:-30}"
# DEBUG_EVERY_SEC: interval between step-summary / attacker-summary debug logs (SNOWFLAKE_SIM_DEBUG_EVERY_SEC).
DEBUG_EVERY_SEC="${DEBUG_EVERY_SEC:-60}"
# PROBER_START_HOURS: hours after sim start before attacker/prober polls begin (SNOWFLAKE_SIM_PROBER_START_HOURS), which is for cold start.
PROBER_START_HOURS="${PROBER_START_HOURS:-24}"
# OUT_ROOT: directory tree for all scenario outputs (logs, attacker_enum.csv per episode).
OUT_ROOT="${OUT_ROOT:-${SCRIPT_DIR}/logs/scenario-runs-$(date -u +%Y%m%dT%H%M%SZ)}"
# ONLY_REGEX: if set, only run scenarios whose name matches this bash extended regex (empty = run all).
ONLY_REGEX="${ONLY_REGEX:-}"

# BASE_PROXY_TIMEOUT_SEC: broker-side proxy poll timeout seconds (SNOWFLAKE_SIM_PROXY_TIMEOUT_SEC).
BASE_PROXY_TIMEOUT_SEC="${BASE_PROXY_TIMEOUT_SEC:-10}"
# PERF_EVERY_REAL_SEC: wall-clock interval for perf sampling logs (SNOWFLAKE_SIM_PERF_EVERY_REAL_SEC).
PERF_EVERY_REAL_SEC="${PERF_EVERY_REAL_SEC:-60}"
# DEFAULT_ATTACKER_CLIENT_PCT: default attackers as % of client target (matches sim when SNOWFLAKE_SIM_ATTACKER_COUNT is unset).
DEFAULT_ATTACKER_CLIENT_PCT="${DEFAULT_ATTACKER_CLIENT_PCT:-0.05}"
# SNOWFLAKE_SIM_CLIENT_TARGET_COUNT: optional default active client target; unset = sim default. CLIENT_COUNT is a shorthand alias.
SNOWFLAKE_SIM_CLIENT_TARGET_COUNT="${SNOWFLAKE_SIM_CLIENT_TARGET_COUNT:-${CLIENT_COUNT:-}}"
# CLIENT_BASELINE: must match broker/sim/steploop.go defaultClientCount (30800*2); clients_half / quarter / double scale from this.
CLIENT_BASELINE="${CLIENT_BASELINE:-61600}"
# CLIENT_MAX_RETRIES: max client retry rounds before giving up (SNOWFLAKE_SIM_CLIENT_MAX_RETRIES).
CLIENT_MAX_RETRIES="${CLIENT_MAX_RETRIES:-1000000}"
# CONNECTION_MEAN_SEC: mean simulated client–proxy connection duration in seconds (SNOWFLAKE_SIM_CONNECTION_MEAN_SEC).
CONNECTION_MEAN_SEC="${CONNECTION_MEAN_SEC:-10800}"
# CONNECTION_STDDEV_SEC: stddev of connection duration for sampling (SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC).
CONNECTION_STDDEV_SEC="${CONNECTION_STDDEV_SEC:-1800}"

mkdir -p "${OUT_ROOT}"

should_run() {
  local name="$1"
  if [[ -z "${ONLY_REGEX}" ]]; then
    return 0
  fi
  [[ "${name}" =~ ${ONLY_REGEX} ]]
}

compute_attackers_from_pct() {
  local total_clients="$1"
  local pct="$2"
  awk -v n="${total_clients}" -v p="${pct}" '
    BEGIN {
      if (n <= 1) {
        print 0
        exit
      }
      val = n * (p / 100.0)
      a = int(val)
      if (val > a) {
        a = a + 1
      }
      if (a < 1) {
        a = 1
      }
      if ((a % 2) != 0) {
        a = a + 1
      }
      if (a >= n) {
        a = n - 1
      }
      if ((a % 2) != 0 && a > 1) {
        a = a - 1
      }
      print a
    }
  '
}

run_case() {
  local scenario="$1"
  local attack_mode="$2"
  shift 2
  local -a extra_env=()
  if [[ "$#" -gt 0 ]]; then
    extra_env=("$@")
  fi

  local attacker_pct=""
  local scenario_client_target=""
  local -a forwarded_extra_env=()
  for kv in "${extra_env[@]}"; do
    case "${kv}" in
      SNOWFLAKE_SIM_ATTACKER_CLIENT_PCT=*)
        attacker_pct="${kv#*=}"
        ;;
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

  local effective_attacker_count
  if [[ -n "${attacker_pct}" ]]; then
    effective_attacker_count="$(compute_attackers_from_pct "${effective_client_target}" "${attacker_pct}")"
    effective_client_target=$((effective_client_target - effective_attacker_count))
  else
    effective_attacker_count="$(compute_attackers_from_pct "${effective_client_target}" "${DEFAULT_ATTACKER_CLIENT_PCT}")"
    effective_client_target=$((effective_client_target - effective_attacker_count))
  fi

  local -a attacker_env=("SNOWFLAKE_SIM_ATTACKER_COUNT=${effective_attacker_count}")
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
    local enum_file="${episode_dir}/attacker_enum.csv"
    mkdir -p "${episode_dir}"

    echo "=== scenario=${scenario} episode=${ep} attack_mode=${attack_mode} ==="
    if [[ "${#extra_env[@]}" -gt 0 ]]; then
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
        "${attacker_env[@]}" \
        SNOWFLAKE_SIM_ATTACK_ENUM_FILE="${enum_file}" \
        SNOWFLAKE_SIM_CLIENT_MAX_RETRIES="${CLIENT_MAX_RETRIES}" \
        "${client_target_env[@]}" \
        SNOWFLAKE_SIM_CONNECTION_MEAN_SEC="${CONNECTION_MEAN_SEC}" \
        SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC="${CONNECTION_STDDEV_SEC}" \
        "${forwarded_extra_env[@]}" \
        go run . -simulate >"${log_file}" 2>&1
    else
      # Same env as above branch, without scenario-specific overrides.
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
        "${attacker_env[@]}" \
        SNOWFLAKE_SIM_ATTACK_ENUM_FILE="${enum_file}" \
        SNOWFLAKE_SIM_CLIENT_MAX_RETRIES="${CLIENT_MAX_RETRIES}" \
        "${client_target_env[@]}" \
        SNOWFLAKE_SIM_CONNECTION_MEAN_SEC="${CONNECTION_MEAN_SEC}" \
        SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC="${CONNECTION_STDDEV_SEC}" \
        go run . -simulate >"${log_file}" 2>&1
    fi

    echo "Wrote ${log_file}"
    echo "Wrote ${enum_file}"
  done
}

# DEFAULT (enumeration-only).
run_case "default_enumeration" 0

# Churn variants (enumeration-only).
# SNOWFLAKE_SIM_CHURN_RATE_PCT — hourly proxy churn as % of fleet (replaced proxies per churn cycle).
run_case "churn_x2" 0 SNOWFLAKE_SIM_CHURN_RATE_PCT=5.4
run_case "churn_half" 0 SNOWFLAKE_SIM_CHURN_RATE_PCT=1.3
run_case "churn_x4" 0 SNOWFLAKE_SIM_CHURN_RATE_PCT=10.8
run_case "churn_quarter" 0 SNOWFLAKE_SIM_CHURN_RATE_PCT=0.675
run_case "churn_x10" 0 SNOWFLAKE_SIM_CHURN_RATE_PCT=27

# Churn sweep at fixed attacker rate: SNOWFLAKE_SIM_ATTACKER_CLIENT_PCT=0.001 (0.1% of clients as attackers).
for churn in 0.675 1.3 5.4 10.8 27; do
  cstr="${churn//./_}"
  run_case "churn_${cstr}_attackers_0_001" 0 \
    SNOWFLAKE_SIM_CHURN_RATE_PCT="${churn}" \
    SNOWFLAKE_SIM_ATTACKER_CLIENT_PCT=0.001
done

# Client target variants (enumeration-only). SNOWFLAKE_SIM_CLIENT_TARGET_COUNT — half / quarter of CLIENT_BASELINE (default 61600).
run_case "clients_half" 0 SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=$((CLIENT_BASELINE / 2))
run_case "clients_quarter" 0 SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=$((CLIENT_BASELINE / 4))
run_case "clients_double" 0 SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=$((CLIENT_BASELINE * 2))
run_case "clients_x4" 0 SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=$((CLIENT_BASELINE * 4))
run_case "clients_x10" 0 SNOWFLAKE_SIM_CLIENT_TARGET_COUNT=$((CLIENT_BASELINE * 10))

# Connection duration variants (enumeration-only). Optional sweeps; defaults above stay 3h mean / 30m stddev (10800 / 1800).
# 1.5 hours ± 15 minutes (mean 5400s, stddev 900s).
run_case "connection_1_5h_pm15m" 0 \
  SNOWFLAKE_SIM_CONNECTION_MEAN_SEC=5400 \
  SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC=900
# 30 minutes ± 5 minutes (mean 1800s, stddev 300s).
run_case "connection_30m_pm5m" 0 \
  SNOWFLAKE_SIM_CONNECTION_MEAN_SEC=1800 \
  SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC=300
run_case "connection_6h_pm1h" 0 \
  SNOWFLAKE_SIM_CONNECTION_MEAN_SEC=21600 \
  SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC=3600
run_case "connection_9h_pm1h30m" 0 \
  SNOWFLAKE_SIM_CONNECTION_MEAN_SEC=32400 \
  SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC=5400


# Defense sweep: all proxy types at 1s, 10s, 20s, 100s (enumeration-only).
# SNOWFLAKE_SIM_*_POLL_SEC — seconds between polls for standalone / webext / iptproxy proxies.
for p in 10 120 240; do
  run_case "defense_equal_${p}s" 0 \
    SNOWFLAKE_SIM_STANDALONE_POLL_SEC="${p}" \
    SNOWFLAKE_SIM_WEBEXT_POLL_SEC="${p}" \
    SNOWFLAKE_SIM_IPTPROXY_POLL_SEC="${p}"
done

# Number-of-attackers sweep (enumeration-only).
# SNOWFLAKE_SIM_ATTACKER_CLIENT_PCT — attacker count as percentage of total clients; then reduce clients by that count.
for pct in 0.001 0.01 0.05 0.1 0.5 1 5; do
  label="${pct//./_}"
  run_case "attackers_pct_${label}" 0 SNOWFLAKE_SIM_ATTACKER_CLIENT_PCT="${pct}"
done

# NAT distribution variants (enumeration-only).
# SNOWFLAKE_SIM_STANDALONE_UNRESTRICTED_PCT — % of new standalone proxies that are NAT-unrestricted.
# SNOWFLAKE_SIM_WEBIPT_UNRESTRICTED_PCT — % of webext/iptproxy proxies that are unrestricted.
# 0.3 case: standalone restricted=30% => standalone unrestricted=70%;
# web/ipt unrestricted=30%.
run_case "nat_dist_0_3" 0 \
  SNOWFLAKE_SIM_STANDALONE_UNRESTRICTED_PCT=70 \
  SNOWFLAKE_SIM_WEBIPT_UNRESTRICTED_PCT=30

# 0.5 case: all types 50/50 unrestricted/restricted.
run_case "nat_dist_0_5" 0 \
  SNOWFLAKE_SIM_STANDALONE_UNRESTRICTED_PCT=50 \
  SNOWFLAKE_SIM_WEBIPT_UNRESTRICTED_PCT=50

# Proxy count variant (enumeration-only).
# SNOWFLAKE_SIM_PROXY_COUNT_SCALE — multiplies configured hourly proxy targets (0.5 = half the baseline fleet).
run_case "proxy_count_0_5" 0 SNOWFLAKE_SIM_PROXY_COUNT_SCALE=0.5

echo "All requested scenarios completed. Output root: ${OUT_ROOT}"
