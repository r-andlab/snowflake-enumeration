# Docker Quick Start

## Run all three directories

```bash
docker compose --profile live up --build
```

## Run one directory

```bash
# General simulation: default enumeration, then default blocking
docker compose up --build general-simulation

# Malicious-proxy simulation
docker compose up --build malicious-proxy-simulation

# Real-world prober
docker compose --profile live up --build real-world
```

Stop running containers with `Ctrl-C` or:

```bash
docker compose stop
```

## Run in the background and check logs

Start all three services in detached mode:

```bash
docker compose --profile live up --build -d
```

Check whether each service is still running or has finished:

```bash
docker compose --profile live ps --all
```

In the `STATUS` column, `Up` means the service is still running,
`Exited (0)` means it finished successfully, and any other exit code means it
failed.

Follow logs from all services while they are running:

```bash
docker compose --profile live logs --follow --tail=100
```

Follow logs from one service only:

```bash
docker compose --profile live logs --follow --tail=100 general-simulation
docker compose --profile live logs --follow --tail=100 malicious-proxy-simulation
docker compose --profile live logs --follow --tail=100 real-world
```

Press `Ctrl-C` to stop following the logs. The detached containers will keep
running.

## Check logs after stopping

```bash
# Container output
docker compose logs general-simulation
docker compose logs malicious-proxy-simulation
docker compose logs real-world

# General enumeration log
docker compose run --rm --no-deps --entrypoint /usr/bin/tail \
  general-simulation -n 100 /output/default_enumeration/episode-1/sim.log

# General blocking log
docker compose run --rm --no-deps --entrypoint /usr/bin/tail \
  general-simulation -n 100 /output/default_blocking/episode-1/sim.log

# Malicious-proxy log
docker compose run --rm --no-deps --entrypoint /usr/bin/tail \
  malicious-proxy-simulation -n 100 /output/default_malicious/episode-1/sim.log

# Real-world results
docker compose --profile live run --rm --no-deps --entrypoint /usr/bin/tail \
  real-world -n 100 /output/proxy_ASNs.csv
```

Use `docker compose stop`, rather than `docker compose down`, if you still need
the stopped containers' `docker compose logs` output.

---
# Details of each part:

This repository contains 3 folders:
1) general-simulation is for simulation of enumeration and blocking locally
2) real-world  is to run a local client to fetch proxies from real-world broker
3) malicious-proxy-simulation is for simulation of a malicious proxy with client count fixed to be -1

## Snowflake Simulation

This directory contains the Snowflake broker server, the simulation harness and the simulation raw logs for analysis in directory of /data.


### Simulation Model

The current simulator is a **step-loop model**:

- One loop iteration = one simulated second.
- Clients/proxies/attackers are ghost entities tracked as state structs (not one long-lived goroutine per entity).
- Broker IPC and matching logic are real.
- Fake clock is used for simulation timestamps and broker-side timeout behavior.
- Fake-time `After` timers are managed with a deadline min-heap (not linear scan), so timeout handling scales better as pending timers grow.

What is simulated:

- Hourly target proxy populations by type (`standalone`, `webext`, `iptproxy`) from `sim/data.go`.
- Hourly churn (remove/add proxies), with default spread across each simulated hour to avoid synchronized bursts.
- Client polling and retries (retry interval fixed at 3 simulated seconds; max retries configurable).
- Proxy polling behavior and post-match waits.
- Attacker probing with configurable mode and attacker count.
- Two attack modes:
  - `SNOWFLAKE_SIM_ATTACK_MODE=0`: enumeration only (record observed proxies, no blocking).
  - `SNOWFLAKE_SIM_ATTACK_MODE=1`: blocking mode.

### Quick Start

get into directory of `general-simulation/broker`

#### 1) Default blocking experiment

```bash

ONLY_REGEX='default' ./run_blocking.sh
```

#### 2) Default enumeration experiment (no blocking)

```bash

ONLY_REGEX='default' ./run_enumeration.sh
```

#### 3) Run a specific setting

```bash

ONLY_REGEX='xx' ./run_enumeration.sh | ./run_blocking.sh
```

### Log Outputs

Main summary logs:

- `step-summary`: cumulative counters and snapshot state.
- `attacker-summary`: attacker probe totals and next probe schedule.
- `perf-summary`: real-time throughput and ETA.
- `sim-debug`: scheduler/backpressure/runtime internals.
  - Includes `fake_timers=...` (current pending fake-time timeout count).

High-volume logs:

- `SNOWFLAKE_SIM_POLL_LOGS=1`: per-poll client/proxy/prober lines.
- `SNOWFLAKE_SIM_EVENT_LOGS=1`: event-level match/no-match lines.

For long runs, keep poll/event logs low and use summary logs.

### Code Structure

This section is the fastest path for a new developer.

#### Entry path

1. `broker/proxy_poll_simulator.go`
- Handles `-simulate` startup.
- Configures simulation proxy timeout from env.
- Enables fake time.
- Creates broker context + IPC wrapper.
- Calls `sim.ProxyPollSimulation(...)`.

2. `broker/sim/run.go`
- Main simulation loop.
- Creates `ProxyPollSimulator` and `stepLoop`.
- Runs `runStep()` once per simulated second.
- Emits periodic `step-summary`, `attacker-summary`, `perf-summary`, `sim-debug`.

#### State + core behavior

- `broker/sim/steploop.go`
  - Ghost entity state (`ghostClient`, `ghostProxy`, `ghostAttacker`).
  - Scheduling/poll dispatch logic.
  - Churn and hourly target application.
  - Client retry policy and retry-limit handling.
  - Step-summary counters.

- `broker/sim/core.go`
  - Broker IPC request/response preparation and processing.
  - Connection registration/unregistration.
  - Blocked proxy accounting.
  - Client/proxy matching outcomes.

- `broker/sim/types.go`
  - Main simulator struct (`ProxyPollSimulator`) and shared stats structs.
  - Attack mode setup and enum-file setup.

- `broker/sim/instrumentation.go`
  - Env parsing helpers.
  - IPC in-flight/slow-call instrumentation.
  - `sim-debug` snapshot logging.

- `broker/sim/attack.go`
  - Attacker observation tracking and optional CSV output.

- `broker/sim/churn.go`
  - Mapping of proxy type to hourly target count arrays.

- `broker/sim/data.go`
  - Hourly proxy count traces (input data).

- `broker/sim/faketime.go`, `broker/sim/simclock.go`
  - Fake clock primitives used by simulation and logging.

- `broker/sim/stats.go`
  - `Stop()`, runtime stats aggregation, printable stats.


#### Scenario automation

- `broker/sim/run_scenario_episodes.sh`
  - Runs multiple scenario presets and episodes.
  - Writes logs under `broker/logs/...`.

### Simulation Flags (Environment Variables)

All simulation settings are `SNOWFLAKE_SIM_*`.

#### Core control

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_MAX_SIM_DAYS` | `30` | Auto-stop after this many simulated days. `0` = run until interrupted. |
| `SNOWFLAKE_SIM_DEBUG` | `0` | Enables periodic summary debug logs. |
| `SNOWFLAKE_SIM_DEBUG_EVERY_SEC` | `5` | Simulated seconds between summary snapshots. |
| `SNOWFLAKE_SIM_PROBER_START_HOURS` | `24` | Delay before attackers begin probing (simulated hours). |

#### Attack / enumeration

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_ATTACK_MODE` |  | `0` enumeration-only, `1` blocking. |
| `SNOWFLAKE_SIM_ATTACK_ENUM_FILE` | unset | CSV file where newly observed attacker proxies are appended. |
| `SNOWFLAKE_SIM_ATTACKER_COUNT` | `2` | Number of attacker pollers. |

#### Client behavior

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_CLIENT_TARGET_COUNT` | `61600` | Target active client population. Bootstrap starts with this many clients. |
| `SNOWFLAKE_SIM_CLIENT_REPLENISH_HOURLY` | `1` | If enabled, each simulated hour replenishes closed clients back to target count. |
| `SNOWFLAKE_SIM_CLIENT_POLL_JITTER_SEC` | `3600` | Random jitter window (seconds) applied around matched-client wait to avoid synchronized poll bursts. |
| `SNOWFLAKE_SIM_CLIENT_SPAWN_SPREAD_SEC` | `3600` | Spread window for first poll of newly spawned clients (hourly replenish and immediate retry-limit respawn). |
| `SNOWFLAKE_SIM_CLIENT_IMMEDIATE_RESPAWN` | `1` | If enabled, a client that hits retry limit is replaced immediately with a fresh client ID (first poll randomized by `CLIENT_SPAWN_SPREAD_SEC`). |
| `SNOWFLAKE_SIM_CLIENT_MAX_RETRIES` | `1000000` | Max retries per client before that client is closed. |
| `SNOWFLAKE_SIM_MATCHED_CLIENT_WAIT_SEC` | `10800` | Wait after successful client match (default 3h). |

Notes:

- Client retry interval is fixed to 3 simulated seconds in code.
- `step-summary` includes no-match reason counters: `client_nomatch_reasons no_proxies=... timed_out=... blocked=... other=...`.

#### Proxy polling / NAT mix / capacity

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_STANDALONE_POLL_SEC` | `5` | Standalone proxy poll interval. |
| `SNOWFLAKE_SIM_WEBEXT_POLL_SEC` | `60` | WebExtension proxy poll interval. |
| `SNOWFLAKE_SIM_IPTPROXY_POLL_SEC` | `120` | IPT proxy poll interval. |
| `SNOWFLAKE_SIM_MATCHED_PROXY_WAIT_SEC` | `10800` | Wait for non-standalone proxies after non-attacker match (default 3h). |
| `SNOWFLAKE_SIM_PROXY_POLL_JITTER_PCT` | `0` | Random jitter percentage around poll interval. |
| `SNOWFLAKE_SIM_PROXY_COUNT_SCALE` | `1.0` | Multiplier on proxy target counts. |
| `SNOWFLAKE_SIM_STANDALONE_UNRESTRICTED_PCT` | `90` | Standalone unrestricted NAT percent. |
| `SNOWFLAKE_SIM_WEBIPT_UNRESTRICTED_PCT` | `10` | WebExt/IPT unrestricted NAT percent. |
| `SNOWFLAKE_SIM_PROXY_RESULT_BUFFER` | `16384` | Internal result channel capacity for async proxy polls. |
| `SNOWFLAKE_SIM_STEP_YIELD_ROUNDS` | `1` | Scheduler yield rounds per simulation step. |
| `SNOWFLAKE_SIM_STEP_SETTLE_ROUNDS` | `0` | Extra `Gosched+drain` rounds at end of each step to flush completed async proxy results before advancing simulated time. |

#### Churn

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_CHURN_RATE_PCT` | `2.7` | Base hourly churn rate. |
| `SNOWFLAKE_SIM_SPREAD_HOURLY_CHURN` | `1` | If enabled, applies hourly target/churn adjustments gradually across the hour. If `0`, uses legacy batch-at-hour-boundary behavior (can cause client poll spikes near `:00/:01`). |

#### Logging and instrumentation

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_POLL_LOGS` | `1` | Per-poll entity logs (high volume). |
| `SNOWFLAKE_SIM_EVENT_LOGS` | `0` | Event-level logs (matches/no-match detail). |
| `SNOWFLAKE_SIM_POLL_RANDOM_SEED` | start-time unix | RNG seed for randomized due-proxy dispatch ordering. |

`sim-debug` key fields:

- `inflight_ipc`, `async_workers`: current concurrent IPC work.
- `goroutines`: runtime goroutine count.
- `fake_timers`: pending fake-time timeout events.
- `max_inflight`, `max_async`, `max_goroutines`: observed peaks.
- `total_ipc`, `slow_ipc`: cumulative IPC workload.

#### Broker poll timeout (used by simulation)

| Variable | Default | Meaning |
|---|---:|---|
| `SNOWFLAKE_SIM_PROXY_TIMEOUT_SEC` | `10` | Broker proxy poll timeout (seconds). |
| `SNOWFLAKE_SIM_PROXY_TIMEOUT_MS` | unset | Timeout in ms (takes precedence over seconds). |

Script env vars:

| Variable | Default | Meaning |
|---|---:|---|
| `EPISODES` | `3` | Episodes per scenario. |
| `SIM_DAYS` | `30` | Simulated days per episode. |
| `DEBUG_EVERY_SEC` | `60` | Debug snapshot interval (`SNOWFLAKE_SIM_DEBUG_EVERY_SEC`). |
| `PROBER_START_HOURS` | `24` | Attacker start delay (passed through as `SNOWFLAKE_SIM_PROBER_START_HOURS`). |
| `OUT_ROOT` | auto under `broker/logs` | Output root for run artifacts. |
| `ONLY_REGEX` | empty | Filter scenarios by regex. |
| `BASE_PROXY_TIMEOUT_SEC` | `10` | Base broker proxy timeout. |

### Simulation Data
Our simualation logs are available (subject to file size constraints) in `broker/data/`



## Real-World Enumeration
get into directory of `real-world`

This repository redefines the Tor-Snowflake Command Line Client, originally available at https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake, for the purposes of our real-world enumeration experiment. 

#### Modifications to Snowflake Client

The main behavioral changes are:

- `snowflake/client/lib/rendezvous.go` now loads local CAIDA prefix-to-ASN datasets, extracts the proxy IP address from the broker SDP answer, maps the IP to an ASN, anonymizes the IP with a per-run keyed HMAC-SHA256 hash, and appends timestamped results to `proxy_ASNs.csv`.
- The modified rendezvous flow intentionally returns an error after logging the ASN result so the process retries and continues probing instead of completing a normal client session.
- `snowflake/client/prober.go` was added as a standalone probing loop that repeatedly creates WebRTC offers, contacts the broker, triggers ASN logging, closes the peer connection, and repeats.
- Supporting client changes export broker-channel construction, refine WebRTC peer setup, and isolate per-connection client configuration in the SOCKS accept loop.

#### Running the Prober
1. To use the prober, hardcode the client NAT setting first at `snowflake/client/lib/rendezvous.go#L396` 

2. Move to client directory: `cd snowflake/client/`

3. Start the prober using `go prober.go`

4. Enumeration results will be stored in snowflake/client/proxy_ASNs.csv

Note: We caution against using the prober heavily against the live Snowflake broker, as it may cause technical disruptions (see paper for safety details). 

#### Results
Aggregate real-world measurement data from our 48-day enumeration study is available at /data here

Raw Snowflake IP addresses and keyed hashes are withheld to protect the privacy of volunteer proxy operators. 


## Snowflake Broker Simulation (Malicious Proxy)
get into directory of `malicious-proxy-simulation/broker`

This repository changes our Snowflake simulator for the malicious proxy use case (Section 6 in paper). This repository only supports the malicious proxy use case.  

This README only covers `run_malicious.sh`. The data is in directory of /data here.

### Run

From repo root:

```bash
./run_malicious.sh
```

Run only default scenario:

```bash
ONLY_REGEX='default' ./run_malicious.sh
```

Single episode / short run:

```bash
 ./run_malicious.sh
```

### What this script does

- Enables malicious standalone proxies (`SNOWFLAKE_SIM_MALICIOUS_PROXY=1`)
- Uses no attackers (`SNOWFLAKE_SIM_ATTACKER_COUNT=0`)
- Starts malicious proxies at simulated `+24h`

### Key overrides

You can set these before running:

| Variable | Default |
|---|---:|
| `EPISODES` | `3` |
| `SIM_DAYS` | `30` |
| `DEBUG_EVERY_SEC` | `60` |
| `OUT_ROOT` | `broker/logs/malicious-runs-<timestamp>` |
| `ONLY_REGEX` | empty |
| `CLIENT_BASELINE` | `61600` |
| `SNOWFLAKE_SIM_CLIENT_TARGET_COUNT` | unset (falls back to `CLIENT_BASELINE`) |
| `CLIENT_MAX_RETRIES` | `1000000` |
| `CONNECTION_MEAN_SEC` | `10800` |
| `CONNECTION_STDDEV_SEC` | `1800` |
| `BASE_PROXY_TIMEOUT_SEC` | `10` |

### Output

By default:

```text
broker/logs/malicious-runs-<timestamp>/<scenario>/episode-<n>/sim.log
```

Typical lines to inspect:

- `minute-malicious-proxy`
- `step-summary`
- `step-summary-broker-heaps`


### Data
The malicious proxy results are available at data directory
