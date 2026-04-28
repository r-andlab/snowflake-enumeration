# Snowflake Broker (Malicious Runner)

This README only covers `run_malicious.sh`.

## Run

From repo root:

```bash
cd broker
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

## What this script does

- Enables malicious standalone proxies (`SNOWFLAKE_SIM_MALICIOUS_PROXY=1`)
- Uses no attackers (`SNOWFLAKE_SIM_ATTACKER_COUNT=0`)
- Uses equal poll interval for all proxy types (currently `240s`)
- Starts malicious proxies at simulated `+24h`

## Key overrides

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

## Output

By default:

```text
broker/logs/malicious-runs-<timestamp>/<scenario>/episode-<n>/sim.log
```

Typical lines to inspect:

- `minute-malicious-proxy`
- `step-summary`
- `step-summary-broker-heaps`


