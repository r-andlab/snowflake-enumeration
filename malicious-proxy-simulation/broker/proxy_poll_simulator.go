package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/broker/sim"
)

// ProxyPollSimulation runs the proxy poll simulation: creates the broker,
// then delegates to sim.ProxyPollSimulation (which blocks until interrupt).
func ProxyPollSimulation() {
	startTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	configureSimulationProxyTimeout()
	sim.UseFakeTime(startTime)

	metricsLogger := sim.NewSimulationMetricsLogger()
	ctx := NewBrokerContext(metricsLogger, "^0\\.0\\.0\\.0$")
	ipc := &IPC{ctx: ctx}
	go ctx.Broker()

	sim.ProxyPollSimulation(ipc, startTime)
}

func configureSimulationProxyTimeout() {
	rawMs := strings.TrimSpace(os.Getenv("SNOWFLAKE_SIM_PROXY_TIMEOUT_MS"))
	if rawMs != "" {
		ms, err := strconv.Atoi(rawMs)
		if err != nil || ms < 1 {
			log.Printf(
				"invalid SNOWFLAKE_SIM_PROXY_TIMEOUT_MS=%q, keeping default proxy timeout %s",
				rawMs,
				proxyPollTimeout,
			)
			return
		}
		proxyPollTimeout = time.Duration(ms) * time.Millisecond
		log.Printf("Simulation proxy poll timeout set to %s", proxyPollTimeout)
		return
	}

	rawSec := strings.TrimSpace(os.Getenv("SNOWFLAKE_SIM_PROXY_TIMEOUT_SEC"))
	if rawSec == "" {
		return
	}
	sec, err := strconv.Atoi(rawSec)
	if err != nil || sec < 1 {
		log.Printf(
			"invalid SNOWFLAKE_SIM_PROXY_TIMEOUT_SEC=%q, keeping default proxy timeout %s",
			rawSec,
			proxyPollTimeout,
		)
		return
	}
	proxyPollTimeout = time.Duration(sec) * time.Second
	log.Printf("Simulation proxy poll timeout set to %s", proxyPollTimeout)
}
