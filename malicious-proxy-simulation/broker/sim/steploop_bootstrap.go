package sim

import (
	"log"
	"time"
)

func (sl *stepLoop) bootstrap() {
	standaloneInit := sl.targetCount("standalone", 0)
	webextInit := sl.targetCount("webext", 0)
	iptInit := sl.targetCount("iptproxy", 0)

	log.Printf("Initializing step-loop entities: standalone=%d webext=%d iptproxy=%d clients=%d", standaloneInit, webextInit, iptInit, sl.clientTargetCount)
	log.Printf("Proxy poll dispatch mode: randomized (seed=%d)", sl.pollRandSeed)
	log.Printf(
		"Simulation config: attack_mode=%s attackers=%d prober_interval=%s standalone_poll=%s webext_poll=%s iptproxy_poll=%s poll_jitter_pct=%.2f churn_rate_pct=%.3f standalone_churn_factor=%.3f spread_hourly_churn=%t proxy_count_scale=%.3f nat_unrestricted standalone=%.3f web_ipt=%.3f matched_proxy_wait=%s matched_client_wait=%s connection_mean_wait=%s connection_stddev_wait=%s max_retries client=%d client_target=%d client_replenish_hourly=%t client_immediate_respawn=%t client_poll_jitter=%s client_spawn_spread=%s step_settle_rounds=%d",
		sl.sim.attackModeLabel(),
		len(sl.attackers),
		sl.proberInterval,
		sl.standalonePollInterval,
		sl.webextPollInterval,
		sl.iptPollInterval,
		sl.proxyPollJitterPct,
		sl.churnRateBase*100.0,
		defaultStandaloneChurnK,
		sl.spreadHourlyChurn,
		sl.proxyCountScale,
		sl.standaloneUnrestricted,
		sl.webIPTUnrestricted,
		sl.matchedProxyWait,
		sl.matchedClientWait,
		sl.connectionMeanWait,
		sl.connectionStddevWait,
		sl.clientMaxRetries,
		sl.clientTargetCount,
		sl.clientReplenishHour,
		sl.clientImmediateRespawn,
		sl.clientPollJitter,
		sl.clientSpawnSpread,
		sl.stepSettleRounds,
	)
	if sl.sim.attackEnumPath != "" {
		log.Printf("Attacker enumeration output file: %s", sl.sim.attackEnumPath)
	}
	if sl.clientResultsUnbounded {
		log.Printf("Async client result queue: unbounded (SNOWFLAKE_SIM_CLIENT_RESULT_BUFFER=0)")
	} else {
		log.Printf("Async client result queue: hard_max=%d", cap(sl.clientResults))
	}

	standaloneUnrestricted := int(float64(standaloneInit)*sl.standaloneUnrestricted + 0.5)
	if standaloneUnrestricted < 0 {
		standaloneUnrestricted = 0
	}
	if standaloneUnrestricted > standaloneInit {
		standaloneUnrestricted = standaloneInit
	}
	sl.addInitialStandalone(standaloneUnrestricted, "unrestricted")
	sl.addInitialStandalone(standaloneInit-standaloneUnrestricted, "restricted")
	sl.addInitialProxyType("webext", webextInit, sl.webextPollInterval)
	sl.addInitialProxyType("iptproxy", iptInit, sl.iptPollInterval)
	sl.addClients(sl.clientTargetCount)
	sl.addMaliciousProxies()
}

// addMaliciousProxies registers two standalone malicious proxies (unrestricted + restricted). Each uses the
// same async pollProxy path (one goroutine per in-flight poll) and repolls every simulated step.
func (sl *stepLoop) addMaliciousProxies() {
	if !sl.maliciousProxyEnabled {
		return
	}
	pt := "standalone"
	interval := sl.standalonePollInterval

	addOne := func(nat string) int {
		id := sl.nextProxyID[pt]
		sl.nextProxyID[pt]++
		gp := &ghostProxy{
			proxyID:       id,
			proxyType:     pt,
			standaloneNAT: nat,
			pollInterval:  interval,
			nextPollAt:    sl.startTime,
			malicious:     true,
		}
		sl.proxies[pt][id] = gp
		FakeTimeStepMu.RLock()
		sl.sim.recordProxyStart(pt, id)
		FakeTimeStepMu.RUnlock()
		return id
	}

	sl.maliciousProxyUnrestrictedID = addOne("unrestricted")
	sl.maliciousProxyRestrictedID = addOne("restricted")
	log.Printf(
		"malicious proxies: enabled standalone-%d (unrestricted) and standalone-%d (restricted); poll every simulated step, immediate disconnect on match",
		sl.maliciousProxyUnrestrictedID,
		sl.maliciousProxyRestrictedID,
	)
}

func (sl *stepLoop) addInitialStandalone(count int, natType string) {
	for i := 0; i < count; i++ {
		id := sl.nextProxyID["standalone"]
		sl.nextProxyID["standalone"]++
		nextPoll := sl.startTime.Add(spreadOffset(i, count, proxySpreadWindow))
		sl.proxies["standalone"][id] = &ghostProxy{
			proxyID:       id,
			proxyType:     "standalone",
			standaloneNAT: natType,
			pollInterval:  sl.standalonePollInterval,
			nextPollAt:    nextPoll,
		}
		FakeTimeStepMu.RLock()
		sl.sim.recordProxyStart("standalone", id)
		FakeTimeStepMu.RUnlock()
	}
}

func (sl *stepLoop) addInitialProxyType(proxyType string, count int, interval time.Duration) {
	for i := 0; i < count; i++ {
		id := sl.nextProxyID[proxyType]
		sl.nextProxyID[proxyType]++
		nextPoll := sl.startTime.Add(spreadOffset(i, count, proxySpreadWindow))
		sl.proxies[proxyType][id] = &ghostProxy{
			proxyID:      id,
			proxyType:    proxyType,
			pollInterval: interval,
			nextPollAt:   nextPoll,
		}
		FakeTimeStepMu.RLock()
		sl.sim.recordProxyStart(proxyType, id)
		FakeTimeStepMu.RUnlock()
	}
}

func (sl *stepLoop) addClients(count int) {
	for i := 0; i < count; i++ {
		nextPoll := sl.startTime.Add(sl.randomDuration(24 * time.Hour))
		sl.clients[i] = &ghostClient{clientID: i, nextPollAt: nextPoll}
	}
	sl.nextClientID = count
}
