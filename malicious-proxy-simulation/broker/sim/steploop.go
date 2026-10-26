package sim

import (
	"log"
	mathrand "math/rand"
	"sort"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
)

const (
	defaultClientCount       = 30800 * 2
	defaultClientInterval    = 3 * time.Second
	defaultClientMaxRetries  = 5
	defaultClientPollJitter  = 1 * time.Hour
	defaultClientSpawnSpread = 1 * time.Hour
	defaultProberInterval    = 1 * time.Second
	defaultStandalonePoll    = 5 * time.Second
	defaultWebextPoll        = 60 * time.Second
	defaultIPTPoll           = 120 * time.Second
	defaultMatchedProxyWait  = 3 * time.Hour
	defaultMatchedClientWait = 3 * time.Hour
	defaultChurnRate         = 0.027
	defaultStandaloneChurnK  = 0.5
	proxySpreadWindow        = 24 * time.Hour
)

func newStepLoop(sim *ProxyPollSimulator, startTime time.Time, step time.Duration) *stepLoop {
	if step <= 0 {
		step = time.Second
	}
	standalonePoll := time.Duration(max(1, getEnvInt("SNOWFLAKE_SIM_STANDALONE_POLL_SEC", int(defaultStandalonePoll.Seconds())))) * time.Second
	webextPoll := time.Duration(max(1, getEnvInt("SNOWFLAKE_SIM_WEBEXT_POLL_SEC", int(defaultWebextPoll.Seconds())))) * time.Second
	iptPoll := time.Duration(max(1, getEnvInt("SNOWFLAKE_SIM_IPTPROXY_POLL_SEC", int(defaultIPTPoll.Seconds())))) * time.Second
	matchedProxyWait := time.Duration(max(1, getEnvInt("SNOWFLAKE_SIM_MATCHED_PROXY_WAIT_SEC", int(defaultMatchedProxyWait.Seconds())))) * time.Second
	matchedClientWait := time.Duration(max(1, getEnvInt("SNOWFLAKE_SIM_MATCHED_CLIENT_WAIT_SEC", int(defaultMatchedClientWait.Seconds())))) * time.Second
	connectionMeanWait := time.Duration(max(1, getEnvInt("SNOWFLAKE_SIM_CONNECTION_MEAN_SEC", int(defaultMatchedProxyWait.Seconds())))) * time.Second
	connectionStddevSec := getEnvFloat("SNOWFLAKE_SIM_CONNECTION_STDDEV_SEC", 0.0)
	if connectionStddevSec < 0 {
		connectionStddevSec = 0
	}
	connectionStddevWait := time.Duration(connectionStddevSec * float64(time.Second))
	churnRatePct := getEnvFloat("SNOWFLAKE_SIM_CHURN_RATE_PCT", defaultChurnRate*100.0)
	if churnRatePct < 0 {
		churnRatePct = 0
	}
	churnRateBase := churnRatePct / 100.0
	proxyCountScale := getEnvFloat("SNOWFLAKE_SIM_PROXY_COUNT_SCALE", 1.0)
	if proxyCountScale < 0 {
		proxyCountScale = 0
	}
	standaloneUnrestricted := getEnvFloat("SNOWFLAKE_SIM_STANDALONE_UNRESTRICTED_PCT", 90.0) / 100.0
	if standaloneUnrestricted < 0 {
		standaloneUnrestricted = 0
	}
	if standaloneUnrestricted > 1 {
		standaloneUnrestricted = 1
	}
	webIPTUnrestricted := getEnvFloat("SNOWFLAKE_SIM_WEBIPT_UNRESTRICTED_PCT", 10.0) / 100.0
	if webIPTUnrestricted < 0 {
		webIPTUnrestricted = 0
	}
	if webIPTUnrestricted > 1 {
		webIPTUnrestricted = 1
	}
	proxyPollJitterPct := getEnvFloat("SNOWFLAKE_SIM_PROXY_POLL_JITTER_PCT", 0.0)
	if proxyPollJitterPct < 0 {
		proxyPollJitterPct = 0
	}
	if proxyPollJitterPct > 95 {
		proxyPollJitterPct = 95
	}
	attackerCount := max(0, getEnvInt("SNOWFLAKE_SIM_ATTACKER_COUNT", 2))
	proberStartHours := getEnvInt("SNOWFLAKE_SIM_PROBER_START_HOURS", 24)
	if proberStartHours < 0 {
		proberStartHours = 0
	}
	clientTargetCount := getEnvInt("SNOWFLAKE_SIM_CLIENT_TARGET_COUNT", defaultClientCount)
	if clientTargetCount < 1 {
		clientTargetCount = defaultClientCount
	}
	clientPollJitter := time.Duration(max(0, getEnvInt("SNOWFLAKE_SIM_CLIENT_POLL_JITTER_SEC", int(defaultClientPollJitter.Seconds())))) * time.Second
	clientSpawnSpread := time.Duration(max(0, getEnvInt("SNOWFLAKE_SIM_CLIENT_SPAWN_SPREAD_SEC", int(defaultClientSpawnSpread.Seconds())))) * time.Second
	clientResultBuffer := getEnvInt("SNOWFLAKE_SIM_CLIENT_RESULT_BUFFER", 0)
	if clientResultBuffer < 0 {
		clientResultBuffer = 0
	}
	loop := &stepLoop{
		sim:                    sim,
		startTime:              startTime,
		step:                   step,
		natTypes:               []string{"unrestricted", "restricted"},
		proxies:                map[string]map[int]*ghostProxy{"standalone": {}, "webext": {}, "iptproxy": {}},
		nextProxyID:            map[string]int{"standalone": 0, "webext": 0, "iptproxy": 0},
		clients:                make(map[int]*ghostClient),
		clientTargetCount:      clientTargetCount,
		clientReplenishHour:    getEnvBool("SNOWFLAKE_SIM_CLIENT_REPLENISH_HOURLY", true),
		clientImmediateRespawn: getEnvBool("SNOWFLAKE_SIM_CLIENT_IMMEDIATE_RESPAWN", true),
		clientPollJitter:       clientPollJitter,
		clientSpawnSpread:      clientSpawnSpread,
		clientInterval:         defaultClientInterval,
		clientMaxRetries:       max(1, getEnvInt("SNOWFLAKE_SIM_CLIENT_MAX_RETRIES", defaultClientMaxRetries)),
		spreadHourlyChurn:      getEnvBool("SNOWFLAKE_SIM_SPREAD_HOURLY_CHURN", true),
		proberInterval:         defaultProberInterval,
		proberStartAt:          startTime.Add(time.Duration(proberStartHours) * time.Hour),
		attackers:              make([]*ghostAttacker, 0, attackerCount),
		standalonePollInterval: standalonePoll,
		webextPollInterval:     webextPoll,
		iptPollInterval:        iptPoll,
		matchedProxyWait:       matchedProxyWait,
		matchedClientWait:      matchedClientWait,
		connectionMeanWait:     connectionMeanWait,
		connectionStddevWait:   connectionStddevWait,
		churnRateBase:          churnRateBase,
		proxyCountScale:        proxyCountScale,
		standaloneUnrestricted: standaloneUnrestricted,
		webIPTUnrestricted:     webIPTUnrestricted,
		proxyPollJitterPct:     proxyPollJitterPct,
		proxyPollsByType: map[string]int64{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		clientMatchesByType: map[string]int64{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		clientBlockedByType: map[string]int64{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		attackerPollsByNAT: map[string]int64{
			"unrestricted": 0,
			"restricted":   0,
		},
		pendingTargetStart: map[string]int{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		pendingTargetStop: map[string]int{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		pendingChurnStart: map[string]int{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		pendingChurnStop: map[string]int{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		blockedRetryByAttempt: make(map[int]int64),
		totalRetryByAttempt:   make(map[int]int64),
		clientRetryEventsByNAT: map[string]int64{
			"unrestricted": 0,
			"restricted":   0,
		},
		clientBlockedRetriesByNAT: map[string]int64{
			"unrestricted": 0,
			"restricted":   0,
		},
		minuteProxyPollSet:               make(map[string]struct{}),
		minuteClientAttemptsByNAT:        make(map[string]int64),
		minuteClientRetriesByNAT:         make(map[string]int64),
		minuteSumRetriesBeforeMatchByNAT: make(map[string]int64),
		minuteMatchCountByNAT:            make(map[string]int64),
		maliciousProxyEnabled:            getEnvBool("SNOWFLAKE_SIM_MALICIOUS_PROXY", false),
		maliciousProxyUnrestrictedID:     -1,
		maliciousProxyRestrictedID:       -1,
		pollLogs:                         getEnvBool("SNOWFLAKE_SIM_POLL_LOGS", true),
		proxyResults:                     make(chan proxyPollResult, max(1024, getEnvInt("SNOWFLAKE_SIM_PROXY_RESULT_BUFFER", 16384))),
		attackerResults:                  make(chan attackerPollResult, max(64, getEnvInt("SNOWFLAKE_SIM_ATTACKER_RESULT_BUFFER", 2048))),
		clientResultsUnbounded:           clientResultBuffer == 0,
		stepYieldRounds:                  max(0, getEnvInt("SNOWFLAKE_SIM_STEP_YIELD_ROUNDS", 1)),
		stepSettleRounds:                 max(0, getEnvInt("SNOWFLAKE_SIM_STEP_SETTLE_ROUNDS", 0)),
		proxyTypeOrder:                   []string{"standalone", "webext", "iptproxy"},
	}
	if clientResultBuffer > 0 {
		loop.clientResults = make(chan clientPollResult, max(1, clientResultBuffer))
	}
	seed := int64(getEnvInt("SNOWFLAKE_SIM_POLL_RANDOM_SEED", int(time.Now().Unix())))
	if seed == 0 {
		seed = 1
	}
	log.Printf("Using poll random seed: %d", seed)
	loop.pollRandSeed = seed
	loop.pollRand = mathrand.New(mathrand.NewSource(seed))
	for i := 0; i < attackerCount; i++ {
		nat := loop.natTypes[i%len(loop.natTypes)]
		loop.attackers = append(loop.attackers, &ghostAttacker{
			attackerID: i + 1,
			natType:    nat,
			nextPollAt: loop.proberStartAt,
		})
	}
	return loop
}

func spreadOffset(i, count int, window time.Duration) time.Duration {
	if count <= 1 {
		return 0
	}
	interval := window / time.Duration(count)
	if interval < time.Second {
		interval = time.Second
	}
	return time.Duration(i) * interval
}

func (sl *stepLoop) scaledCount(base int) int {
	if base <= 0 {
		return 0
	}
	scaled := int(float64(base)*sl.proxyCountScale + 0.5)
	if scaled < 1 {
		scaled = 1
	}
	return scaled
}

func (sl *stepLoop) targetCount(proxyType string, hoursElapsed int) int {
	dailyCounts := targetCountConfig[proxyType]
	if len(dailyCounts) == 0 {
		return 0
	}
	base := dailyCounts[hoursElapsed%len(dailyCounts)]
	return sl.scaledCount(base)
}

func (sl *stepLoop) jitteredInterval(base time.Duration) time.Duration {
	if base <= 0 || sl.proxyPollJitterPct <= 0 {
		return base
	}
	amp := sl.proxyPollJitterPct / 100.0
	minFactor := 1.0 - amp
	maxFactor := 1.0 + amp
	factor := minFactor + sl.pollRand.Float64()*(maxFactor-minFactor)
	jittered := time.Duration(float64(base) * factor)
	if jittered < time.Second {
		return time.Second
	}
	return jittered
}

func (sl *stepLoop) sampleConnectionDuration() time.Duration {
	mean := sl.connectionMeanWait
	if mean <= 0 {
		mean = defaultMatchedProxyWait
	}
	stddev := sl.connectionStddevWait
	if stddev <= 0 {
		return mean
	}
	meanSec := float64(mean) / float64(time.Second)
	stddevSec := float64(stddev) / float64(time.Second)
	if stddevSec <= 0 {
		return mean
	}
	sampledSec := meanSec + sl.pollRand.NormFloat64()*stddevSec
	if sampledSec < 1.0 {
		sampledSec = 1.0
	}
	maxSec := meanSec + 6.0*stddevSec
	if maxSec < 1.0 {
		maxSec = 1.0
	}
	if sampledSec > maxSec {
		sampledSec = maxSec
	}
	return time.Duration(sampledSec * float64(time.Second))
}

func (sl *stepLoop) firstPollOffsetForNewClient() time.Duration {
	window := sl.clientSpawnSpread
	if window <= 0 {
		window = sl.clientInterval
	}
	offset := sl.randomDuration(window)
	if offset < sl.step {
		offset = sl.step
	}
	return offset
}

func (sl *stepLoop) addClientsNow(now time.Time, count int) {
	if count <= 0 {
		return
	}
	for i := 0; i < count; i++ {
		clientID := sl.nextClientID
		sl.nextClientID++
		offset := sl.firstPollOffsetForNewClient()
		sl.clients[clientID] = &ghostClient{
			clientID:   clientID,
			nextPollAt: now.Add(offset),
		}
	}
	sl.clientRespawnedTotal += int64(count)
}

func sortedProxyIDs(m map[int]*ghostProxy) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// sortedStoppableProxyIDs is like sortedProxyIDs but omits the malicious proxy (never stopped by churn/target).
func sortedStoppableProxyIDs(m map[int]*ghostProxy) []int {
	ids := make([]int, 0, len(m))
	for id, p := range m {
		if p != nil && p.malicious {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func (sl *stepLoop) stopProxy(now time.Time, proxyType string, proxyID int) {
	p, ok := sl.proxies[proxyType][proxyID]
	if !ok || p == nil || p.malicious {
		return
	}
	delete(sl.proxies[proxyType], proxyID)
	clientIDs := sl.sim.getConnectedClients(proxyType, proxyID)
	for _, clientID := range clientIDs {
		if c, ok := sl.clients[clientID]; ok {
			c.nextPollAt = now.Add(sl.clientInterval)
		}
		if state, exists := sl.sim.clientStates[clientID]; exists {
			state.mu.Lock()
			state.currentProxyID = -1
			state.currentProxyType = ""
			state.currentSession = ""
			state.waitRemaining = 0
			state.waitUntil = time.Time{}
			state.mu.Unlock()
		}
	}
}

func (sl *stepLoop) addProxyNow(now time.Time, proxyType string) {
	id := sl.nextProxyID[proxyType]
	sl.nextProxyID[proxyType]++

	p := &ghostProxy{
		proxyID:      id,
		proxyType:    proxyType,
		nextPollAt:   now,
		pollInterval: sl.webextPollInterval,
	}
	if proxyType == "standalone" {
		p.pollInterval = sl.standalonePollInterval
		p.standaloneNAT = pickByProbability(sl.natTypes, sl.standaloneUnrestricted)
	} else if proxyType == "iptproxy" {
		p.pollInterval = sl.iptPollInterval
	}
	sl.proxies[proxyType][id] = p

	FakeTimeStepMu.RLock()
	sl.sim.recordProxyStart(proxyType, id)
	FakeTimeStepMu.RUnlock()
}

func (sl *stepLoop) applyTargetCounts(now time.Time, hoursElapsed int) {
	for proxyType := range targetCountConfig {
		target := sl.targetCount(proxyType, hoursElapsed)
		actual := len(sl.proxies[proxyType])
		if target > actual {
			for i := 0; i < target-actual; i++ {
				sl.addProxyNow(now, proxyType)
			}
			log.Printf("Target(step): started %d new %s proxies (target=%d, was=%d)", target-actual, proxyType, target, actual)
		} else if target < actual {
			toStop := actual - target
			ids := sortedStoppableProxyIDs(sl.proxies[proxyType])
			nStop := toStop
			if nStop > len(ids) {
				nStop = len(ids)
			}
			for i := 0; i < nStop; i++ {
				id := ids[len(ids)-1-i]
				sl.stopProxy(now, proxyType, id)
			}
			log.Printf("Target(step): stopped %d %s proxies (target=%d, was=%d)", toStop, proxyType, target, actual)
		}
	}
}

func (sl *stepLoop) applyChurn(now time.Time) {
	if sl.churnRateBase <= 0 {
		return
	}
	for proxyType, proxies := range sl.proxies {
		if len(proxies) == 0 {
			continue
		}
		rate := sl.churnRateBase
		if proxyType == "standalone" {
			rate = sl.churnRateBase * defaultStandaloneChurnK
		}
		if rate <= 0 {
			continue
		}
		toStop := int(float64(len(proxies)) * rate)
		if toStop < 1 {
			toStop = 1
		}
		if toStop > len(proxies) {
			toStop = len(proxies)
		}
		ids := sortedStoppableProxyIDs(proxies)
		nStop := toStop
		if nStop > len(ids) {
			nStop = len(ids)
		}
		for i := 0; i < nStop; i++ {
			id := ids[len(ids)-1-i]
			sl.stopProxy(now, proxyType, id)
		}
		for i := 0; i < toStop; i++ {
			sl.addProxyNow(now, proxyType)
		}
		log.Printf("Churn(step): stopped %d and started %d new %s proxies", toStop, toStop, proxyType)
	}
}

func (sl *stepLoop) projectedProxyCount(proxyType string) int {
	current := len(sl.proxies[proxyType])
	projected := current + sl.pendingTargetStart[proxyType] - sl.pendingTargetStop[proxyType] + sl.pendingChurnStart[proxyType] - sl.pendingChurnStop[proxyType]
	if projected < 0 {
		return 0
	}
	return projected
}

func (sl *stepLoop) churnRateForType(proxyType string) float64 {
	if sl.churnRateBase < 0 {
		return 0
	}
	return sl.churnRateBase
}

func churnCountForSize(size int, rate float64) int {
	if size <= 0 || rate <= 0 {
		return 0
	}
	toChurn := int(float64(size) * rate)
	if toChurn < 1 {
		toChurn = 1
	}
	if toChurn > size {
		toChurn = size
	}
	return toChurn
}

func (sl *stepLoop) scheduleSpreadHourlyEvents(hour int) {
	for proxyType := range targetCountConfig {
		target := sl.targetCount(proxyType, hour)
		projected := sl.projectedProxyCount(proxyType)
		if target > projected {
			sl.pendingTargetStart[proxyType] += target - projected
		} else if target < projected {
			sl.pendingTargetStop[proxyType] += projected - target
		}
	}
	if sl.churnRateBase > 0 {
		for proxyType := range targetCountConfig {
			projectedAfterTarget := sl.projectedProxyCount(proxyType)
			churnCount := churnCountForSize(projectedAfterTarget, sl.churnRateForType(proxyType))
			if churnCount <= 0 {
				continue
			}
			sl.pendingChurnStop[proxyType] += churnCount
			sl.pendingChurnStart[proxyType] += churnCount
		}
	}
	log.Printf(
		"Scheduled hourly spread events hour=%d target_start standalone=%d webext=%d iptproxy=%d target_stop standalone=%d webext=%d iptproxy=%d churn_start standalone=%d webext=%d iptproxy=%d churn_stop standalone=%d webext=%d iptproxy=%d",
		hour,
		sl.pendingTargetStart["standalone"],
		sl.pendingTargetStart["webext"],
		sl.pendingTargetStart["iptproxy"],
		sl.pendingTargetStop["standalone"],
		sl.pendingTargetStop["webext"],
		sl.pendingTargetStop["iptproxy"],
		sl.pendingChurnStart["standalone"],
		sl.pendingChurnStart["webext"],
		sl.pendingChurnStart["iptproxy"],
		sl.pendingChurnStop["standalone"],
		sl.pendingChurnStop["webext"],
		sl.pendingChurnStop["iptproxy"],
	)
}

func (sl *stepLoop) scheduledOpsThisStep(pending, remainingSteps int) int {
	if pending <= 0 {
		return 0
	}
	if remainingSteps <= 1 {
		return pending
	}
	base := pending / remainingSteps
	rem := pending % remainingSteps
	ops := base
	if rem > 0 && sl.pollRand.Intn(remainingSteps) < rem {
		ops++
	}
	if ops > pending {
		ops = pending
	}
	return ops
}

func (sl *stepLoop) pickProxyIDsForRemoval(proxyType string, count int) []int {
	if count <= 0 {
		return nil
	}
	ids := sortedStoppableProxyIDs(sl.proxies[proxyType])
	if len(ids) == 0 {
		return nil
	}
	if count > len(ids) {
		count = len(ids)
	}
	out := make([]int, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, ids[len(ids)-1-i])
	}
	return out
}

func (sl *stepLoop) applyScheduledStops(now time.Time, proxyType string, pending map[string]int, remainingSteps int) {
	queued := pending[proxyType]
	if queued <= 0 {
		return
	}
	ops := sl.scheduledOpsThisStep(queued, remainingSteps)
	if ops <= 0 {
		return
	}
	if ops > len(sl.proxies[proxyType]) {
		ops = len(sl.proxies[proxyType])
	}
	if ops <= 0 {
		return
	}
	ids := sl.pickProxyIDsForRemoval(proxyType, ops)
	for _, id := range ids {
		sl.stopProxy(now, proxyType, id)
	}
	pending[proxyType] -= len(ids)
	if pending[proxyType] < 0 {
		pending[proxyType] = 0
	}
}

func (sl *stepLoop) applyScheduledStarts(now time.Time, proxyType string, pending map[string]int, remainingSteps int) {
	queued := pending[proxyType]
	if queued <= 0 {
		return
	}
	ops := sl.scheduledOpsThisStep(queued, remainingSteps)
	if ops <= 0 {
		return
	}
	for i := 0; i < ops; i++ {
		sl.addProxyNow(now, proxyType)
	}
	pending[proxyType] -= ops
	if pending[proxyType] < 0 {
		pending[proxyType] = 0
	}
}

func (sl *stepLoop) applySpreadHourlyEvents(now time.Time) {
	if !sl.spreadHourlyChurn {
		return
	}
	nextHour := now.Truncate(time.Hour).Add(time.Hour)
	remainingSteps := int(nextHour.Sub(now) / sl.step)
	if remainingSteps < 1 {
		remainingSteps = 1
	}
	for _, proxyType := range sl.proxyTypeOrder {
		sl.applyScheduledStops(now, proxyType, sl.pendingTargetStop, remainingSteps)
		sl.applyScheduledStops(now, proxyType, sl.pendingChurnStop, remainingSteps)
		sl.applyScheduledStarts(now, proxyType, sl.pendingTargetStart, remainingSteps)
		sl.applyScheduledStarts(now, proxyType, sl.pendingChurnStart, remainingSteps)
	}
}

func (sl *stepLoop) applyHourlyEvents(now time.Time) {
	hoursElapsed := int(now.Sub(sl.startTime).Hours())
	for sl.lastAppliedHour < hoursElapsed {
		sl.lastAppliedHour++
		if sl.spreadHourlyChurn {
			sl.scheduleSpreadHourlyEvents(sl.lastAppliedHour)
		} else {
			sl.applyTargetCounts(now, sl.lastAppliedHour)
			sl.applyChurn(now)
		}
		if sl.clientReplenishHour {
			deficit := sl.clientTargetCount - len(sl.clients)
			if deficit > 0 {
				sl.addClientsNow(now, deficit)
				log.Printf("Target(step): started %d new clients (target=%d, was=%d)", deficit, sl.clientTargetCount, sl.clientTargetCount-deficit)
			}
		}
		sl.sim.churnCycles.Add(1)
	}
	sl.applySpreadHourlyEvents(now)
}

func (sl *stepLoop) pollProxy(p *ghostProxy) bool {
	if p.inFlight {
		return false
	}
	if sl.pollLogs && !p.malicious {
		log.Printf("%s proxy %d polling counter: %d", p.proxyType, p.proxyID, p.pollCounter)
	}
	sl.totalProxyPolls++
	sl.proxyPollsByType[p.proxyType]++
	sessionID := generateSessionID(p.proxyType, p.proxyID)
	natType := p.standaloneNAT
	if p.proxyType != "standalone" {
		natType = pickByProbability(sl.natTypes, sl.webIPTUnrestricted)
	}
	clients := 1 + p.pollCounter
	// Malicious proxies reschedule the next poll to the current step, so they poll far more often
	// than normal standalones (standalonePollInterval). The broker picks proxies with minimum
	// reported clients first; without this, pollCounter-driven clients would grow without bound
	// and malicious IDs would almost never be matched after warmup, so match_events would read 0.
	if p.malicious {
		clients = -1
	}
	relayPattern := "^0\\.0\\.0\\.0$"
	p.inFlight = true
	p.pollCounter++
	proxyType := p.proxyType
	proxyID := p.proxyID
	pollInterval := p.pollInterval

	go func() {
		result := proxyPollResult{
			proxyType:    proxyType,
			proxyID:      proxyID,
			sessionID:    sessionID,
			pollInterval: pollInterval,
		}
		matched, isProber, _ := sl.sim.RunProxyPoll(sessionID, proxyType, natType, clients, relayPattern, func(arg messages.Arg) ([]byte, error) {
			var response []byte
			if err := sl.sim.callProxyPolls(arg, &response); err != nil {
				return nil, err
			}
			return response, nil
		})

		result.matched = matched
		result.isProber = isProber
		if matched {
			answerSDP := CreateTestSDP()
			sl.sim.SimulateProxyAnswer(answerSDP, sessionID)
		}
		sl.proxyResults <- result
	}()
	return true
}

func (sl *stepLoop) pollClient(now time.Time, c *ghostClient) {
	if c.inFlight {
		return
	}
	if sl.pollLogs {
		log.Printf("Client %d polling counter: %d", c.clientID, c.pollCounter)
	}
	sl.totalClientPolls++
	sdp := CreateTestSDP()
	natType := pickByProbability(sl.natTypes, 0.72)
	fingerprint := CreateTestFingerprint()

	c.inFlight = true
	clientID := c.clientID
	go func() {
		matched, sid, reason, runErr := sl.sim.RunClientOffer(clientID, sdp, natType, fingerprint)
		sl.pushClientResult(clientPollResult{
			clientID: clientID,
			natType:  natType,
			sdp:      sdp,
			polledAt: now,
			err:      runErr,
			matched:  matched,
			sid:      sid,
			reason:   reason,
		})
	}()
}

func (sl *stepLoop) pollProber(now time.Time, attacker *ghostAttacker) {
	if attacker == nil || attacker.inFlight {
		return
	}
	if sl.pollLogs {
		log.Printf("Prober %d %s polling counter: %d", attacker.attackerID, attacker.natType, attacker.pollCounter)
	}
	sl.totalProberPolls++
	sl.attackerPollsByNAT[attacker.natType]++
	attacker.pollCounter++
	attacker.nextPollAt = now.Add(sl.proberInterval)
	attacker.inFlight = true
	attackerID := attacker.attackerID
	natType := attacker.natType
	polledAt := now
	go func() {
		sdp := CreateProberSDP()
		fingerprint := CreateTestFingerprint()
		matched, sid, _, err := sl.sim.RunClientOffer(-1, sdp, natType, fingerprint)
		sl.attackerResults <- attackerPollResult{
			attackerID: attackerID,
			natType:    natType,
			polledAt:   polledAt,
			matched:    matched,
			sid:        sid,
			err:        err,
		}
	}()
}

func (sl *stepLoop) attackerByID(attackerID int) *ghostAttacker {
	for _, attacker := range sl.attackers {
		if attacker != nil && attacker.attackerID == attackerID {
			return attacker
		}
	}
	return nil
}

func (sl *stepLoop) activeConnectionCount() int {
	sl.sim.connectionLock.Lock()
	defer sl.sim.connectionLock.Unlock()
	return len(sl.sim.connections)
}

func (sl *stepLoop) logStepSummary(now time.Time) {
	standalone := len(sl.proxies["standalone"])
	webext := len(sl.proxies["webext"])
	ipt := len(sl.proxies["iptproxy"])
	totalProxies := standalone + webext + ipt
	matchesStandalone := sl.clientMatchesByType["standalone"]
	matchesWebext := sl.clientMatchesByType["webext"]
	matchesIPT := sl.clientMatchesByType["iptproxy"]
	matchesTotal := matchesStandalone + matchesWebext + matchesIPT
	blockedStandalone := sl.clientBlockedByType["standalone"]
	blockedWebext := sl.clientBlockedByType["webext"]
	blockedIPT := sl.clientBlockedByType["iptproxy"]
	blockedTotal := blockedStandalone + blockedWebext + blockedIPT
	blockedRetryAttempts, blockedRetryAvgPerAttempt, blockedRetryP25, blockedRetryP50, blockedRetryP75, blockedRetryP99 := retryAttemptStats(sl.blockedRetryByAttempt)
	totalRetryAttempts, totalRetryAvgPerAttempt, totalRetryP25, totalRetryP50, totalRetryP75, totalRetryP99 := retryAttemptStats(sl.totalRetryByAttempt)
	uniqueClientsSeen := sl.nextClientID
	uniqueStandaloneSeen := sl.nextProxyID["standalone"]
	uniqueWebextSeen := sl.nextProxyID["webext"]
	uniqueIPTSeen := sl.nextProxyID["iptproxy"]
	uniqueProxiesSeen := uniqueStandaloneSeen + uniqueWebextSeen + uniqueIPTSeen
	proxyPollStandalone := sl.proxyPollsByType["standalone"]
	proxyPollWebext := sl.proxyPollsByType["webext"]
	proxyPollIPT := sl.proxyPollsByType["iptproxy"]
	attackerUnrestricted := sl.attackerPollsByNAT["unrestricted"]
	attackerRestricted := sl.attackerPollsByNAT["restricted"]
	attackerUniqueObservedTotal, attackerUniqueObservedByType, attackerObservedByNATAndType := sl.sim.getAttackerObservedCounts()
	attackerFoundNT := func(nat, proxyType string) int64 {
		m := attackerObservedByNATAndType[nat]
		if m == nil {
			return 0
		}
		return m[proxyType]
	}
	clientRetryU := sl.clientRetryEventsByNAT["unrestricted"]
	clientRetryR := sl.clientRetryEventsByNAT["restricted"]
	clientRetryUnknown := sl.clientRetryEventsByNAT["unknown"]
	clientBlockedU := sl.clientBlockedRetriesByNAT["unrestricted"]
	clientBlockedR := sl.clientBlockedRetriesByNAT["restricted"]
	clientBlockedUnknown := sl.clientBlockedRetriesByNAT["unknown"]
	log.Printf(
		"step-summary t=%s clients=%d proxies_total=%d standalone=%d webext=%d iptproxy=%d unique_seen clients=%d proxies_total=%d proxies standalone=%d webext=%d iptproxy=%d connected=%d polls_total client=%d proxy=%d attacker=%d proxy_polls standalone=%d webext=%d iptproxy=%d matches_total=%d matches standalone=%d webext=%d iptproxy=%d blocked_matches_total=%d blocked_matches standalone=%d webext=%d iptproxy=%d blocked_retry_events=%d blocked_retry_attempts=%d blocked_retry_avg_per_attempt=%.3f blocked_retry_attempt_p25=%.3f blocked_retry_attempt_p50=%.3f blocked_retry_attempt_p75=%.3f blocked_retry_attempt_p99=%.3f total_retry_events=%d total_retry_attempts=%d total_retry_avg_per_attempt=%.3f total_retry_attempt_p25=%.3f total_retry_attempt_p50=%.3f total_retry_attempt_p75=%.3f total_retry_attempt_p99=%.3f client_nomatch_total=%d client_nomatch_reasons no_proxies=%d timed_out=%d blocked=%d other=%d retry_limit_hits clients=%d client_respawned_total=%d attacker_polls unrestricted=%d restricted=%d attacker_unique_proxies_total=%d attacker_unique_proxies standalone=%d webext=%d iptproxy=%d",
		now.Format(time.RFC3339),
		len(sl.clients),
		totalProxies,
		standalone,
		webext,
		ipt,
		uniqueClientsSeen,
		uniqueProxiesSeen,
		uniqueStandaloneSeen,
		uniqueWebextSeen,
		uniqueIPTSeen,
		sl.activeConnectionCount(),
		sl.totalClientPolls,
		sl.totalProxyPolls,
		sl.totalProberPolls,
		proxyPollStandalone,
		proxyPollWebext,
		proxyPollIPT,
		matchesTotal,
		matchesStandalone,
		matchesWebext,
		matchesIPT,
		blockedTotal,
		blockedStandalone,
		blockedWebext,
		blockedIPT,
		sl.blockedRetryEvents,
		blockedRetryAttempts,
		blockedRetryAvgPerAttempt,
		blockedRetryP25,
		blockedRetryP50,
		blockedRetryP75,
		blockedRetryP99,
		sl.totalRetryEvents,
		totalRetryAttempts,
		totalRetryAvgPerAttempt,
		totalRetryP25,
		totalRetryP50,
		totalRetryP75,
		totalRetryP99,
		sl.clientNoMatches,
		sl.clientNoMatchByNoPx,
		sl.clientNoMatchByTO,
		sl.clientNoMatchByBlock,
		sl.clientNoMatchByOther,
		sl.clientRetryLimitHits,
		sl.clientRespawnedTotal,
		attackerUnrestricted,
		attackerRestricted,
		attackerUniqueObservedTotal,
		attackerUniqueObservedByType["standalone"],
		attackerUniqueObservedByType["webext"],
		attackerUniqueObservedByType["iptproxy"],
	)
	log.Printf(
		"step-summary-client-nat t=%s client_retry_events unrestricted=%d restricted=%d unknown=%d client_blocked_retries unrestricted=%d restricted=%d unknown=%d",
		now.Format(time.RFC3339),
		clientRetryU,
		clientRetryR,
		clientRetryUnknown,
		clientBlockedU,
		clientBlockedR,
		clientBlockedUnknown,
	)
	log.Printf(
		"step-summary-attacker-found t=%s attacker_unique_by_nat unrestricted=%d restricted=%d unknown=%d attacker_unique_proxies_by_nat unrestricted_standalone=%d unrestricted_webext=%d unrestricted_iptproxy=%d restricted_standalone=%d restricted_webext=%d restricted_iptproxy=%d unknown_standalone=%d unknown_webext=%d unknown_iptproxy=%d",
		now.Format(time.RFC3339),
		attackerFoundNT("unrestricted", "standalone")+attackerFoundNT("unrestricted", "webext")+attackerFoundNT("unrestricted", "iptproxy"),
		attackerFoundNT("restricted", "standalone")+attackerFoundNT("restricted", "webext")+attackerFoundNT("restricted", "iptproxy"),
		attackerFoundNT("unknown", "standalone")+attackerFoundNT("unknown", "webext")+attackerFoundNT("unknown", "iptproxy"),
		attackerFoundNT("unrestricted", "standalone"),
		attackerFoundNT("unrestricted", "webext"),
		attackerFoundNT("unrestricted", "iptproxy"),
		attackerFoundNT("restricted", "standalone"),
		attackerFoundNT("restricted", "webext"),
		attackerFoundNT("restricted", "iptproxy"),
		attackerFoundNT("unknown", "standalone"),
		attackerFoundNT("unknown", "webext"),
		attackerFoundNT("unknown", "iptproxy"),
	)
	sl.logBrokerSnowflakeHeapSummary(now)
}

// logBrokerSnowflakeHeapSummary logs real broker SnowflakeHeap sizes (broker/snowflake-heap.go) and, among
// heap session IDs that parse as sim proxy keys, the share not yet in global attacker enumeration.
func (sl *stepLoop) logBrokerSnowflakeHeapSummary(now time.Time) {
	u, r, ids := sl.sim.ipc.SnowflakeHeapSnapshot()
	parseable := 0
	neverSeen := 0
	for _, sid := range ids {
		pt, pid, ok := parseProxyIDFromSession(sid)
		if !ok {
			continue
		}
		parseable++
		if !sl.sim.AttackerHasObservedProxy(proxyPollKey(pt, pid)) {
			neverSeen++
		}
	}
	var pct float64
	if parseable > 0 {
		pct = 100.0 * float64(neverSeen) / float64(parseable)
	}
	log.Printf(
		"step-summary-broker-heaps t=%s snowflake_heap_unrestricted=%d snowflake_heap_restricted=%d snowflake_heap_total=%d snowflake_heap_parseable=%d snowflake_heap_never_seen_by_any_attacker=%d pct_snowflake_heap_never_seen_by_any_attacker=%.4f",
		now.Format(time.RFC3339),
		u,
		r,
		u+r,
		parseable,
		neverSeen,
		pct,
	)
}

func (sl *stepLoop) logAttackerSummary(now time.Time) {
	nextPoll := ""
	if len(sl.attackers) > 0 {
		soonest := sl.attackers[0].nextPollAt
		for _, attacker := range sl.attackers[1:] {
			if attacker.nextPollAt.Before(soonest) {
				soonest = attacker.nextPollAt
			}
		}
		nextPoll = soonest.Format(time.RFC3339)
	}
	log.Printf(
		"attacker-summary t=%s mode=%s attackers=%d total_probes=%d unrestricted=%d restricted=%d next_poll=%s",
		now.Format(time.RFC3339),
		sl.sim.attackModeLabel(),
		len(sl.attackers),
		sl.totalProberPolls,
		sl.attackerPollsByNAT["unrestricted"],
		sl.attackerPollsByNAT["restricted"],
		nextPoll,
	)
}

func (sl *stepLoop) dispatchDueProxyPolls(now time.Time) {
	if len(sl.proxyTypeOrder) == 0 {
		return
	}

	dueByType := make(map[string][]int, len(sl.proxyTypeOrder))
	totalDue := 0
	for _, proxyType := range sl.proxyTypeOrder {
		for id, p := range sl.proxies[proxyType] {
			if p == nil || p.inFlight || p.nextPollAt.After(now) {
				continue
			}
			dueByType[proxyType] = append(dueByType[proxyType], id)
			totalDue++
		}
	}
	if totalDue == 0 {
		return
	}

	activeTypes := make([]string, 0, len(sl.proxyTypeOrder))
	for _, proxyType := range sl.proxyTypeOrder {
		if len(dueByType[proxyType]) > 0 {
			activeTypes = append(activeTypes, proxyType)
		}
	}
	launched := 0
	for len(activeTypes) > 0 {
		typeIdx := 0
		if len(activeTypes) > 1 {
			typeIdx = sl.pollRand.Intn(len(activeTypes))
		}
		proxyType := activeTypes[typeIdx]
		ids := dueByType[proxyType]
		if len(ids) == 0 {
			activeTypes[typeIdx] = activeTypes[len(activeTypes)-1]
			activeTypes = activeTypes[:len(activeTypes)-1]
			continue
		}

		idIdx := 0
		if len(ids) > 1 {
			idIdx = sl.pollRand.Intn(len(ids))
		}
		id := ids[idIdx]
		ids[idIdx] = ids[len(ids)-1]
		dueByType[proxyType] = ids[:len(ids)-1]
		if len(dueByType[proxyType]) == 0 {
			activeTypes[typeIdx] = activeTypes[len(activeTypes)-1]
			activeTypes = activeTypes[:len(activeTypes)-1]
		}

		p := sl.proxies[proxyType][id]
		if p == nil || p.inFlight || p.nextPollAt.After(now) {
			continue
		}
		if sl.pollProxy(p) {
			launched++
			continue
		}
	}
}

func (sl *stepLoop) pushClientResult(result clientPollResult) {
	if !sl.clientResultsUnbounded {
		sl.clientResults <- result
		return
	}
	sl.clientResultsMu.Lock()
	sl.clientResultsQueue = append(sl.clientResultsQueue, result)
	sl.clientResultsMu.Unlock()
}

func (sl *stepLoop) popClientResult() (clientPollResult, bool) {
	if !sl.clientResultsUnbounded {
		select {
		case result := <-sl.clientResults:
			return result, true
		default:
			return clientPollResult{}, false
		}
	}
	sl.clientResultsMu.Lock()
	defer sl.clientResultsMu.Unlock()
	if len(sl.clientResultsQueue) == 0 {
		return clientPollResult{}, false
	}
	last := len(sl.clientResultsQueue) - 1
	result := sl.clientResultsQueue[last]
	sl.clientResultsQueue[last] = clientPollResult{}
	sl.clientResultsQueue = sl.clientResultsQueue[:last]
	return result, true
}
