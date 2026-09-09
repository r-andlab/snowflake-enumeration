package sim

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
)

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("invalid %s=%q, using default %d", key, raw, fallback)
		return fallback
	}
	return value
}

func getEnvFloat(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		log.Printf("invalid %s=%q, using default %.4f", key, raw, fallback)
		return fallback
	}
	return value
}

func getEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		log.Printf("invalid %s=%q, using default %t", key, raw, fallback)
		return fallback
	}
}

func updateMax(counter *atomic.Int64, value int64) {
	for {
		current := counter.Load()
		if value <= current {
			return
		}
		if counter.CompareAndSwap(current, value) {
			return
		}
	}
}

func (sim *ProxyPollSimulator) recordIPCCall() func() {
	start := sim.simulationNow()
	inFlight := sim.inFlightIPCCalls.Add(1)
	updateMax(&sim.maxInFlightIPCCalls, inFlight)
	sim.blockingIPCCalls.Add(1)

	return func() {
		sim.inFlightIPCCalls.Add(-1)
		sim.totalIPCCalls.Add(1)
		sim.blockingIPCCalls.Add(-1)

		callDuration := sim.simulationNow().Sub(start)
		updateMax(&sim.maxIPCRealNanos, callDuration.Nanoseconds())
	}
}

func (sim *ProxyPollSimulator) callProxyPolls(arg messages.Arg, response *[]byte) error {
	done := sim.recordIPCCall()
	defer done()
	return sim.ipc.ProxyPolls(arg, response)
}

func (sim *ProxyPollSimulator) callClientOffers(arg messages.Arg, response *[]byte) error {
	done := sim.recordIPCCall()
	defer done()
	return sim.ipc.ClientOffers(arg, response)
}

func (sim *ProxyPollSimulator) callProxyAnswers(arg messages.Arg, response *[]byte) error {
	done := sim.recordIPCCall()
	defer done()
	return sim.ipc.ProxyAnswers(arg, response)
}

func (sim *ProxyPollSimulator) recordTimeStep(step time.Duration) {
	sim.timeSteps.Add(1)
	sim.totalAdvancedFakeNanos.Add(step.Nanoseconds())
}

func (sim *ProxyPollSimulator) logDebugSnapshot() {
	if !sim.debugMode {
		return
	}
	stats := sim.GetStats()
	log.Printf(
		"sim-debug fake_now=%s inflight_ipc=%d blocking_ipc=%d max_inflight=%d fake_timers=%d backpressure_pauses=%d steps=%d churn_cycles=%d churn_catchup=%d goroutines=%d max_goroutines=%d total_ipc=%d max_ipc_real=%s",
		sim.simulationNow().Format(time.RFC3339),
		stats.InFlightIPCCalls,
		stats.BlockingIPCCalls,
		stats.MaxInFlightIPCCalls,
		FakeTimePendingTimers(),
		stats.BackpressurePauses,
		stats.TimeSteps,
		stats.ChurnCycles,
		stats.ChurnCatchupHours,
		stats.RuntimeGoroutines,
		stats.MaxRuntimeGoroutines,
		stats.TotalIPCCalls,
		stats.MaxIPCRealDuration,
	)
}

// drainAttackerResults drains all pending attacker poll results and updates attacker state.
func (sl *stepLoop) drainAttackerResults() int {
	drained := 0
	for {
		select {
		case result := <-sl.attackerResults:
			drained++
			attacker := sl.attackerByID(result.attackerID)
			if attacker != nil {
				attacker.inFlight = false
			}
			if result.err != nil {
				log.Printf("Error simulating prober %d %s offer: %v", result.attackerID, result.natType, result.err)
				continue
			}
			if sl.sim.eventLogs && result.matched {
				log.Printf("Prober %d %s matched with proxy %s, continuing to poll", result.attackerID, result.natType, result.sid)
			} else if sl.sim.eventLogs {
				log.Printf("Prober %d %s did not match with proxy, continuing to poll", result.attackerID, result.natType)
			}
			if result.matched {
				if sl.sim.recordAttackerObservation(result.polledAt, result.attackerID, result.natType, result.sid) && attacker != nil {
					attacker.enumerated++
					attacker.lastMatchSID = result.sid
				}
			}
		default:
			return drained
		}
	}
}

func (sl *stepLoop) isMaliciousProxy(proxyType string, proxyID int) bool {
	if !sl.maliciousProxyEnabled || proxyType != "standalone" {
		return false
	}
	return proxyID == sl.maliciousProxyUnrestrictedID || proxyID == sl.maliciousProxyRestrictedID
}

// drainProxyResults drains and applies all pending proxy poll results.
func (sl *stepLoop) drainProxyResults(now time.Time) int {
	drained := 0
	for {
		select {
		case result := <-sl.proxyResults:
			drained++
			proxies, ok := sl.proxies[result.proxyType]
			if !ok {
				continue
			}
			p, ok := proxies[result.proxyID]
			if !ok || p == nil {
				continue
			}

			p.inFlight = false
			sl.recordProxyPolledInWindow(result.proxyType, result.proxyID)
			if result.err != nil {
				if sl.isMaliciousProxy(result.proxyType, result.proxyID) {
					p.nextPollAt = now
				} else {
					p.nextPollAt = now.Add(sl.jitteredInterval(result.pollInterval))
				}
				continue
			}
			if sl.isMaliciousProxy(result.proxyType, result.proxyID) {
				p.nextPollAt = now
				continue
			}
			if result.proxyType == "standalone" {
				p.nextPollAt = now.Add(sl.jitteredInterval(sl.standalonePollInterval))
			} else if result.matched && !result.isProber {
				disconnectAt, ok := sl.sim.getConnectionDisconnectAt(result.sessionID)
				if ok {
					if disconnectAt.Before(now) {
						disconnectAt = now.Add(time.Second)
					}
					p.nextPollAt = disconnectAt
				} else {
					// If the client-side match wasn't finalized (for example blocked),
					// return this proxy to its normal poll cadence.
					p.nextPollAt = now.Add(sl.jitteredInterval(result.pollInterval))
				}
			} else {
				p.nextPollAt = now.Add(sl.jitteredInterval(result.pollInterval))
			}
		default:
			return drained
		}
	}
}

func (sl *stepLoop) recordClientRetryByNAT(nat string, blockedRetry bool) {
	if nat == "" {
		nat = "unknown"
	}
	sl.clientRetryEventsByNAT[nat]++
	if blockedRetry {
		sl.clientBlockedRetriesByNAT[nat]++
	}
}

// recordMinuteClientNATStats records one completed client offer simulation for the current simulated minute window.
// isRetry is true when the outcome schedules a retry (error or no match); matched outcomes are attempts only.
func (sl *stepLoop) recordMinuteClientNATStats(nat string, isRetry bool) {
	if nat == "" {
		nat = "unknown"
	}
	sl.minuteClientAttemptsByNAT[nat]++
	if isRetry {
		sl.minuteClientRetriesByNAT[nat]++
	}
}

// drainClientResults drains and applies all pending client poll results.
func (sl *stepLoop) drainClientResults(now time.Time) int {
	drained := 0
	for {
		result, ok := sl.popClientResult()
		if !ok {
			return drained
		}
		drained++
		c, ok := sl.clients[result.clientID]
		if !ok || c == nil {
			continue
		}
		c.inFlight = false
		natKey := result.natType
		if natKey == "" {
			natKey = "unknown"
		}
		if result.err != nil {
			sl.recordMinuteClientNATStats(natKey, true)
			log.Printf("Error simulating client %d offer: %v", result.clientID, result.err)
			sl.totalRetryEvents++
			reason := result.reason
			if reason == clientNoMatchNone {
				reason = clientNoMatchOther
			}
			blocked := reason == clientNoMatchBlocked
			sl.recordClientRetryByNAT(result.natType, blocked)
			sl.recordRetryAttempt(c, blocked)
			sl.recordNoMatchReason(reason)
			if blocked {
				sl.blockedRetryEvents++
			} else {
				sl.clientNoMatches++
			}
			sl.scheduleClientRetry(now, c)
			continue
		}

		matched := result.matched
		sid := result.sid
		reason := result.reason
		proxyType, proxyID, haveProxyType := parseProxyIDFromSession(sid)
		if matched {
			sl.recordMinuteClientNATStats(natKey, false)
			// Denominator for minute-malicious-proxy: total new successful connections created in this minute.
			sl.maliciousConnTotalSum++
			if haveProxyType {
				sl.clientMatchesByType[proxyType]++
			}
			sl.minuteSumRetriesBeforeMatchByNAT[natKey] += int64(c.totalRetriesInAttempt)
			sl.minuteMatchCountByNAT[natKey]++
			sl.finalizeRetryAttempt(c)
			c.retryStreak = 0
			if sl.isMaliciousProxy(proxyType, proxyID) {
				if proxyID == sl.maliciousProxyUnrestrictedID {
					sl.maliciousConnSumUnrestricted++
				} else {
					sl.maliciousConnSumRestricted++
				}
				if sid != "" {
					sl.sim.unregisterConnection(sid)
				}
				c.nextPollAt = now.Add(sl.clientInterval)
				c.pollCounter++
				continue
			}
			connectionDuration := sl.sampleConnectionDuration()
			disconnectAt := now.Add(connectionDuration)
			if sid != "" {
				if assignedDisconnectAt, ok := sl.sim.setConnectionDuration(sid, connectionDuration); ok {
					disconnectAt = assignedDisconnectAt
				}
			}
			c.nextPollAt = disconnectAt
			c.pollCounter++
			continue
		}

		sl.recordMinuteClientNATStats(natKey, true)
		sl.totalRetryEvents++
		if reason == clientNoMatchNone {
			if haveProxyType {
				reason = clientNoMatchBlocked
			} else {
				reason = clientNoMatchOther
			}
		}
		blocked := reason == clientNoMatchBlocked
		sl.recordClientRetryByNAT(result.natType, blocked)
		sl.recordRetryAttempt(c, blocked)
		sl.recordNoMatchReason(reason)
		if blocked {
			if haveProxyType {
				sl.clientBlockedByType[proxyType]++
			}
			sl.blockedRetryEvents++
		} else {
			sl.clientNoMatches++
		}
		sl.scheduleClientRetry(now, c)
	}
}

func (sl *stepLoop) randomDuration(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	return time.Duration(sl.pollRand.Int63n(int64(window)))
}

// generateSessionID generates a session ID that includes proxy type and proxy ID
func generateSessionID(proxyType string, proxyID int) string {
	// Generate random component
	b := make([]byte, 12) // Reduced from 16 to leave room for prefix
	rand.Read(b)
	randomPart := hex.EncodeToString(b)

	// Format: {proxyType}-{proxyID}-{randomHex}
	return fmt.Sprintf("%s-%d-%s", proxyType, proxyID, randomPart)
}

// parseProxyIDFromSession extracts proxyID and proxyType from a session ID
// Returns (proxyType, proxyID, ok)
func parseProxyIDFromSession(sessionID string) (string, int, bool) {
	parts := strings.Split(sessionID, "-")
	if len(parts) < 3 {
		return "", 0, false
	}
	proxyType := parts[0]
	var proxyID int
	_, err := fmt.Sscanf(parts[1], "%d", &proxyID)
	if err != nil {
		return "", 0, false
	}
	return proxyType, proxyID, true
}

// generateRandomIP generates a random IP address for simulation
func generateRandomIP() string {
	ip := make([]byte, 4)
	rand.Read(ip)
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// CreateTestSDP creates a test SDP string for simulation
func CreateTestSDP() string {
	return "v=0\r\n" +
		"o=- 123456789 987654321 IN IP4 0.0.0.0\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=fingerprint:sha-256 12:34\r\n" +
		"a=extmap-allow-mixed\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=setup:actpass\r\n" +
		"a=mid:0\r\n" +
		"a=sendrecv\r\n" +
		"a=sctp-port:5000\r\n" +
		"a=ice-ufrag:CoVEaiFXRGVzshXG\r\n" +
		"a=ice-pwd:aOrOZXraTfFKzyeBxIXYYKjSgRVPGhUx\r\n" +
		"a=candidate:1000 1 udp 2000 8.8.8.8 3000 typ host\r\n" +
		"a=end-of-candidates\r\n"
}

// CreateProberSDP creates a test SDP string for prober simulation
// Probers are identified by a special attribute in the SDP
func CreateProberSDP() string {
	return "v=0\r\n" +
		"o=- 123456789 987654321 IN IP4 0.0.0.0\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=fingerprint:sha-256 12:34\r\n" +
		"a=extmap-allow-mixed\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=setup:actpass\r\n" +
		"a=mid:0\r\n" +
		"a=sendrecv\r\n" +
		"a=sctp-port:5000\r\n" +
		"a=ice-ufrag:CoVEaiFXRGVzshXG\r\n" +
		"a=ice-pwd:aOrOZXraTfFKzyeBxIXYYKjSgRVPGhUx\r\n" +
		"a=candidate:1000 1 udp 2000 8.8.8.8 3000 typ host\r\n" +
		"a=prober:true\r\n" +
		"a=end-of-candidates\r\n"
}

// IsProberSDP checks if an SDP string is from a prober
// Probers are identified by the presence of "a=prober:true" attribute
func IsProberSDP(sdp string) bool {
	return strings.Contains(sdp, "a=prober:true")
}

// CreateTestFingerprint creates a test bridge fingerprint
func CreateTestFingerprint() string {
	// Default bridge fingerprint from broker.go
	return "2B280B23E1107BB62ABFC40DDCC8824814F80A72"
}

func pickByProbability(values []string, firstWeight float64) string {
	if mathrand.Float64() < firstWeight {
		return values[0]
	}
	return values[1]
}

// GetStats returns current simulation statistics
func (sim *ProxyPollSimulator) GetStats() SimulationStats {
	sim.statsLock.Lock()
	defer sim.statsLock.Unlock()

	stats := *sim.stats
	if stats.TotalPolls > 0 {
		stats.AverageResponseTime = stats.TotalResponseTime / time.Duration(stats.TotalPolls)
	}
	stats.InFlightIPCCalls = sim.inFlightIPCCalls.Load()
	stats.MaxInFlightIPCCalls = sim.maxInFlightIPCCalls.Load()
	stats.TotalIPCCalls = sim.totalIPCCalls.Load()
	stats.MaxIPCRealDuration = time.Duration(sim.maxIPCRealNanos.Load())
	stats.BlockingIPCCalls = sim.blockingIPCCalls.Load()
	stats.TimeSteps = sim.timeSteps.Load()
	stats.TotalAdvancedFakeTime = time.Duration(sim.totalAdvancedFakeNanos.Load())
	stats.BackpressurePauses = sim.backpressurePauses.Load()
	stats.ChurnCycles = sim.churnCycles.Load()
	stats.ChurnCatchupHours = sim.churnCatchupHours.Load()
	stats.RuntimeGoroutines = runtime.NumGoroutine()
	updateMax(&sim.maxRuntimeGoroutines, int64(stats.RuntimeGoroutines))
	stats.MaxRuntimeGoroutines = sim.maxRuntimeGoroutines.Load()

	return stats
}
