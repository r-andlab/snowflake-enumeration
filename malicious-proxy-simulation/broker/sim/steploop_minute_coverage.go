package sim

import (
	"fmt"
	"log"
	"strings"
	"time"
)

func proxyPollKey(proxyType string, proxyID int) string {
	return fmt.Sprintf("%s-%d", proxyType, proxyID)
}

// proxyTypeFromPollKey returns the proxy type prefix for keys produced by proxyPollKey ("standalone-3", "iptproxy-1", …).
func proxyTypeFromPollKey(key string) string {
	for _, pt := range []string{"iptproxy", "standalone", "webext"} {
		prefix := pt + "-"
		if strings.HasPrefix(key, prefix) {
			return pt
		}
	}
	return ""
}

func minuteCoveragePct(polled, notFound int) float64 {
	if polled <= 0 {
		return 0
	}
	return 100.0 * float64(notFound) / float64(polled)
}

func (sl *stepLoop) recordProxyPolledInWindow(proxyType string, proxyID int) {
	key := proxyPollKey(proxyType, proxyID)
	sl.minuteProxyPollSet[key] = struct{}{}
}

// afterStepMinuteCoverage runs at the end of each simulated step: every 60 steps, log coverage and clear the set.
func (sl *stepLoop) afterStepMinuteCoverage(now time.Time) {
	sl.stepSeq++
	if sl.stepSeq%60 != 0 {
		return
	}
	sl.flushAndClearMinuteProxyPollSet(now)
}

func natMinute64(m map[string]int64, key string) int64 {
	if m == nil {
		return 0
	}
	return m[key]
}

// avgRetriesPerMatch is sum(totalRetriesInAttempt at match) / successful matches in the window (0 if no matches).
func avgRetriesPerMatch(sumRetries, matchCount int64) float64 {
	if matchCount <= 0 {
		return 0
	}
	return float64(sumRetries) / float64(matchCount)
}

func (sl *stepLoop) flushMinuteClientNATStats(ts string) {
	ua := natMinute64(sl.minuteClientAttemptsByNAT, "unrestricted")
	ur := natMinute64(sl.minuteClientRetriesByNAT, "unrestricted")
	ra := natMinute64(sl.minuteClientAttemptsByNAT, "restricted")
	rr := natMinute64(sl.minuteClientRetriesByNAT, "restricted")
	xa := natMinute64(sl.minuteClientAttemptsByNAT, "unknown")
	xr := natMinute64(sl.minuteClientRetriesByNAT, "unknown")

	us := natMinute64(sl.minuteSumRetriesBeforeMatchByNAT, "unrestricted")
	um := natMinute64(sl.minuteMatchCountByNAT, "unrestricted")
	rs := natMinute64(sl.minuteSumRetriesBeforeMatchByNAT, "restricted")
	rm := natMinute64(sl.minuteMatchCountByNAT, "restricted")
	xs := natMinute64(sl.minuteSumRetriesBeforeMatchByNAT, "unknown")
	xm := natMinute64(sl.minuteMatchCountByNAT, "unknown")

	log.Printf(
		"minute-client-nat t=%s unrestricted_attempts=%d unrestricted_retries=%d unrestricted_avg_retries_per_attempt=%.4f restricted_attempts=%d restricted_retries=%d restricted_avg_retries_per_attempt=%.4f unknown_attempts=%d unknown_retries=%d unknown_avg_retries_per_attempt=%.4f",
		ts,
		ua, ur, avgRetriesPerMatch(us, um),
		ra, rr, avgRetriesPerMatch(rs, rm),
		xa, xr, avgRetriesPerMatch(xs, xm),
	)
	sl.minuteClientAttemptsByNAT = make(map[string]int64)
	sl.minuteClientRetriesByNAT = make(map[string]int64)
	sl.minuteSumRetriesBeforeMatchByNAT = make(map[string]int64)
	sl.minuteMatchCountByNAT = make(map[string]int64)
}

func (sl *stepLoop) flushAndClearMinuteProxyPollSet(now time.Time) {
	ts := now.UTC().Format(time.RFC3339)
	sl.flushMinuteClientNATStats(ts)

	set := sl.minuteProxyPollSet
	sl.minuteProxyPollSet = make(map[string]struct{})
	n := len(set)
	if n == 0 {
		log.Printf(
			"minute-coverage t=%s unique_proxies_polled=0 unique_not_found_by_attacker=0 pct_not_found_by_attacker=0.0000",
			ts,
		)
		sl.flushMaliciousProxyMinute(ts)
		return
	}

	notFoundGlobal := 0
	for key := range set {
		if !sl.sim.AttackerHasObservedProxy(key) {
			notFoundGlobal++
		}
	}
	pctGlobal := minuteCoveragePct(n, notFoundGlobal)
	log.Printf(
		"minute-coverage t=%s unique_proxies_polled=%d unique_not_found_by_attacker=%d pct_not_found_by_attacker=%.4f",
		ts,
		n,
		notFoundGlobal,
		pctGlobal,
	)

	byTypeKeys := map[string][]string{
		"standalone": nil,
		"webext":     nil,
		"iptproxy":   nil,
	}
	for key := range set {
		pt := proxyTypeFromPollKey(key)
		if pt != "" {
			byTypeKeys[pt] = append(byTypeKeys[pt], key)
		}
	}

	for _, nat := range []string{"unrestricted", "restricted", "unknown"} {
		sa := byTypeKeys["standalone"]
		we := byTypeKeys["webext"]
		ip := byTypeKeys["iptproxy"]
		saNF := countNotFoundByNAT(sl, nat, sa)
		weNF := countNotFoundByNAT(sl, nat, we)
		ipNF := countNotFoundByNAT(sl, nat, ip)
		log.Printf(
			"minute-coverage t=%s attacker_nat=%s standalone_polled=%d standalone_not_found_by_attacker=%d standalone_pct_not_found_by_attacker=%.4f webext_polled=%d webext_not_found_by_attacker=%d webext_pct_not_found_by_attacker=%.4f iptproxy_polled=%d iptproxy_not_found_by_attacker=%d iptproxy_pct_not_found_by_attacker=%.4f",
			ts,
			nat,
			len(sa), saNF, minuteCoveragePct(len(sa), saNF),
			len(we), weNF, minuteCoveragePct(len(we), weNF),
			len(ip), ipNF, minuteCoveragePct(len(ip), ipNF),
		)
	}
	sl.flushMaliciousProxyMinute(ts)
}

func (sl *stepLoop) flushMaliciousProxyMinute(ts string) {
	if !sl.maliciousProxyEnabled || sl.maliciousProxyUnrestrictedID < 0 || sl.maliciousProxyRestrictedID < 0 {
		sl.maliciousConnSumUnrestricted = 0
		sl.maliciousConnSumRestricted = 0
		sl.maliciousConnTotalSum = 0
		return
	}
	var pctU, pctR float64
	if sl.maliciousConnTotalSum > 0 {
		pctU = sl.maliciousConnSumUnrestricted / float64(sl.maliciousConnTotalSum)
		pctR = sl.maliciousConnSumRestricted / float64(sl.maliciousConnTotalSum)
	}
	log.Printf(
		"minute-malicious-proxy t=%s standalone-%d (unrestricted) pct_match_events_vs_new_connections=%.6f match_events=%.0f standalone-%d (restricted) pct_match_events_vs_new_connections=%.6f match_events=%.0f total_new_connections_in_minute=%d",
		ts,
		sl.maliciousProxyUnrestrictedID,
		pctU,
		sl.maliciousConnSumUnrestricted,
		sl.maliciousProxyRestrictedID,
		pctR,
		sl.maliciousConnSumRestricted,
		sl.maliciousConnTotalSum,
	)
	sl.maliciousConnSumUnrestricted = 0
	sl.maliciousConnSumRestricted = 0
	sl.maliciousConnTotalSum = 0
}

func countNotFoundByNAT(sl *stepLoop, natType string, keys []string) int {
	n := 0
	for _, k := range keys {
		if !sl.sim.AttackerHasObservedProxyForNAT(natType, k) {
			n++
		}
	}
	return n
}

// FlushPartialMinuteCoverageOnShutdown logs and clears if the window ended before a multiple of 60 steps.
func (sl *stepLoop) FlushPartialMinuteCoverageOnShutdown(now time.Time) {
	if len(sl.minuteProxyPollSet) > 0 {
		sl.flushAndClearMinuteProxyPollSet(now)
		return
	}
	if len(sl.minuteClientAttemptsByNAT) > 0 || len(sl.minuteClientRetriesByNAT) > 0 ||
		len(sl.minuteSumRetriesBeforeMatchByNAT) > 0 || len(sl.minuteMatchCountByNAT) > 0 {
		sl.flushMinuteClientNATStats(now.UTC().Format(time.RFC3339))
	}
	if sl.maliciousConnTotalSum > 0 || sl.maliciousConnSumUnrestricted != 0 || sl.maliciousConnSumRestricted != 0 {
		sl.flushMaliciousProxyMinute(now.UTC().Format(time.RFC3339))
	}
}
