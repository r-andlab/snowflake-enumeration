package sim

import (
	"fmt"
	"os"
	"time"
)

func (sim *ProxyPollSimulator) isBlockingAttackEnabled() bool {
	return sim.attackMode != 0
}

func (sim *ProxyPollSimulator) attackModeLabel() string {
	if sim.isBlockingAttackEnabled() {
		return "blocking"
	}
	return "enumeration-only"
}

func (sim *ProxyPollSimulator) openAttackEnumFile() error {
	if sim.attackEnumPath == "" {
		return nil
	}
	f, err := os.OpenFile(sim.attackEnumPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil && info.Size() == 0 {
		if _, werr := f.WriteString("time,attacker_id,nat_type,proxy_type,proxy_id,session_id\n"); werr != nil {
			_ = f.Close()
			return werr
		}
	}
	sim.attackEnumFile = f
	return nil
}

func (sim *ProxyPollSimulator) closeAttackEnumFile() {
	sim.attackEnumMu.Lock()
	defer sim.attackEnumMu.Unlock()
	if sim.attackEnumFile != nil {
		_ = sim.attackEnumFile.Close()
		sim.attackEnumFile = nil
	}
}

// recordAttackerObservation tracks a unique proxy matched by a prober.
// Returns true if this was the first observation of the proxy.
func (sim *ProxyPollSimulator) recordAttackerObservation(
	now time.Time,
	attackerID int,
	natType string,
	sessionID string,
) bool {
	proxyType, proxyID, ok := parseProxyIDFromSession(sessionID)
	if !ok {
		return false
	}
	key := fmt.Sprintf("%s-%d", proxyType, proxyID)

	natKey := natType
	if natKey == "" {
		natKey = "unknown"
	}

	firstSeen := false
	sim.attackerObservedMu.Lock()
	// Every successful match: this prober NAT has observed this proxy (minute-coverage per NAT).
	if sim.attackerSeenProxyByNAT == nil {
		sim.attackerSeenProxyByNAT = make(map[string]map[string]struct{})
	}
	if sim.attackerSeenProxyByNAT[natKey] == nil {
		sim.attackerSeenProxyByNAT[natKey] = make(map[string]struct{})
	}
	sim.attackerSeenProxyByNAT[natKey][key] = struct{}{}

	if _, exists := sim.attackerObserved[key]; !exists {
		sim.attackerObserved[key] = struct{}{}
		sim.attackerObservedByT[proxyType]++
		if sim.attackerObservedByNATAndType[natKey] == nil {
			sim.attackerObservedByNATAndType[natKey] = map[string]int64{
				"standalone": 0, "webext": 0, "iptproxy": 0,
			}
		}
		sim.attackerObservedByNATAndType[natKey][proxyType]++
		firstSeen = true
	}
	sim.attackerObservedMu.Unlock()
	if !firstSeen {
		return false
	}

	sim.attackEnumMu.Lock()
	defer sim.attackEnumMu.Unlock()
	if sim.attackEnumFile != nil {
		_, _ = sim.attackEnumFile.WriteString(
			fmt.Sprintf(
				"%s,%d,%s,%s,%d,%s\n",
				now.Format(time.RFC3339),
				attackerID,
				natType,
				proxyType,
				proxyID,
				sessionID,
			),
		)
	}
	return true
}

// AttackerHasObservedProxy reports whether any prober has recorded this proxy key (e.g. "standalone-3").
func (sim *ProxyPollSimulator) AttackerHasObservedProxy(key string) bool {
	sim.attackerObservedMu.RLock()
	defer sim.attackerObservedMu.RUnlock()
	_, ok := sim.attackerObserved[key]
	return ok
}

// AttackerHasObservedProxyForNAT reports whether a prober with this NAT has matched this proxy key at least once.
func (sim *ProxyPollSimulator) AttackerHasObservedProxyForNAT(natType, proxyKey string) bool {
	natKey := natType
	if natKey == "" {
		natKey = "unknown"
	}
	sim.attackerObservedMu.RLock()
	defer sim.attackerObservedMu.RUnlock()
	m := sim.attackerSeenProxyByNAT[natKey]
	if m == nil {
		return false
	}
	_, ok := m[proxyKey]
	return ok
}

func (sim *ProxyPollSimulator) getAttackerObservedCounts() (int64, map[string]int64, map[string]map[string]int64) {
	sim.attackerObservedMu.RLock()
	defer sim.attackerObservedMu.RUnlock()
	byType := map[string]int64{
		"standalone": sim.attackerObservedByT["standalone"],
		"webext":     sim.attackerObservedByT["webext"],
		"iptproxy":   sim.attackerObservedByT["iptproxy"],
	}
	total := byType["standalone"] + byType["webext"] + byType["iptproxy"]
	byNATAndType := make(map[string]map[string]int64, len(sim.attackerObservedByNATAndType))
	for nat, inner := range sim.attackerObservedByNATAndType {
		cp := make(map[string]int64, len(inner))
		for pt, n := range inner {
			cp[pt] = n
		}
		byNATAndType[nat] = cp
	}
	return total, byType, byNATAndType
}
