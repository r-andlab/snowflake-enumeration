package sim

import (
	"runtime"
	"time"
)

// runStep advances the simulation by a single discrete step at time now.
func (sl *stepLoop) runStep(now time.Time) {
	sl.drainProxyResults(now)
	sl.drainClientResults(now)
	sl.drainAttackerResults()
	sl.applyHourlyEvents(now)

	sl.dispatchDueProxyPolls(now)
	if sl.stepYieldRounds <= 0 {
		runtime.Gosched()
	} else {
		for i := 0; i < sl.stepYieldRounds; i++ {
			runtime.Gosched()
		}
	}
	for _, c := range sl.clients {
		if c == nil || c.nextPollAt.After(now) {
			continue
		}
		sl.pollClient(now, c)
	}
	sl.drainProxyResults(now)
	sl.drainClientResults(now)
	sl.drainAttackerResults()

	if !now.Before(sl.proberStartAt) {
		for _, attacker := range sl.attackers {
			if !attacker.nextPollAt.After(now) {
				sl.pollProber(now, attacker)
			}
		}
	}
	sl.drainProxyResults(now)
	sl.drainClientResults(now)
	sl.drainAttackerResults()
	sl.settleCompletedAsync(now)
	sl.afterStepMinuteCoverage(now)
}

// settleCompletedAsync allows asynchronous results to settle over several small Gosched rounds.
func (sl *stepLoop) settleCompletedAsync(now time.Time) {
	if sl.stepSettleRounds <= 0 {
		return
	}
	for i := 0; i < sl.stepSettleRounds; i++ {
		runtime.Gosched()
		proxyDrained := sl.drainProxyResults(now)
		clientDrained := sl.drainClientResults(now)
		attackerDrained := sl.drainAttackerResults()
		if proxyDrained == 0 && clientDrained == 0 && attackerDrained == 0 && len(sl.proxyResults) == 0 && len(sl.attackerResults) == 0 {
			return
		}
	}
}

