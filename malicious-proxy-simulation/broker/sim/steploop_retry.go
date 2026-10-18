package sim

import (
	"log"
	"math"
	"sort"
	"time"
)

func (sl *stepLoop) recordNoMatchReason(reason clientNoMatchReason) {
	switch reason {
	case clientNoMatchNoProxies:
		sl.clientNoMatchByNoPx++
	case clientNoMatchTimedOut:
		sl.clientNoMatchByTO++
	case clientNoMatchBlocked:
		sl.clientNoMatchByBlock++
	default:
		sl.clientNoMatchByOther++
	}
}

func (sl *stepLoop) recordRetryAttempt(c *ghostClient, blocked bool) {
	if c == nil {
		return
	}
	c.totalRetriesInAttempt++
	if blocked {
		c.blockedRetriesInAttempt++
	}
}

func (sl *stepLoop) finalizeRetryAttempt(c *ghostClient) {
	if c == nil {
		return
	}
	if c.totalRetriesInAttempt > 0 {
		sl.totalRetryByAttempt[c.totalRetriesInAttempt]++
	}
	if c.blockedRetriesInAttempt > 0 {
		sl.blockedRetryByAttempt[c.blockedRetriesInAttempt]++
	}
	c.totalRetriesInAttempt = 0
	c.blockedRetriesInAttempt = 0
}

func retryAttemptPercentile(dist map[int]int64, q float64) float64 {
	if len(dist) == 0 {
		return 0
	}
	if q < 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	total := int64(0)
	keys := make([]int, 0, len(dist))
	for k, c := range dist {
		if c <= 0 {
			continue
		}
		keys = append(keys, k)
		total += c
	}
	if total <= 0 || len(keys) == 0 {
		return 0
	}
	sort.Ints(keys)
	rank := int64(math.Ceil(q * float64(total)))
	if rank < 1 {
		rank = 1
	}
	seen := int64(0)
	for _, k := range keys {
		seen += dist[k]
		if seen >= rank {
			return float64(k)
		}
	}
	return float64(keys[len(keys)-1])
}

func retryAttemptStats(dist map[int]int64) (attempts int64, avg float64, p25 float64, p50 float64, p75 float64, p99 float64) {
	totalRetries := int64(0)
	for retries, count := range dist {
		if count <= 0 {
			continue
		}
		attempts += count
		totalRetries += int64(retries) * count
	}
	if attempts > 0 {
		avg = float64(totalRetries) / float64(attempts)
	}
	p25 = retryAttemptPercentile(dist, 0.25)
	p50 = retryAttemptPercentile(dist, 0.50)
	p75 = retryAttemptPercentile(dist, 0.75)
	p99 = retryAttemptPercentile(dist, 0.99)
	return
}

func (sl *stepLoop) scheduleClientRetry(now time.Time, c *ghostClient) {
	c.retryStreak++
	c.pollCounter++
	if c.retryStreak >= sl.clientMaxRetries {
		sl.finalizeRetryAttempt(c)
		clientID := c.clientID
		delete(sl.clients, clientID)
		sl.clientRetryLimitHits++

		sl.sim.removeClientConnections(clientID)
		sl.sim.connectionLock.Lock()
		delete(sl.sim.clientStates, clientID)
		sl.sim.connectionLock.Unlock()

		if sl.sim.eventLogs {
			log.Printf(
				"Client %d reached max retries (%d), closing client",
				clientID,
				sl.clientMaxRetries,
			)
		}
		if sl.clientImmediateRespawn {
			sl.addClientsNow(now, 1)
		}
		return
	}
	c.nextPollAt = now.Add(sl.clientInterval)
}

