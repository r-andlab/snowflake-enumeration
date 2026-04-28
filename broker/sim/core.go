package sim

import (
	"context"
	"fmt"
	"log"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
)

type clientNoMatchReason string

const (
	clientNoMatchNone      clientNoMatchReason = "none"
	clientNoMatchNoProxies clientNoMatchReason = "no_proxies"
	clientNoMatchTimedOut  clientNoMatchReason = "timed_out"
	clientNoMatchBlocked   clientNoMatchReason = "blocked"
	clientNoMatchOther     clientNoMatchReason = "other"
)

func classifyClientNoMatchReason(errString string) clientNoMatchReason {
	switch errString {
	case messages.StrNoProxies:
		return clientNoMatchNoProxies
	case messages.StrTimedOut:
		return clientNoMatchTimedOut
	default:
		return clientNoMatchOther
	}
}

// RunProxyPoll runs the full proxy-poll flow: encode request and record start time under FakeTimeStepMu,
// doPoll without the lock (IPC must not run while holding the step lock), then decode response and
// update stats under the lock again.
func (sim *ProxyPollSimulator) RunProxyPoll(
	sessionID string,
	proxyType string,
	natType string,
	clients int,
	relayPattern string,
	doPoll func(messages.Arg) ([]byte, error),
) (matched bool, isProber bool, err error) {
	FakeTimeStepMu.RLock()
	startTime := sim.simulationNow()
	body, encodeErr := messages.EncodeProxyPollRequestWithRelayPrefix(
		sessionID, proxyType, natType, clients, relayPattern,
	)
	var arg messages.Arg
	if encodeErr == nil {
		arg = messages.Arg{Body: body, RemoteAddr: generateRandomIP()}
	}

	response, pollErr := doPoll(arg)
	if pollErr != nil {
		return false, false, pollErr
	}

	responseTime := sim.simulationNow().Sub(startTime)
	sim.updateStats(proxyType, natType, response, responseTime)
	offer, _, _, decodeErr := messages.DecodePollResponseWithRelayURL(response)
	if decodeErr != nil {
		log.Printf("Error decoding proxy poll response: %s", response)
		matched, isProber = false, false
	} else {
		matched = len(offer) > 0
		isProber = matched && IsProberSDP(offer)
	}
	FakeTimeStepMu.RUnlock()
	return matched, isProber, nil
}

// RunClientOffer encodes the client offer, calls doOffer without holding FakeTimeStepMu, then decodes the
// response and updates sim state under FakeTimeStepMu.RLock().
func (sim *ProxyPollSimulator) RunClientOffer(
	clientID int,
	sdp string,
	natType string,
	fingerprint string,
) (matched bool, sid string, reason clientNoMatchReason, err error) {
	reason = clientNoMatchNone
	clientRequest := &messages.ClientPollRequest{
		Offer: sdp, NAT: natType, Fingerprint: fingerprint,
	}
	body, encErr := clientRequest.EncodeClientPollRequest()
	if encErr != nil {
		return false, "", reason, fmt.Errorf("failed to encode client offer: %w", encErr)
	}
	arg := messages.Arg{
		Body:             body,
		RemoteAddr:       generateRandomIP(),
		RendezvousMethod: messages.RendezvousHttp,
		Context:          context.Background(),
	}
	var response []byte
	offerErr := sim.callClientOffers(arg, &response)
	if offerErr != nil {
		return false, "", reason, fmt.Errorf("client offer failed: %w", offerErr)
	}

	resp, decErr := messages.DecodeClientPollResponse(response)
	if decErr != nil {
		return false, "", clientNoMatchOther, fmt.Errorf("failed to decode client response: %w", decErr)
	}
	sid = resp.Sid
	matched = resp.Error == "" && resp.Answer != ""

	if matched && resp.Sid != "" {
		proxyType, proxyID, ok := parseProxyIDFromSession(resp.Sid)
		if ok {
			if IsProberSDP(sdp) {
				if sim.isBlockingAttackEnabled() {
					sim.blockProxy(proxyType, proxyID)
				}
			} else if sim.isProxyBlocked(proxyType, proxyID) {
				sim.recordClientFetchRetry(clientID, true)
				if sim.eventLogs {
					log.Printf("Client %d matched with a blocked proxy %s-%d", clientID, proxyType, proxyID)
				}
				matched = false
				reason = clientNoMatchBlocked
			} else {
				if sim.eventLogs {
					log.Printf("Client %d successfully matched with proxy %s-%d", clientID, proxyType, proxyID)
				}
				sim.registerConnection(proxyID, proxyType, resp.Sid, clientID)
			}
		}
	}

	if !matched && clientID >= 0 {
		if reason == clientNoMatchNone {
			reason = classifyClientNoMatchReason(resp.Error)
		}
		if sim.eventLogs {
			log.Printf(
				"Client %d got no match, will retry (reason=%s error=%q sid=%q answer_present=%t)",
				clientID,
				reason,
				resp.Error,
				resp.Sid,
				resp.Answer != "",
			)
		}
		sim.recordClientFetchRetry(clientID, reason == clientNoMatchBlocked)
	}
	return matched, sid, reason, nil
}

func (sim *ProxyPollSimulator) recordProxyStart(proxyType string, proxyID int) {
	key := fmt.Sprintf("%s-%d", proxyType, proxyID)
	sim.proxyStartMu.Lock()
	defer sim.proxyStartMu.Unlock()
	sim.proxyStartTime[key] = sim.simulationNow()
}

func (sim *ProxyPollSimulator) blockProxy(proxyType string, proxyID int) {
	key := fmt.Sprintf("%s-%d", proxyType, proxyID)
	sim.proxyStartMu.RLock()
	startedAt := sim.proxyStartTime[key]
	sim.proxyStartMu.RUnlock()

	now := sim.simulationNow()
	delta := now.Sub(startedAt)
	if sim.eventLogs && !startedAt.IsZero() {
		log.Printf("proxy %s-%d blocked: time delta since start = %v", proxyType, proxyID, delta)
	}

	sim.blockedProxiesMu.Lock()
	defer sim.blockedProxiesMu.Unlock()
	if _, exists := sim.blockedProxies[key]; exists {
		return
	}
	sim.blockedProxies[key] = struct{}{}
	sim.blockedByType[proxyType]++
}

func (sim *ProxyPollSimulator) isProxyBlocked(proxyType string, proxyID int) bool {
	sim.blockedProxiesMu.RLock()
	defer sim.blockedProxiesMu.RUnlock()
	_, ok := sim.blockedProxies[fmt.Sprintf("%s-%d", proxyType, proxyID)]
	return ok
}

func (sim *ProxyPollSimulator) recordClientFetchRetry(clientID int, blocked bool) {
	if clientID < 0 {
		return // probers don't count
	}
	sim.statsLock.Lock()
	defer sim.statsLock.Unlock()
	sim.stats.ClientFetchRetries++
	if blocked {
		sim.stats.ClientFetchRetriesBlocked++
	}
}

func proxyConnKey(proxyType string, proxyID int) string {
	return fmt.Sprintf("%s-%d", proxyType, proxyID)
}

func (sim *ProxyPollSimulator) indexConnectionLocked(conn *connection) {
	sim.connections[conn.proxySession] = conn

	pkey := proxyConnKey(conn.proxyType, conn.proxyID)
	if _, ok := sim.proxySessions[pkey]; !ok {
		sim.proxySessions[pkey] = make(map[string]struct{})
	}
	sim.proxySessions[pkey][conn.proxySession] = struct{}{}

	if _, ok := sim.clientSessions[conn.clientID]; !ok {
		sim.clientSessions[conn.clientID] = make(map[string]struct{})
	}
	sim.clientSessions[conn.clientID][conn.proxySession] = struct{}{}
}

func (sim *ProxyPollSimulator) removeConnectionIndexesLocked(conn *connection) {
	pkey := proxyConnKey(conn.proxyType, conn.proxyID)
	if sessions, ok := sim.proxySessions[pkey]; ok {
		delete(sessions, conn.proxySession)
		if len(sessions) == 0 {
			delete(sim.proxySessions, pkey)
		}
	}

	if sessions, ok := sim.clientSessions[conn.clientID]; ok {
		delete(sessions, conn.proxySession)
		if len(sessions) == 0 {
			delete(sim.clientSessions, conn.clientID)
		}
	}
}

func (sim *ProxyPollSimulator) removeConnectionBySessionLocked(proxySession string) (*connection, bool) {
	conn, exists := sim.connections[proxySession]
	if !exists {
		return nil, false
	}
	delete(sim.connections, proxySession)
	sim.removeConnectionIndexesLocked(conn)
	return conn, true
}

func (sim *ProxyPollSimulator) notifyClientDisconnectedLocked(conn *connection) {
	state, exists := sim.clientStates[conn.clientID]
	if !exists {
		return
	}
	state.mu.Lock()
	if state.currentProxyID == conn.proxyID && state.currentProxyType == conn.proxyType {
		state.currentProxyID = -1
		state.currentProxyType = ""
		state.currentSession = ""
		select {
		case state.disconnectChan <- struct{}{}:
		default:
		}
	}
	state.mu.Unlock()
}

func (sim *ProxyPollSimulator) clearClientConnectionsLocked(clientID int, notify bool) {
	sessions := sim.clientSessions[clientID]
	if len(sessions) == 0 {
		return
	}

	sessionIDs := make([]string, 0, len(sessions))
	for sessionID := range sessions {
		sessionIDs = append(sessionIDs, sessionID)
	}
	for _, sessionID := range sessionIDs {
		conn, ok := sim.removeConnectionBySessionLocked(sessionID)
		if !ok {
			continue
		}
		if notify {
			sim.notifyClientDisconnectedLocked(conn)
		}
	}
}

func (sim *ProxyPollSimulator) removeClientConnections(clientID int) {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()
	sim.clearClientConnectionsLocked(clientID, false)
}

// registerConnection registers a connection between a proxy and client
func (sim *ProxyPollSimulator) registerConnection(proxyID int, proxyType string, proxySession string, clientID int) {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()

	// Remove stale prior sessions for this client before registering a new one.
	sim.clearClientConnectionsLocked(clientID, false)

	conn := &connection{
		proxyID:      proxyID,
		proxyType:    proxyType,
		proxySession: proxySession,
		clientID:     clientID,
		matchedAt:    sim.simulationNow(),
	}
	sim.indexConnectionLocked(conn)

	// Update or create client state
	state, exists := sim.clientStates[clientID]
	if !exists {
		state = &clientState{
			clientID:         clientID,
			currentProxyID:   -1,
			currentProxyType: "",
			disconnectChan:   make(chan struct{}, 1),
		}
		sim.clientStates[clientID] = state
	}
	state.mu.Lock()
	state.currentProxyID = proxyID
	state.currentProxyType = proxyType
	state.currentSession = proxySession
	state.mu.Unlock()
}

// unregisterConnection removes a connection
func (sim *ProxyPollSimulator) unregisterConnection(proxySession string) {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()

	conn, exists := sim.connections[proxySession]
	if !exists {
		return
	}
	sim.removeConnectionIndexesLocked(conn)
	delete(sim.connections, proxySession)
	sim.notifyClientDisconnectedLocked(conn)
}

// setConnectionDuration sets a shared connection lifetime for a session and returns its disconnect time.
func (sim *ProxyPollSimulator) setConnectionDuration(proxySession string, duration time.Duration) (time.Time, bool) {
	if duration < time.Second {
		duration = time.Second
	}
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()

	conn, exists := sim.connections[proxySession]
	if !exists || conn == nil {
		return time.Time{}, false
	}
	if conn.matchedAt.IsZero() {
		conn.matchedAt = sim.simulationNow()
	}
	conn.disconnectAt = conn.matchedAt.Add(duration)
	return conn.disconnectAt, true
}

// getConnectionDisconnectAt returns the disconnect time for a session if one has been assigned.
func (sim *ProxyPollSimulator) getConnectionDisconnectAt(proxySession string) (time.Time, bool) {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()

	conn, exists := sim.connections[proxySession]
	if !exists || conn == nil || conn.disconnectAt.IsZero() {
		return time.Time{}, false
	}
	return conn.disconnectAt, true
}

// getClientState returns the client state for a given client ID
func (sim *ProxyPollSimulator) getClientState(clientID int) *clientState {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()

	state, exists := sim.clientStates[clientID]
	if !exists {
		state = &clientState{
			clientID:         clientID,
			currentProxyID:   -1,
			currentProxyType: "",
			disconnectChan:   make(chan struct{}, 1),
		}
		sim.clientStates[clientID] = state
	}
	return state
}

// countActiveConnectionsToProxy returns how many live sessions are registered for this proxy identity.
func (sim *ProxyPollSimulator) countActiveConnectionsToProxy(proxyType string, proxyID int) int {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()
	pkey := proxyConnKey(proxyType, proxyID)
	return len(sim.proxySessions[pkey])
}

// countTotalActiveConnections returns the number of registered sessions (all proxies).
func (sim *ProxyPollSimulator) countTotalActiveConnections() int {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()
	return len(sim.connections)
}

// getConnectedClients returns client IDs connected to a given proxy identity.
func (sim *ProxyPollSimulator) getConnectedClients(proxyType string, proxyID int) []int {
	sim.connectionLock.Lock()
	defer sim.connectionLock.Unlock()

	pkey := proxyConnKey(proxyType, proxyID)
	sessions := sim.proxySessions[pkey]
	if len(sessions) == 0 {
		return nil
	}

	sessionIDs := make([]string, 0, len(sessions))
	for sessionID := range sessions {
		sessionIDs = append(sessionIDs, sessionID)
	}

	clientSet := make(map[int]struct{})
	clientIDs := make([]int, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		conn, ok := sim.removeConnectionBySessionLocked(sessionID)
		if !ok {
			continue
		}
		if _, exists := clientSet[conn.clientID]; !exists {
			clientSet[conn.clientID] = struct{}{}
			clientIDs = append(clientIDs, conn.clientID)
		}
		sim.notifyClientDisconnectedLocked(conn)
	}

	return clientIDs
}

// SimulateProxyAnswer simulates a proxy sending an answer back
func (sim *ProxyPollSimulator) SimulateProxyAnswer(
	sdpAnswer string,
	sessionID string,
) error {
	// Encode the answer request
	body, err := messages.EncodeAnswerRequest(sdpAnswer, sessionID)
	if err != nil {
		return fmt.Errorf("failed to encode proxy answer: %w", err)
	}

	// Create the argument
	arg := messages.Arg{
		Body:       body,
		RemoteAddr: generateRandomIP(),
	}

	// Call ProxyAnswers directly (no network communication)
	var response []byte
	err = sim.callProxyAnswers(arg, &response)
	if err != nil {
		return fmt.Errorf("proxy answer failed: %w", err)
	}

	return nil
}

// updateStats updates the statistics based on the poll response
func (sim *ProxyPollSimulator) updateStats(
	proxyType string,
	natType string,
	response []byte,
	responseTime time.Duration,
) {
	sim.statsLock.Lock()
	defer sim.statsLock.Unlock()

	sim.stats.TotalPolls++
	sim.stats.TotalResponseTime += responseTime
	sim.stats.ProxyTypes[proxyType]++
	sim.stats.NATTypes[natType]++

	// Decode response to determine if it was a match or idle
	if len(response) > 0 {
		// Try to decode as poll response to check if it has an offer
		offer, _, _, err := messages.DecodePollResponseWithRelayURL(response)
		if err == nil {
			if len(offer) > 0 {
				sim.stats.SuccessfulMatches++
			} else {
				sim.stats.IdlePolls++
			}
		} else {
			// If decoding fails, might be an error response
			sim.stats.RejectedPolls++
		}
	} else {
		sim.stats.IdlePolls++
	}
}
