package sim

import (
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mathrand "math/rand"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
)

// ghostProxy represents a proxy in the simulation.
type ghostProxy struct {
	proxyID       int
	proxyType     string
	standaloneNAT string
	pollInterval  time.Duration
	nextPollAt    time.Time
	pollCounter   int
	inFlight      bool
	malicious     bool // if true, never removed by churn/target shrink; polls every simulated step
}

// ghostClient represents a client in the simulation.
type ghostClient struct {
	clientID                int
	nextPollAt              time.Time
	pollCounter             int
	inFlight                bool
	retryStreak             int
	totalRetriesInAttempt   int
	blockedRetriesInAttempt int
}

// ghostAttacker represents an attacker in the simulation.
type ghostAttacker struct {
	attackerID   int
	natType      string
	nextPollAt   time.Time
	pollCounter  int
	enumerated   int64
	lastMatchSID string
	inFlight     bool
}

// proxyPollResult represents the result of a proxy poll.
type proxyPollResult struct {
	proxyType    string
	proxyID      int
	sessionID    string
	pollInterval time.Duration
	matched      bool
	isProber     bool
	err          error
}

// clientPollResult represents the result of a client poll.
type clientPollResult struct {
	clientID int
	natType  string // client NAT for this poll ("unrestricted" / "restricted")
	sdp      string
	polledAt time.Time
	err      error
	matched  bool
	sid      string
	reason   clientNoMatchReason
}

// attackerPollResult represents the result of an attacker poll.
type attackerPollResult struct {
	attackerID int
	natType    string
	polledAt   time.Time
	matched    bool
	sid        string
	err        error
}

// stepLoop represents a step loop in the simulation.
type stepLoop struct {
	sim              *ProxyPollSimulator
	startTime        time.Time
	step             time.Duration
	pollLogs         bool
	stepYieldRounds  int
	stepSettleRounds int

	natTypes []string

	proxies     map[string]map[int]*ghostProxy
	nextProxyID map[string]int
	clients     map[int]*ghostClient

	clientTargetCount      int
	clientReplenishHour    bool
	clientImmediateRespawn bool
	clientPollJitter       time.Duration
	clientSpawnSpread      time.Duration
	clientInterval         time.Duration
	clientMaxRetries       int
	spreadHourlyChurn      bool
	proberInterval         time.Duration
	proberStartAt          time.Time
	attackers              []*ghostAttacker

	standalonePollInterval time.Duration
	webextPollInterval     time.Duration
	iptPollInterval        time.Duration
	matchedProxyWait       time.Duration
	matchedClientWait      time.Duration
	connectionMeanWait     time.Duration
	connectionStddevWait   time.Duration

	churnRateBase          float64
	proxyCountScale        float64
	standaloneUnrestricted float64
	webIPTUnrestricted     float64
	proxyPollJitterPct     float64

	lastAppliedHour int
	nextClientID    int

	pendingTargetStart map[string]int
	pendingTargetStop  map[string]int
	pendingChurnStart  map[string]int
	pendingChurnStop   map[string]int

	totalClientPolls     int64
	totalProxyPolls      int64
	totalProberPolls     int64
	clientNoMatches      int64
	blockedRetryEvents   int64
	totalRetryEvents     int64
	clientRetryLimitHits int64
	clientRespawnedTotal int64
	clientNoMatchByNoPx  int64
	clientNoMatchByTO    int64
	clientNoMatchByBlock int64
	clientNoMatchByOther int64

	proxyPollsByType      map[string]int64
	clientMatchesByType   map[string]int64
	clientBlockedByType   map[string]int64
	attackerPollsByNAT    map[string]int64
	blockedRetryByAttempt map[int]int64
	totalRetryByAttempt   map[int]int64

	// Per client NAT: retry scheduling events and blocked-style retries (see drainClientResults).
	clientRetryEventsByNAT    map[string]int64
	clientBlockedRetriesByNAT map[string]int64

	proxyTypeOrder []string
	pollRandSeed   int64
	pollRand       *mathrand.Rand

	proxyResults           chan proxyPollResult
	clientResults          chan clientPollResult
	attackerResults        chan attackerPollResult
	clientResultsUnbounded bool
	clientResultsMu        sync.Mutex
	clientResultsQueue     []clientPollResult

	// Unique proxy keys "type-id" that completed a poll since the last %60 flush (step index).
	minuteProxyPollSet map[string]struct{}
	stepSeq            int64

	// Per simulated minute (every 60 steps): client offer outcomes by client NAT (see flushMinuteClientNATStats).
	minuteClientAttemptsByNAT map[string]int64
	minuteClientRetriesByNAT  map[string]int64
	// Sum of totalRetriesInAttempt at each successful match and match counts (avg retries per successful match per NAT).
	minuteSumRetriesBeforeMatchByNAT map[string]int64
	minuteMatchCountByNAT            map[string]int64

	// Optional malicious proxies (see SNOWFLAKE_SIM_MALICIOUS_PROXY): two standalone proxies — one
	// unrestricted NAT, one restricted — each polls every step and tears down client sessions on match.
	maliciousProxyEnabled        bool
	maliciousProxyUnrestrictedID int     // standalone id; -1 if disabled
	maliciousProxyRestrictedID   int     // standalone id; -1 if disabled
	maliciousConnSumUnrestricted float64 // match events to unrestricted malicious proxy in the current minute window
	maliciousConnSumRestricted   float64 // match events to restricted malicious proxy in the current minute window
	maliciousConnTotalSum        int64   // total new successful connections (all proxies) in current minute window
}

// IPCInterface is the broker IPC interface used by the simulator (avoids importing broker main).
type IPCInterface interface {
	ProxyPolls(arg messages.Arg, response *[]byte) error
	ClientOffers(arg messages.Arg, response *[]byte) error
	ProxyAnswers(arg messages.Arg, response *[]byte) error
	// SnowflakeHeapSnapshot exposes broker pending proxy-poll snowflakes (see broker/snowflake-heap.go).
	// unrestricted/restricted are heap lengths; sessionIDs are snowflake.id values currently on those heaps.
	SnowflakeHeapSnapshot() (unrestricted int, restricted int, sessionIDs []string)
}

// connection represents a connection between a proxy and client
type connection struct {
	proxyID      int
	proxyType    string
	proxySession string
	clientID     int
	matchedAt    time.Time
	disconnectAt time.Time
}

// clientState tracks the state of a client
type clientState struct {
	clientID         int
	currentProxyID   int
	currentProxyType string
	currentSession   string
	waitUntil        time.Time
	waitRemaining    time.Duration
	disconnectChan   chan struct{}
	mu               sync.Mutex
}

// ProxyPollSimulator simulates proxy polling without network communication
type ProxyPollSimulator struct {
	ipc       IPCInterface
	stats     *SimulationStats
	statsLock sync.Mutex
	stopChan  chan struct{}
	wg        sync.WaitGroup
	debugMode bool
	eventLogs bool

	proxyStartTime map[string]time.Time
	proxyStartMu   sync.RWMutex

	connections    map[string]*connection
	clientStates   map[int]*clientState
	proxySessions  map[string]map[string]struct{}
	clientSessions map[int]map[string]struct{}
	connectionLock sync.Mutex

	blockedProxies   map[string]struct{}
	blockedByType    map[string]int64
	blockedProxiesMu sync.RWMutex

	attackMode          int
	attackerObserved    map[string]struct{}
	attackerObservedByT map[string]int64
	// First-seen unique proxy counts by prober NAT and proxy type (keys: unrestricted, restricted, unknown, …).
	attackerObservedByNATAndType map[string]map[string]int64
	// Per prober NAT: proxy keys this NAT has matched at least once (for minute-coverage vs global first-seen).
	attackerSeenProxyByNAT map[string]map[string]struct{}
	attackerObservedMu     sync.RWMutex
	attackEnumPath         string
	attackEnumFile         *os.File
	attackEnumMu           sync.Mutex

	inFlightIPCCalls    atomic.Int64
	maxInFlightIPCCalls atomic.Int64
	totalIPCCalls       atomic.Int64
	maxIPCRealNanos     atomic.Int64
	currentSimUnixNanos atomic.Int64

	timeSteps              atomic.Int64
	totalAdvancedFakeNanos atomic.Int64
	backpressurePauses     atomic.Int64

	churnCycles       atomic.Int64
	churnCatchupHours atomic.Int64

	maxRuntimeGoroutines atomic.Int64

	blockingIPCCalls atomic.Int64
}

// SimulationStats tracks statistics during simulation
type SimulationStats struct {
	TotalPolls                int64
	SuccessfulMatches         int64
	IdlePolls                 int64
	RejectedPolls             int64
	ProxyTypes                map[string]int64
	NATTypes                  map[string]int64
	AverageResponseTime       time.Duration
	TotalResponseTime         time.Duration
	ClientFetchRetries        int64
	ClientFetchRetriesBlocked int64

	InFlightIPCCalls    int64
	MaxInFlightIPCCalls int64
	TotalIPCCalls       int64
	MaxIPCRealDuration  time.Duration
	BlockingIPCCalls    int64

	TimeSteps             int64
	TotalAdvancedFakeTime time.Duration
	BackpressurePauses    int64

	ChurnCycles       int64
	ChurnCatchupHours int64

	RuntimeGoroutines    int
	MaxRuntimeGoroutines int64
}

// NewProxyPollSimulator creates a new simulator instance using the given IPC.
func NewProxyPollSimulator(ipc IPCInterface) *ProxyPollSimulator {
	attackMode := getEnvInt("SNOWFLAKE_SIM_ATTACK_MODE", 1)
	if attackMode != 0 && attackMode != 1 {
		log.Printf("invalid SNOWFLAKE_SIM_ATTACK_MODE=%d, using 1 (blocking)", attackMode)
		attackMode = 1
	}
	attackEnumPath := strings.TrimSpace(os.Getenv("SNOWFLAKE_SIM_ATTACK_ENUM_FILE"))

	sim := &ProxyPollSimulator{
		ipc:            ipc,
		stats:          &SimulationStats{ProxyTypes: make(map[string]int64), NATTypes: make(map[string]int64)},
		stopChan:       make(chan struct{}),
		debugMode:      getEnvBool("SNOWFLAKE_SIM_DEBUG", false),
		eventLogs:      getEnvBool("SNOWFLAKE_SIM_EVENT_LOGS", false),
		proxyStartTime: make(map[string]time.Time),
		connections:    make(map[string]*connection),
		clientStates:   make(map[int]*clientState),
		proxySessions:  make(map[string]map[string]struct{}),
		clientSessions: make(map[int]map[string]struct{}),
		blockedProxies: make(map[string]struct{}),
		blockedByType: map[string]int64{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		attackMode:       attackMode,
		attackerObserved: make(map[string]struct{}),
		attackerObservedByT: map[string]int64{
			"standalone": 0,
			"webext":     0,
			"iptproxy":   0,
		},
		attackerObservedByNATAndType: map[string]map[string]int64{
			"unrestricted": {"standalone": 0, "webext": 0, "iptproxy": 0},
			"restricted":   {"standalone": 0, "webext": 0, "iptproxy": 0},
			"unknown":      {"standalone": 0, "webext": 0, "iptproxy": 0},
		},
		attackEnumPath: attackEnumPath,
	}
	if err := sim.openAttackEnumFile(); err != nil {
		log.Printf("failed to open attacker enumeration file %q: %v", sim.attackEnumPath, err)
	}
	return sim
}

// NewSimulationMetricsLogger returns a logger that uses fake time when enabled (for broker context).
func NewSimulationMetricsLogger() *log.Logger {
	if globalFakeTime != nil {
		fakeWriter := &fakeTimeWriter{writer: os.Stdout}
		return log.New(fakeWriter, "", 0)
	}
	return log.New(os.Stdout, "", log.LstdFlags)
}
