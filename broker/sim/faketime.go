package sim

import (
	"container/heap"
	"log"
	"os"
	"sync"
	"time"
)

// simulationStartTime is set when ProxyPollSimulation starts, used for hourly target indexing
var simulationStartTime time.Time

// faketime provides controllable time for simulation
type faketime struct {
	mu          sync.Mutex
	now         time.Time
	nextTimerID int64
	timers      fakeTimerHeap
}

type fakeTimer struct {
	id       int64
	deadline time.Time
	ch       chan time.Time
}

type fakeTimerHeap []*fakeTimer

func (h fakeTimerHeap) Len() int { return len(h) }

func (h fakeTimerHeap) Less(i, j int) bool {
	if h[i].deadline.Equal(h[j].deadline) {
		return h[i].id < h[j].id
	}
	return h[i].deadline.Before(h[j].deadline)
}

func (h fakeTimerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *fakeTimerHeap) Push(x interface{}) {
	*h = append(*h, x.(*fakeTimer))
}

func (h *fakeTimerHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

var globalFakeTime *faketime

// FakeTimeStepMu ensures time only advances after sim-side work at the current time is done.
// Hold RLock only around code that uses fake time and does NOT call the broker (IPC).
// The advance loop holds Lock() so it blocks until no RLock is held.
var FakeTimeStepMu sync.RWMutex

// UseFakeTime enables fake time mode with initial time
func UseFakeTime(initialTime time.Time) {
	globalFakeTime = &faketime{
		now:    initialTime,
		timers: make(fakeTimerHeap, 0),
	}
	heap.Init(&globalFakeTime.timers)
	// Configure logging to use fake time
	setupFakeTimeLogging()
}

// AdvanceFakeTime advances fake time by the given duration
func AdvanceFakeTime(d time.Duration) {
	if globalFakeTime == nil {
		return
	}
	globalFakeTime.mu.Lock()
	defer globalFakeTime.mu.Unlock()
	globalFakeTime.now = globalFakeTime.now.Add(d)

	// Trigger all timers due at or before the new fake time.
	for globalFakeTime.timers.Len() > 0 {
		next := globalFakeTime.timers[0]
		if next.deadline.After(globalFakeTime.now) {
			break
		}
		timer := heap.Pop(&globalFakeTime.timers).(*fakeTimer)
		select {
		case timer.ch <- globalFakeTime.now:
		default:
		}
	}
}

// FakeTimeNow returns fake time if enabled, otherwise real time. Exported for broker use.
func FakeTimeNow() time.Time {
	return fakeTimeNow()
}

func fakeTimeNow() time.Time {
	if globalFakeTime != nil {
		globalFakeTime.mu.Lock()
		defer globalFakeTime.mu.Unlock()
		return globalFakeTime.now
	}
	return time.Now()
}

// FakeTimeAfter returns a channel that fires after duration in fake time. Exported for broker use.
func FakeTimeAfter(d time.Duration) <-chan time.Time {
	return fakeTimeAfter(d)
}

func fakeTimeAfter(d time.Duration) <-chan time.Time {
	if globalFakeTime != nil {
		globalFakeTime.mu.Lock()
		defer globalFakeTime.mu.Unlock()
		ch := make(chan time.Time, 1)
		if d <= 0 {
			ch <- globalFakeTime.now
			return ch
		}
		globalFakeTime.nextTimerID++
		timer := &fakeTimer{
			id:       globalFakeTime.nextTimerID,
			deadline: globalFakeTime.now.Add(d),
			ch:       ch,
		}
		heap.Push(&globalFakeTime.timers, timer)
		return ch
	}
	return time.After(d)
}

// FakeTimePendingTimers returns the number of currently scheduled fake timers.
func FakeTimePendingTimers() int {
	if globalFakeTime == nil {
		return 0
	}
	globalFakeTime.mu.Lock()
	defer globalFakeTime.mu.Unlock()
	return globalFakeTime.timers.Len()
}

// RemovalLogInterval returns the duration to use for snowflake-removal log bucketing.
// In simulation this follows SNOWFLAKE_SIM_DEBUG_EVERY_SEC (same as debug summary interval); otherwise 1 minute.
func RemovalLogInterval() time.Duration {
	if globalFakeTime == nil {
		return time.Minute
	}
	sec := getEnvInt("SNOWFLAKE_SIM_DEBUG_EVERY_SEC", 60)
	if sec <= 0 {
		sec = 60
	}
	return time.Duration(sec) * time.Second
}

// FakeTimeTicker provides a ticker that works with fake time. Exported for broker use.
type FakeTimeTicker struct {
	C          <-chan time.Time
	c          chan time.Time
	stop       chan struct{}
	period     time.Duration
	stopped    bool
	mu         sync.Mutex
	realTicker *time.Ticker
}

// FakeTimeNewTicker returns a ticker that works with fake time. Exported for broker use.
func FakeTimeNewTicker(d time.Duration) *FakeTimeTicker {
	return fakeTimeNewTicker(d)
}

func fakeTimeNewTicker(d time.Duration) *FakeTimeTicker {
	if globalFakeTime != nil {
		c := make(chan time.Time, 1)
		ticker := &FakeTimeTicker{
			C:      c,
			c:      c,
			stop:   make(chan struct{}),
			period: d,
		}
		// Start a goroutine that will fire ticks when fake time advances
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("fakeTimeTicker goroutine panic: %v", r)
				}
			}()
			for {
				select {
				case <-ticker.stop:
					return
				case tickTime := <-fakeTimeAfter(d):
					select {
					case ticker.c <- tickTime:
					default:
					}
				}
			}
		}()
		return ticker
	}
	// Use real ticker if fake time is not enabled
	realTicker := time.NewTicker(d)
	return &FakeTimeTicker{
		C:          realTicker.C,
		stop:       make(chan struct{}),
		period:     d,
		realTicker: realTicker,
	}
}

// Stop stops the ticker
func (t *FakeTimeTicker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.stopped = true
	if t.realTicker != nil {
		t.realTicker.Stop()
	} else {
		close(t.stop)
	}
}

// fakeTimeWriter wraps an io.Writer and prepends fake time timestamps
type fakeTimeWriter struct {
	writer interface {
		Write([]byte) (int, error)
	}
}

func (w *fakeTimeWriter) Write(p []byte) (n int, err error) {
	if globalFakeTime != nil {
		now := FakeTimeNow()
		timestamp := now.Format("2006/01/02 15:04:05 ")
		_, err = w.writer.Write([]byte(timestamp))
		if err != nil {
			return 0, err
		}
	}
	return w.writer.Write(p)
}

// setupFakeTimeLogging configures the standard log package to use fake time
func setupFakeTimeLogging() {
	if globalFakeTime != nil {
		fakeWriter := &fakeTimeWriter{writer: os.Stderr}
		log.SetOutput(fakeWriter)
		log.SetFlags(0) // Remove default timestamp flags since we add our own
	}
}

func (sim *ProxyPollSimulator) setSimulationTime(now time.Time) {
	sim.currentSimUnixNanos.Store(now.UTC().UnixNano())
}

func (sim *ProxyPollSimulator) simulationNow() time.Time {
	ns := sim.currentSimUnixNanos.Load()
	if ns != 0 {
		return time.Unix(0, ns).UTC()
	}
	if globalFakeTime != nil {
		return fakeTimeNow().UTC()
	}
	return time.Unix(0, 0).UTC()
}
