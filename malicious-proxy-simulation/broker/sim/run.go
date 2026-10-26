package sim

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ProxyPollSimulation runs the proxy poll simulation with the given IPC and start time.
// Caller must have already started the broker (e.g. go ctx.Broker()).
// Blocks until the process receives an interrupt signal.
func ProxyPollSimulation(ipc IPCInterface, startTime time.Time) {
	simulationStartTime = startTime

	sim := NewProxyPollSimulator(ipc)
	sim.setSimulationTime(startTime.UTC())
	stepDuration := time.Second
	debugEvery := time.Duration(getEnvInt("SNOWFLAKE_SIM_DEBUG_EVERY_SEC", 5)) * time.Second
	if debugEvery <= 0 {
		debugEvery = 5 * time.Second
	}
	maxSimDays := getEnvFloat("SNOWFLAKE_SIM_MAX_SIM_DAYS", 0)
	maxSimDuration := time.Duration(0)
	if maxSimDays > 0 {
		maxSimDuration = time.Duration(maxSimDays * float64(24*time.Hour))
	}
	loop := newStepLoop(sim, startTime, stepDuration)
	standaloneInit := loop.targetCount("standalone", 0)
	webextInit := loop.targetCount("webext", 0)
	iptInit := loop.targetCount("iptproxy", 0)

	fmt.Println("Starting proxy poll simulation (step-loop mode)...")
	fmt.Printf("  - %d standalone proxies (hour 0 target)\n", standaloneInit)
	fmt.Printf("  - %d webext proxies (hour 0 target)\n", webextInit)
	fmt.Printf("  - %d iptproxy proxies (hour 0 target)\n", iptInit)
	fmt.Printf("  - %d clients (target active)\n", loop.clientTargetCount)
	if maxSimDuration > 0 {
		fmt.Printf("  - auto-stop after %s simulated time\n", maxSimDuration.Round(time.Second))
	}
	fmt.Println()
	loop.bootstrap()

	fmt.Println("Simulation running... Press Ctrl+C to stop")
	fmt.Println()
	if sim.debugMode {
		log.Printf(
			"Simulation debug mode enabled: step_duration=%s mode=single-loop prober_start=%s event_logs=%t",
			stepDuration,
			loop.proberStartAt.Format(time.RFC3339),
			sim.eventLogs,
		)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	currentTime := startTime.UTC()
	lastDebugFake := currentTime
	stepsCompleted := int64(0)
	for {
		select {
		case <-sigChan:
			loop.FlushPartialMinuteCoverageOnShutdown(currentTime)
			sim.Stop()
			if sim.debugMode {
				sim.logDebugSnapshot()
			}
			return
		default:
		}

		loop.runStep(currentTime)
		currentTime = currentTime.Add(stepDuration)
		sim.setSimulationTime(currentTime)
		AdvanceFakeTime(stepDuration)

		sim.recordTimeStep(stepDuration)
		stepsCompleted++
		if maxSimDuration > 0 && currentTime.Sub(startTime.UTC()) >= maxSimDuration {
			log.Printf(
				"Simulation reached SNOWFLAKE_SIM_MAX_SIM_DAYS=%.3f (sim_elapsed=%s), stopping",
				maxSimDays,
				currentTime.Sub(startTime.UTC()).Round(time.Second),
			)
			loop.FlushPartialMinuteCoverageOnShutdown(currentTime)
			sim.Stop()
			if sim.debugMode {
				loop.logStepSummary(currentTime)
				loop.logAttackerSummary(currentTime)
				sim.logDebugSnapshot()
			}
			return
		}
		if sim.debugMode && currentTime.Sub(lastDebugFake) >= debugEvery {
			loop.logStepSummary(currentTime)
			loop.logAttackerSummary(currentTime)
			sim.logDebugSnapshot()
			lastDebugFake = currentTime
		}
	}
}
