package sim

// Stop stops the continuous polling
// Closes the stop channel to signal all goroutines to exit immediately
func (sim *ProxyPollSimulator) Stop() {
	sim.safeCloseSignalChan(sim.stopChan)
	sim.closeAttackEnumFile()
	// Don't wait - goroutines will exit when they see the closed channel
}

func (sim *ProxyPollSimulator) safeCloseSignalChan(ch chan struct{}) {
	defer func() {
		_ = recover()
	}()
	close(ch)
}
