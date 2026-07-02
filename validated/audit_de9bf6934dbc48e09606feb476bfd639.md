### Title
Single Compromised Consensus Node Can Manipulate the `NewestQC` Embedded in a Partial TC, Skewing View-Change Decisions - (File: `consensus/hotstuff/timeoutcollector/timeout_processor.go`)

---

### Summary

A single compromised consensus node can supply a `TimeoutObject` carrying a `NewestQC` with an arbitrarily chosen (but cryptographically valid) view number. Because the `OnPartialTcCreated` notification is fired as soon as the superminority weight threshold (>1/3) is crossed, and the `NewestQC` embedded in that notification is taken directly from the first timeout that crosses the threshold, a single node whose weight alone exceeds the superminority threshold can unilaterally determine which `NewestQC` is broadcast to all other replicas via `OnPartialTcCreated`. This causes every honest replica that receives the partial TC to immediately call `paceMaker.ProcessQC(partialTC.NewestQC)`, potentially triggering a premature view change to an attacker-chosen view.

---

### Finding Description

In `TimeoutProcessor.Process` (`consensus/hotstuff/timeoutcollector/timeout_processor.go`), after a timeout object passes signature validation, the processor:

1. Updates `newestQCTracker` with the QC from the incoming timeout.
2. Adds the signer's weight to `sigAggregator`.
3. Checks whether the accumulated weight has crossed the **partial-TC threshold** (`timeoutThreshold = floor(totalWeight/3) + 1`).
4. If so, fires `OnPartialTcCreated(p.view, p.newestQCTracker.NewestQC(), timeout.LastViewTC)`. [1](#0-0) 

The `newestQCTracker` is a simple max-by-view tracker: [2](#0-1) 

The partial-TC threshold is `floor(totalWeight/3) + 1`: [3](#0-2) 

This means that if a single node holds weight **≥ floor(totalWeight/3) + 1** (i.e., it alone constitutes a superminority), it can be the very first timeout processed, causing `newestQCTracker` to record its chosen QC view, and immediately triggering `OnPartialTcCreated` with that QC.

The `EventHandler.OnPartialTcCreated` then unconditionally calls `paceMaker.ProcessQC(partialTC.NewestQC)`: [4](#0-3) 

`ProcessQC` advances the local view to `newestQC.View + 1` if that view is higher than the current view: [5](#0-4) 

The `TimeoutCollector` interface documents this threshold explicitly: [6](#0-5) 

---

### Impact Explanation

A single consensus node holding weight ≥ 1/3 of the total committee weight (the superminority threshold) can:

1. Craft a `TimeoutObject` embedding a `NewestQC` pointing to any valid, previously-seen QC (the QC itself must pass `validator.ValidateQC`, so it must be a real, cryptographically valid QC for some past view).
2. Submit it first to the `TimeoutProcessor`.
3. Cause `OnPartialTcCreated` to fire with that attacker-chosen `NewestQC`.
4. Force every honest replica that processes this partial TC to call `paceMaker.ProcessQC` with the attacker's QC, potentially jumping the local view forward to `attackerQC.View + 1`.

This is the Flow analog of the oracle median manipulation: just as a single oracle can shift the dAPI median to any value between the min and max of honest oracles, a single consensus node can shift the `NewestQC` view embedded in the partial TC to any view for which it holds a valid QC — skewing the view at which honest replicas begin their timeout countdown, and potentially causing them to skip views, miss proposals, or time out prematurely.

The impact is **consensus liveness interference**: honest replicas may be forced into a view for which no leader is prepared to propose, causing unnecessary view timeouts and degrading throughput. In the worst case (attacker supplies a QC for a very high view), honest replicas could be pushed far ahead, breaking the normal view-progression invariant.

---

### Likelihood Explanation

This requires a single consensus node whose individual weight meets or exceeds the superminority threshold (`floor(totalWeight/3) + 1`). In a committee where weights are roughly equal, this requires controlling approximately 1/3 of the total stake — a significant but not impossible condition in a permissioned or semi-permissioned network. The attacker only needs to be a legitimate, staked consensus participant; no key compromise of other nodes is required. The attack is reachable via the normal `AddTimeout` path on any consensus node's `TimeoutCollector`. [7](#0-6) 

---

### Recommendation

- **Short term:** Monitor for `OnPartialTcCreated` events where the embedded `NewestQC.View` is significantly ahead of the expected view progression. Alert on anomalous view jumps.
- **Long term:** Before firing `OnPartialTcCreated`, require that the `NewestQC` embedded in the notification is the **median** (or at minimum the **minimum**) of the `NewestQC.View` values contributed by the signers that crossed the threshold, rather than the maximum tracked by `newestQCTracker`. This mirrors the dAPI recommendation: make the aggregated value robust against a single participant's manipulation by using a statistic that requires a majority to shift, not just the first contributor.

---

### Proof of Concept

1. Assume a committee of 10 nodes each with weight 100 (total = 1000). Superminority threshold = `floor(1000/3) + 1 = 334`. A single node with weight ≥ 334 (e.g., weight 334) meets the threshold alone.
2. Attacker node holds a valid QC for view 9999 (obtained legitimately from a prior epoch or by observing network traffic).
3. Attacker submits `TimeoutObject{View: currentView, NewestQC: QC{View: 9999}, ...}` to the `TimeoutProcessor`.
4. `newestQCTracker.Track(QC{View:9999})` records view 9999.
5. `sigAggregator.VerifyAndAdd(...)` returns `totalWeight = 334 ≥ timeoutThreshold`.
6. `partialTCTracker.Track(334)` returns `true` (first time threshold is crossed).
7. `notifier.OnPartialTcCreated(currentView, QC{View:9999}, nil)` fires.
8. `EventHandler.OnPartialTcCreated` calls `paceMaker.ProcessQC(QC{View:9999})`.
9. All honest replicas jump to view 10000, skipping any intermediate proposals. [8](#0-7) [9](#0-8)

### Citations

**File:** consensus/hotstuff/timeoutcollector/timeout_processor.go (L86-96)
```go
		partialTCTracker: accumulatedWeightTracker{
			minRequiredWeight: timeoutThreshold,
			done:              *atomic.NewBool(false),
		},
		tcTracker: accumulatedWeightTracker{
			minRequiredWeight: qcThreshold,
			done:              *atomic.NewBool(false),
		},
		sigAggregator:   sigAggregator,
		newestQCTracker: tracker.NewNewestQCTracker(),
	}, nil
```

**File:** consensus/hotstuff/timeoutcollector/timeout_processor.go (L134-152)
```go
	p.newestQCTracker.Track(timeout.NewestQC)

	totalWeight, err := p.sigAggregator.VerifyAndAdd(timeout.SignerID, timeout.SigData, timeout.NewestQC.View)
	if err != nil {
		if model.IsInvalidSignerError(err) {
			return model.NewInvalidTimeoutErrorf(timeout, "invalid signer for timeout: %w", err)
		}
		if errors.Is(err, model.ErrInvalidSignature) {
			return model.NewInvalidTimeoutErrorf(timeout, "timeout is from valid signer but has cryptographically invalid signature: %w", err)
		}
		// model.DuplicatedSignerError is an expected error and just bubbled up the call stack.
		// It does _not necessarily_ imply that the timeout is invalid or the sender is equivocating.
		return fmt.Errorf("adding signature to aggregator failed: %w", err)
	}
	p.log.Debug().Msgf("processed timeout, total weight=(%d), required=(%d)", totalWeight, p.tcTracker.minRequiredWeight)

	if p.partialTCTracker.Track(totalWeight) {
		p.notifier.OnPartialTcCreated(p.view, p.newestQCTracker.NewestQC(), timeout.LastViewTC)
	}
```

**File:** consensus/hotstuff/tracker/tracker.go (L26-43)
```go
// Track updates local state of NewestQC if the provided instance is newer(by view)
// Concurrently safe
func (t *NewestQCTracker) Track(qc *flow.QuorumCertificate) bool {
	// to record the newest value that we have ever seen we need to use loop
	// with CAS atomic operation to make sure that we always write the latest value
	// in case of shared access to updated value.
	for {
		// take a snapshot
		newestQC := t.NewestQC()
		// verify that our update makes sense
		if newestQC != nil && newestQC.View >= qc.View {
			return false
		}
		// attempt to install new value, repeat in case of shared update.
		if t.newestQC.CompareAndSwap(unsafe.Pointer(newestQC), unsafe.Pointer(qc)) {
			return true
		}
	}
```

**File:** consensus/hotstuff/committees/threshold.go (L19-25)
```go
// WeightThresholdToTimeout returns the weight (sum of unique, valid timeout objects for this view)
// that is minimally required to immediately timeout and build a TO.
func WeightThresholdToTimeout(totalWeight uint64) uint64 {
	// Given totalWeight, we need the smallest integer t such that totalWeight / 3 < t
	// Formally, the minimally required weight is: Floor(totalWeight/3) + 1
	return totalWeight/3 + 1
}
```

**File:** consensus/hotstuff/eventhandler/event_handler.go (L213-256)
```go
func (e *EventHandler) OnPartialTcCreated(partialTC *hotstuff.PartialTcCreated) error {
	curView := e.paceMaker.CurView()
	lastViewTC := partialTC.LastViewTC
	logger := e.log.With().
		Uint64("cur_view", curView).
		Uint64("qc_view", partialTC.NewestQC.View)
	if lastViewTC != nil {
		logger.Uint64("last_view_tc_view", lastViewTC.View)
	}
	log := logger.Logger()
	log.Debug().Msg("constructed partial TC")

	e.notifier.OnPartialTc(curView, partialTC)
	defer e.notifier.OnEventProcessed()

	// process QC, this might trigger view change
	_, err := e.paceMaker.ProcessQC(partialTC.NewestQC)
	if err != nil {
		return fmt.Errorf("could not process newest QC: %w", err)
	}

	// process TC, this might trigger view change
	_, err = e.paceMaker.ProcessTC(lastViewTC)
	if err != nil {
		return fmt.Errorf("could not process TC for view %d: %w", lastViewTC.View, err)
	}

	// NOTE: in other cases when we have observed a view change we will trigger proposing logic, this is desired logic
	// for handling proposal, QC and TC. However, observing a partial TC means
	// that superminority have timed out and there was at least one honest replica in that set. Honest replicas will never vote
	// after timing out for current view meaning we won't be able to collect supermajority of votes for a proposal made after
	// observing partial TC.

	// by definition, we are allowed to produce timeout object if we have received partial TC for current view
	if e.paceMaker.CurView() != partialTC.View {
		return nil
	}

	log.Debug().Msg("partial TC generated for current view, broadcasting timeout")
	err = e.broadcastTimeoutObjectIfAuthorized()
	if err != nil {
		return fmt.Errorf("unexpected exception while processing partial TC in view %d: %w", partialTC.View, err)
	}
	return nil
```

**File:** consensus/hotstuff/pacemaker/view_tracker.go (L59-81)
```go
func (vt *viewTracker) ProcessQC(qc *flow.QuorumCertificate) (uint64, error) {
	view := vt.livenessData.CurrentView
	if qc.View < view {
		// If the QC is for a past view, our view does not change. Nevertheless, the QC might be
		// newer than the newest QC we know, since view changes can happen through TCs as well.
		// While not very likely, is is possible that individual replicas know newer QCs than the
		// ones previously included in TCs. E.g. a primary that crashed before it could construct
		// its block is has rebooted and is now sharing its newest QC as part of a TimeoutObject.
		err := vt.updateNewestQC(qc)
		if err != nil {
			return view, fmt.Errorf("could not update tracked newest QC: %w", err)
		}
		return view, nil
	}

	// supermajority of replicas have already voted during round `qc.view`, hence it is safe to proceed to subsequent view
	newView := qc.View + 1
	err := vt.updateLivenessData(newView, qc, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to update liveness data: %w", err)
	}
	return newView, nil
}
```

**File:** consensus/hotstuff/timeout_collector.go (L13-20)
```go
	// AddTimeout adds a Timeout Object [TO] to the collector.
	// When TOs from strictly more than 1/3 of consensus participants (measured by weight)
	// were collected, the callback for partial TC will be triggered.
	// After collecting TOs from a supermajority, a TC will be created and passed to the EventLoop.
	// Expected error returns during normal operations:
	// * timeoutcollector.ErrTimeoutForIncompatibleView - submitted timeout for incompatible view
	// All other exceptions are symptoms of potential state corruption.
	AddTimeout(timeoutObject *model.TimeoutObject) error
```
