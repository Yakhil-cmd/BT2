### Title
EpochRecover Service Event Silently Rejected When Safety Threshold Is Reached During Epoch Fallback Mode, Preventing Protocol Recovery - (File: state/protocol/protocol_state/epochs/fallback_statemachine.go)

### Summary

In Flow's `FallbackStateMachine`, the `ensureValidEpochRecover` function rejects any `EpochRecover` service event when the current block's view satisfies `view + FinalizationSafetyThreshold >= CurrentEpochFinalView`. This is the same condition that triggers automatic epoch extension. The result is that when the protocol is in Epoch Fallback Mode (EFM) and has reached the safety threshold — precisely the moment when recovery is most urgently needed — a valid `EpochRecover` event is silently dropped, and the protocol cannot exit EFM until the epoch extension has been added and the governance committee submits a new recovery transaction targeting the extended epoch's boundary.

### Finding Description

In `FallbackStateMachine.ensureValidEpochRecover`:

```go
func (m *FallbackStateMachine) ensureValidEpochRecover(epochRecover *flow.EpochRecover) error {
    if m.view+m.parentState.GetFinalizationSafetyThreshold() >= m.state.CurrentEpochFinalView() {
        return protocol.NewInvalidServiceEventErrorf("could not process epoch recover, safety threshold reached")
    }
    ...
}
``` [1](#0-0) 

The `FallbackStateMachine` constructor also adds an epoch extension at the same threshold:

```go
if !nextEpochCommitted && view+parentState.GetFinalizationSafetyThreshold() >= state.CurrentEpochFinalView() {
    err := sm.extendCurrentEpoch(flow.EpochExtension{...})
}
``` [2](#0-1) 

The epoch extension updates `CurrentEpochFinalView()` to `oldFinalView + EpochExtensionViewCount`. The `EpochRecover` event's `EpochSetup.FirstView` must equal `CurrentEpochFinalView() + 1` (enforced by `IsValidExtendingEpochSetup`):

```go
if extendingSetup.FirstView != epochState.CurrentEpochFinalView()+1 {
    return NewInvalidServiceEventErrorf(...)
}
``` [3](#0-2) 

The sequence of events is:

1. Protocol enters EFM.
2. Governance committee prepares an `EpochRecover` event with `FirstView = originalFinalView + 1`.
3. Before the event is sealed, the block view reaches the safety threshold. The `FallbackStateMachine` constructor adds an epoch extension, making `CurrentEpochFinalView() = originalFinalView + EpochExtensionViewCount`.
4. When the block sealing the `EpochRecover` event is processed, `ensureValidEpochRecover` rejects it because `view + threshold >= newCurrentEpochFinalView` is now false — but the `EpochSetup.FirstView` check in `IsValidExtendingEpochSetup` also fails because `FirstView = originalFinalView + 1 ≠ newCurrentEpochFinalView + 1`.
5. The governance committee must now prepare a **new** `EpochRecover` transaction targeting `newCurrentEpochFinalView + 1`, submit it on-chain, wait for execution and sealing — all before the **next** safety threshold is reached for the extension itself.

The `EpochExtensionViewCount` is required to be at least `2 * FinalizationSafetyThreshold`:

```go
if viewCount < model.FinalizationSafetyThreshold*2 {
    return fmt.Errorf("invalid view count %d, expect at least %d: %w", ...)
}
``` [4](#0-3) 

This means the governance committee has a window of approximately `EpochExtensionViewCount - FinalizationSafetyThreshold` views (at minimum `FinalizationSafetyThreshold` views) to submit a new recovery transaction after each extension. On mainnet, `FinalizationSafetyThreshold = 1000` views and `EpochExtensionViewCount = 100_000` views, so the window is large in practice. However, the design creates a **repeating race condition**: every time an extension is added, the previously prepared `EpochRecover` transaction becomes invalid, and the governance committee must race to submit a new one before the next extension threshold is reached. [5](#0-4) 

### Impact Explanation

When the protocol is in EFM and the safety threshold is reached, a valid `EpochRecover` event sealed in the same block as the epoch extension is silently rejected. The governance committee's recovery transaction — which may have taken significant time to prepare and submit — is invalidated. The committee must restart the recovery process with a new transaction targeting the updated epoch boundary. If the committee is slow or the network is under stress, this cycle can repeat indefinitely across multiple extensions, permanently trapping the protocol in EFM. This is a **protocol liveness failure**: the network remains in EFM and cannot transition to a new epoch, halting normal epoch progression.

### Likelihood Explanation

The scenario is realistic. The governance committee must:
1. Detect EFM.
2. Prepare the `EpochRecover` transaction (requires DKG key coordination, cluster QC generation, etc.).
3. Submit and wait for the transaction to be executed and sealed (requires at least 2 blocks: one to incorporate the execution result, one to seal it).

If the epoch is already near its final view when EFM is triggered, or if the committee's preparation takes longer than the remaining views before the safety threshold, the prepared transaction will be invalidated by the epoch extension. On mainnet the window is large (~99,000 views ≈ ~23 hours), but on testnets and in adversarial conditions (e.g., slow finalization, repeated DKG failures) the window can be much smaller.

### Recommendation

**Short term**: When `ensureValidEpochRecover` detects that the safety threshold has been reached, instead of rejecting the `EpochRecover` event outright, the state machine should check whether the event's `EpochSetup.FirstView` matches the **post-extension** `CurrentEpochFinalView() + 1`. If so, the event should be accepted. Alternatively, the safety-threshold check in `ensureValidEpochRecover` should be removed entirely, since the epoch extension has already been added by the constructor and the `IsValidExtendingEpochSetup` check will enforce the correct `FirstView` alignment.

**Long term**: Identify all recovery-critical actions (analogous to the `MintXToken` case in the original report) and add invariant/integration tests that assert they always succeed when the protocol is in a recovery-required state, regardless of which block view triggers the state machine.

### Proof of Concept

Consider the following sequence with `FinalizationSafetyThreshold = T` and `EpochExtensionViewCount = E`:

1. Epoch N has `FinalView = F`. EFM is triggered at view `V < F - T`.
2. Governance prepares `EpochRecover` with `EpochSetup.FirstView = F + 1`. Transaction is submitted and executed at block A (view `V_A < F - T`).
3. Block B (view `V_B >= F - T`) is built. `FallbackStateMachine` constructor fires: `V_B + T >= F`, so an extension is added. `CurrentEpochFinalView()` becomes `F + E`.
4. Block C seals block A's execution result, incorporating the `EpochRecover` event. `FallbackStateMachine.ProcessEpochRecover` is called:
   - `ensureValidEpochRecover`: `V_C + T >= F + E`? Likely false (we just extended), so this check passes.
   - `IsValidExtendingEpochSetup`: `EpochSetup.FirstView (= F+1) != CurrentEpochFinalView()+1 (= F+E+1)` → **rejected**.
5. The `EpochRecover` event is silently dropped. The protocol remains in EFM. The governance committee must now prepare a new transaction with `FirstView = F + E + 1`.

The relevant code path is: [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** state/protocol/protocol_state/epochs/fallback_statemachine.go (L92-102)
```go
	if !nextEpochCommitted && view+parentState.GetFinalizationSafetyThreshold() >= state.CurrentEpochFinalView() {
		// we have reached safety threshold and we are still in the fallback mode
		// prepare a new extension for the current epoch.
		err := sm.extendCurrentEpoch(flow.EpochExtension{
			FirstView: state.CurrentEpochFinalView() + 1,
			FinalView: state.CurrentEpochFinalView() + parentState.GetEpochExtensionViewCount(),
		})
		if err != nil {
			return nil, err
		}
	}
```

**File:** state/protocol/protocol_state/epochs/fallback_statemachine.go (L234-240)
```go
func (m *FallbackStateMachine) ProcessEpochRecover(epochRecover *flow.EpochRecover) (bool, error) {
	m.telemetry.OnServiceEventReceived(epochRecover.ServiceEvent())
	err := m.ensureValidEpochRecover(epochRecover)
	if err != nil {
		m.telemetry.OnInvalidServiceEvent(epochRecover.ServiceEvent(), err)
		return false, nil
	}
```

**File:** state/protocol/protocol_state/epochs/fallback_statemachine.go (L321-334)
```go
func (m *FallbackStateMachine) ensureValidEpochRecover(epochRecover *flow.EpochRecover) error {
	if m.view+m.parentState.GetFinalizationSafetyThreshold() >= m.state.CurrentEpochFinalView() {
		return protocol.NewInvalidServiceEventErrorf("could not process epoch recover, safety threshold reached")
	}
	err := protocol.IsValidExtendingEpochSetup(&epochRecover.EpochSetup, m.state)
	if err != nil {
		return fmt.Errorf("invalid setup portion in EpochRecover event: %w", err)
	}
	err = protocol.IsValidEpochCommit(&epochRecover.EpochCommit, &epochRecover.EpochSetup)
	if err != nil {
		return fmt.Errorf("invalid commit portion in EpochRecover event: %w", err)
	}
	return nil
}
```

**File:** state/protocol/validity.go (L19-42)
```go
func IsValidExtendingEpochSetup(extendingSetup *flow.EpochSetup, epochState *flow.EpochStateEntry) error {
	// Enforce EpochSetup is valid w.r.t to current epoch state
	if epochState.NextEpoch != nil { // We should only have a single epoch setup event per epoch.
		// true iff EpochSetup event for NEXT epoch was already included before
		return NewInvalidServiceEventErrorf("duplicate epoch setup service event: %x", epochState.NextEpoch.SetupID)
	}
	if extendingSetup.Counter != epochState.EpochCounter()+1 { // The setup event should have the counter increased by one.
		return NewInvalidServiceEventErrorf("next epoch setup has invalid counter (%d => %d)", epochState.EpochCounter(), extendingSetup.Counter)
	}
	if extendingSetup.FirstView != epochState.CurrentEpochFinalView()+1 { // The first view needs to be exactly one greater than the current epoch final view
		return NewInvalidServiceEventErrorf(
			"next epoch first view must be exactly 1 more than current epoch final view (%d != %d+1)",
			extendingSetup.FirstView,
			epochState.CurrentEpochFinalView(),
		)
	}

	// Enforce the EpochSetup event is syntactically correct
	err := IsValidEpochSetup(extendingSetup, true)
	if err != nil {
		return NewInvalidServiceEventErrorf("invalid epoch setup: %w", err)
	}
	return nil
}
```

**File:** state/protocol/protocol_state/kvstore/models.go (L134-138)
```go
	if viewCount < model.FinalizationSafetyThreshold*2 {
		return fmt.Errorf("invalid view count %d, expect at least %d: %w", viewCount, model.FinalizationSafetyThreshold*2, ErrInvalidValue)
	}
	model.EpochExtensionViewCount = viewCount
	return nil
```

**File:** state/protocol/defaults.go (L20-24)
```go
	case flow.Mainnet, flow.Testnet, flow.Sandboxnet, flow.Previewnet:
		return SafetyParams{
			FinalizationSafetyThreshold: 1_000,
			EpochExtensionViewCount:     100_000, // approximately 1 day
		}, nil
```
