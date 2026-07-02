### Title
`SetEpochExtensionViewCount` Validation Uses Strict Less-Than, Allowing Boundary Value `2*FinalizationSafetyThreshold` to Pass — (`File: state/protocol/protocol_state/kvstore/models.go`)

### Summary

The `SetEpochExtensionViewCount` service event validation in `Modelv0.SetEpochExtensionViewCount` uses a strict `<` comparison, meaning a value of exactly `2*FinalizationSafetyThreshold` is accepted. However, the protocol comment and the `flow.SetEpochExtensionViewCount` struct's own documentation state the event is accepted **if and only if** `E.Value > 2*FinalizationSafetyThreshold` (strictly greater than). This is a boundary mismatch: the implementation accepts the boundary value that the specification says must be rejected.

### Finding Description

The `flow.SetEpochExtensionViewCount` struct documents the acceptance condition as:

> "A `SetEpochExtensionViewCount` event `E` is accepted while processing block `B` which seals `E` if and only if `E.Value > 2*FinalizationSafetyThreshold`." [1](#0-0) 

The enforcement in `Modelv0.SetEpochExtensionViewCount` is:

```go
if viewCount < model.FinalizationSafetyThreshold*2 {
    return fmt.Errorf("invalid view count %d, expect at least %d: %w", ...)
}
``` [2](#0-1) 

This check rejects values **strictly less than** `2*FinalizationSafetyThreshold`, meaning `viewCount == 2*FinalizationSafetyThreshold` passes validation and is stored. The specification requires `viewCount > 2*FinalizationSafetyThreshold` (strictly greater), so the boundary value `2*T` should be rejected but is not.

The `SetValueStateMachine.EvolveState` calls this setter directly when processing sealed service events: [3](#0-2) 

### Impact Explanation

When `EpochExtensionViewCount` is set to exactly `2*FinalizationSafetyThreshold`, the epoch extension window is exactly at the minimum boundary. The protocol's safety reasoning requires the extension to be **strictly larger** than `2*T` to guarantee the human governance committee has sufficient time to submit a valid epoch recovery transaction before the next extension threshold is reached. At exactly `2*T`, the safety margin collapses to zero: the next extension trigger fires at `FinalView + 2*T - T = FinalView + T`, which is exactly the finalization safety threshold away from the new final view — leaving no buffer for governance recovery. This can cause the protocol to enter a state where epoch recovery is impossible within the extension window, potentially leading to permanent epoch fallback mode with no recovery path. [4](#0-3) 

### Likelihood Explanation

The `SetEpochExtensionViewCount` service event is emitted by the Flow service account smart contract and sealed into blocks. Any transaction sender who can invoke the relevant service account function (or any governance participant who can submit such a transaction) can craft a `SetEpochExtensionViewCount` event with `Value == 2*FinalizationSafetyThreshold`. The `SetValueStateMachine` will accept and apply it without error, since the boundary value passes the `<` check. This is reachable via a normal Cadence transaction targeting the service account's governance interface. [5](#0-4) 

### Recommendation

Change the validation condition from strict less-than to less-than-or-equal, to enforce the documented invariant `viewCount > 2*FinalizationSafetyThreshold`:

```go
// Before (incorrect — allows boundary value):
if viewCount < model.FinalizationSafetyThreshold*2 {

// After (correct — enforces strict greater-than):
if viewCount <= model.FinalizationSafetyThreshold*2 {
``` [6](#0-5) 

Also update the error message and the `KVStoreMutator` interface docstring to reflect the corrected boundary (`> 2*T` rather than `>= 2*T`). [7](#0-6) 

### Proof of Concept

1. The service account emits `SetEpochExtensionViewCount{Value: 2 * FinalizationSafetyThreshold}` (e.g., `Value = 2000` on mainnet where `T = 1000`).
2. The event is sealed into a block and processed by `SetValueStateMachine.EvolveState`.
3. `Modelv0.SetEpochExtensionViewCount(2000)` is called. The check `2000 < 2000` is `false`, so no error is returned and `EpochExtensionViewCount` is set to `2000`.
4. The protocol specification at `model/flow/kvstore.go` line 6 states this value must be rejected (`E.Value > 2*T` required), but it is accepted.
5. In epoch fallback mode, `FallbackStateMachine` uses `GetEpochExtensionViewCount()` to compute the extension window. With `viewCount = 2*T`, the next extension threshold is `FinalView + 2*T - T = FinalView + T`, which is exactly at the safety threshold — providing zero buffer for governance recovery. [8](#0-7) [9](#0-8)

### Citations

**File:** model/flow/kvstore.go (L1-9)
```go
package flow

// SetEpochExtensionViewCount is a service event emitted by the FlowServiceAccount for updating
// the `EpochExtensionViewCount` parameter in the protocol state's key-value store.
// NOTE: A SetEpochExtensionViewCount event `E` is accepted while processing block `B`
// which seals `E` if and only if E.Value > 2*FinalizationSafetyThreshold.
type SetEpochExtensionViewCount struct {
	Value uint64
}
```

**File:** state/protocol/protocol_state/kvstore/models.go (L130-139)
```go
func (model *Modelv0) SetEpochExtensionViewCount(viewCount uint64) error {
	// Strictly speaking it should be perfectly fine to use a value viewCount >= model.FinalizationSafetyThreshold.
	// By using a slightly higher value (factor of 2), we ensure that each extension spans a sufficiently big time
	// window for the human governance committee to submit a valid epoch recovery transaction.
	if viewCount < model.FinalizationSafetyThreshold*2 {
		return fmt.Errorf("invalid view count %d, expect at least %d: %w", viewCount, model.FinalizationSafetyThreshold*2, ErrInvalidValue)
	}
	model.EpochExtensionViewCount = viewCount
	return nil
}
```

**File:** state/protocol/protocol_state/kvstore/set_value_statemachine.go (L42-62)
```go
func (m *SetValueStateMachine) EvolveState(orderedUpdates []flow.ServiceEvent) error {
	for _, update := range orderedUpdates {
		switch update.Type {
		case flow.ServiceEventSetEpochExtensionViewCount:
			setEpochExtensionViewCount, ok := update.Event.(*flow.SetEpochExtensionViewCount)
			if !ok {
				return fmt.Errorf("internal invalid type for SetEpochExtensionViewCount: %T", update.Event)
			}

			m.telemetry.OnServiceEventReceived(update)
			err := m.EvolvingState.SetEpochExtensionViewCount(setEpochExtensionViewCount.Value)
			if err != nil {
				if errors.Is(err, ErrInvalidValue) {
					m.telemetry.OnInvalidServiceEvent(update,
						protocol.NewInvalidServiceEventErrorf("ignoring invalid value %v in SetEpochExtensionViewCount event: %s",
							setEpochExtensionViewCount.Value, err.Error()))
					continue
				}
				return fmt.Errorf("unexpected error when processing SetEpochExtensionViewCount: %w", err)
			}
			m.telemetry.OnServiceEventProcessed(update)
```

**File:** state/protocol/protocol_state/kvstore.go (L67-70)
```go
	// SetEpochExtensionViewCount sets the number of views for a hypothetical epoch extension.
	// Expected errors during normal operations:
	//  - kvstore.ErrInvalidValue - if the view count is less than FinalizationSafetyThreshold*2.
	SetEpochExtensionViewCount(viewCount uint64) error
```

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
