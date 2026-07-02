### Title
Stale `requiredApprovalsForSealConstruction` Snapshot in `AssignmentCollectorBase` After Runtime Config Update - (`File: engine/consensus/approvals/assignment_collector_base.go`)

---

### Summary

The `requiredApprovalsForSealConstruction` threshold is a runtime-updatable configuration value. When a new `AssignmentCollector` is created for an execution result, the threshold is read **once** from the live config and stored as a plain `uint` field in `AssignmentCollectorBase`. If an operator later raises the threshold via `SetRequiredApprovalsForSealingConstruction`, all already-created collectors continue to use the old (lower) threshold, allowing execution results to be sealed with fewer approvals than the updated policy requires.

---

### Finding Description

`sealingConfigs.requiredApprovalsForSealConstruction` is an `atomic.Uint32` that can be updated at runtime through the admin gRPC interface via `SetRequiredApprovalsForSealingConstruction`. [1](#0-0) 

When `sealing.Core` creates a new `AssignmentCollector` for an incoming execution result, it calls `RequireApprovalsForSealConstructionDynamicValue()` **once** and passes the result as a plain `uint` to `NewAssignmentCollectorBase`: [2](#0-1) 

That value is stored as an immutable field in `AssignmentCollectorBase`: [3](#0-2) 

It is then forwarded verbatim to every `ChunkApprovalCollector` at construction time: [4](#0-3) 

`ChunkApprovalCollector.ProcessApproval` uses this frozen value to decide when a chunk has enough approvals to seal: [5](#0-4) 

Because the threshold is captured at collector-creation time and never refreshed, any collector that was instantiated before the threshold was raised will continue to seal with the old (lower) requirement.

---

### Impact Explanation

An operator raises `requiredApprovalsForSealConstruction` from `N` to `M` (M > N) via the admin interface to tighten the sealing policy. All `AssignmentCollector` instances that were already created for pending execution results retain the old threshold `N`. Those collectors will produce candidate seals with only `N` approvals per chunk, bypassing the updated policy. The `sealValidator` at the consensus node re-reads the dynamic value at validation time: [6](#0-5) 

This means the seal validator **will** apply the new threshold when validating a proposed block, so a seal produced by a stale collector with only `N` approvals will be **rejected** by the validator. The practical impact is therefore a **sealing liveness degradation**: the consensus node will keep producing candidate seals that fail validation, stalling sealing progress until the stale collectors are pruned and new ones are created with the updated threshold. This is not a security bypass in the direction of weakening verification, but it is a correctness/liveness issue caused by the stale threshold snapshot.

Conversely, if the threshold is **lowered** (M < N), newly created collectors use the lower threshold while existing collectors still require the higher count — those existing collectors will never seal until they receive the old (higher) number of approvals, again causing a liveness stall for results that were already in-flight.

---

### Likelihood Explanation

The `requiredApprovalsForSealConstruction` value is explicitly designed to be updatable at runtime: [7](#0-6) 

Any operator with access to the consensus node's admin gRPC endpoint can trigger this. The window of exposure is the lifetime of all `AssignmentCollector` instances that were alive at the time of the update — potentially covering many unsealed finalized blocks. The condition is reachable without any special privilege beyond admin access to the node's own configuration interface.

---

### Recommendation

Instead of storing a plain `uint` snapshot in `AssignmentCollectorBase`, store a reference to the `module.SealingConfigsGetter` interface and call `RequireApprovalsForSealConstructionDynamicValue()` each time the threshold is needed (i.e., inside `ChunkApprovalCollector.ProcessApproval`). This mirrors the pattern already used correctly in `sealValidator.validateSeal`: [6](#0-5) 

Alternatively, document explicitly that changing `requiredApprovalsForSealConstruction` only takes effect for execution results incorporated **after** the change, and that in-flight collectors retain the old threshold — matching the client's accepted behavior in the analogous SoftClay finding.

---

### Proof of Concept

1. Consensus node starts with `requiredApprovalsForSealConstruction = 1`.
2. Execution result R is incorporated; `AssignmentCollector` for R is created, capturing threshold `= 1` in `AssignmentCollectorBase.requiredApprovalsForSealConstruction`. [8](#0-7) 
3. Operator calls `SetRequiredApprovalsForSealingConstruction(3)` via admin gRPC. [9](#0-8) 
4. One verification approval arrives for R. `ChunkApprovalCollector.ProcessApproval` checks `c.requiredApprovalsForSealConstruction` (still `1`) and produces a candidate seal. [5](#0-4) 
5. `sealValidator.validateSeal` reads the live value `3` and rejects the seal because `numberApprovers (1) < requireApprovalsForSealConstruction (3)`. [10](#0-9) 
6. Sealing for R is stalled until the collector is pruned and recreated, or until 3 approvals accumulate (but the collector already fired and will not re-fire).

### Citations

**File:** module/updatable_configs/sealing_configs.go (L50-63)
```go
func (r *sealingConfigs) SetRequiredApprovalsForSealingConstruction(requiredApprovalsForSealConstruction uint) error {
	err := validation.ValidateRequireApprovals(
		requiredApprovalsForSealConstruction,
		r.requiredApprovalsForSealVerification,
		r.chunkAlpha,
	)
	if err != nil {
		return NewValidationErrorf("invalid: %w", err)
	}

	r.requiredApprovalsForSealConstruction.Store(uint32(requiredApprovalsForSealConstruction))

	return nil
}
```

**File:** engine/consensus/sealing/core.go (L94-103)
```go
	factoryMethod := func(result *flow.ExecutionResult) (approvals.AssignmentCollector, error) {
		requiredApprovalsForSealConstruction := sealingConfigsGetter.RequireApprovalsForSealConstructionDynamicValue()
		base, err := approvals.NewAssignmentCollectorBase(core.log, core.workerPool, result, core.state, core.headers,
			assigner, sealsMempool, signatureHasher,
			approvalConduit, core.requestTracker, requiredApprovalsForSealConstruction)
		if err != nil {
			return nil, fmt.Errorf("could not create base collector: %w", err)
		}
		return approvals.NewAssignmentCollectorStateMachine(base), nil
	}
```

**File:** engine/consensus/approvals/assignment_collector_base.go (L33-33)
```go
	requiredApprovalsForSealConstruction uint                            // number of approvals that are required for each chunk to be sealed
```

**File:** engine/consensus/approvals/approval_collector.go (L36-44)
```go
	requiredApprovalsForSealConstruction uint,
) (*ApprovalCollector, error) {
	chunkCollectors := make([]*ChunkApprovalCollector, 0, result.Result.Chunks.Len())
	for _, chunk := range result.Result.Chunks {
		assignedVerifiers, err := assignment.Verifiers(chunk.Index)
		if err != nil {
			return nil, fmt.Errorf("getting verifiers for chunk %d failed: %w", chunk.Index, err)
		}
		collector := NewChunkApprovalCollector(assignedVerifiers, requiredApprovalsForSealConstruction)
```

**File:** engine/consensus/approvals/chunk_collector.go (L34-36)
```go
		if c.chunkApprovals.NumberSignatures() >= c.requiredApprovalsForSealConstruction {
			return c.chunkApprovals.ToAggregatedSignature(), true
		}
```

**File:** module/validation/seal_validator.go (L309-322)
```go
		requireApprovalsForSealConstruction := s.sealingConfigsGetter.RequireApprovalsForSealConstructionDynamicValue()
		requireApprovalsForSealVerification := s.sealingConfigsGetter.RequireApprovalsForSealVerificationConst()
		if uint(numberApprovers) < requireApprovalsForSealConstruction {
			if uint(numberApprovers) >= requireApprovalsForSealVerification {
				// Emergency sealing is a _temporary_ fallback to reduce the probability of
				// sealing halts due to bugs in the verification nodes, where they don't
				// approve a chunk even though they should (false-negative).
				// TODO: remove this fallback for BFT
				emergencySealed = true
			} else {
				return engine.NewInvalidInputErrorf("chunk %d has %d approvals but require at least %d",
					chunk.Index, numberApprovers, requireApprovalsForSealVerification)
			}
		}
```

**File:** module/updatable_configs.go (L13-30)
```go
	// updatable fields
	RequireApprovalsForSealConstructionDynamicValue() uint

	// not-updatable fields
	ChunkAlphaConst() uint
	RequireApprovalsForSealVerificationConst() uint
	EmergencySealingActiveConst() bool
	ApprovalRequestsThresholdConst() uint64
}

// SealingConfigsSetter is an interface that allows the caller to update updatable configs
type SealingConfigsSetter interface {
	SealingConfigsGetter
	// SetRequiredApprovalsForSealingConstruction takes a new config value and updates the config
	// if the new value is valid.
	// Returns ValidationError if the new value results in an invalid sealing config.
	SetRequiredApprovalsForSealingConstruction(newVal uint) error
}
```
