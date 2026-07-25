### Title
Zero-`ValActive` State After Epoch Transition Permanently Breaks Permissionless Consensus — (`kaiax/valset/impl/transition_context.go`)

---

### Summary

`applyEpochTransition` can demote every validator to `ValInactive` in a single epoch boundary when all staking amounts fall below `MinStake`. The `committeeWithFallback` safety net only handles the case where all `ValActive` nodes are *suspended*; it does not handle the case where there are *no* `ValActive` nodes at all. The result is an empty qualified-validator set, an empty committee, and a broken proposer selection — consensus halts permanently until validators re-stake and survive the next epoch.

---

### Finding Description

**Root cause — `applyEpochTransition` lacks a last-validator guard**

At every epoch boundary, `applyEpochTransition` runs the `competeOrDemote` closure over every node in `{VA, VR, VP, CT}`:

```go
competeOrDemote := func(addr common.Address, val *valset.Node) {
    if val.StakingAmount >= ctx.MinStake {
        activeValCompetitors = append(activeValCompetitors, ...)  // T3a
    } else {
        val.State = valset.ValInactive  // T3b — unconditional
    }
}
``` [1](#0-0) 

If every validator's `StakingAmount < MinStake`, `activeValCompetitors` remains empty. The subsequent loop over `activeValCompetitors` never executes, and every node is left in `ValInactive`. There is no guard equivalent to the one in the permissioned path:

```go
// If all validators are demoted, then no one is demoted.
if demoted.Len() == len(council.List()) {
    demoted = valset.NewAddressSet(nil)
}
``` [2](#0-1) 

**Broken invariant propagates through `committeeWithFallback`**

After the epoch transition, `epochVACountForWrite = nodes.CountByState(ValActive) = 0`. `slotLimitsFor(0)` returns `(0, 0)` (both `MaxSlotAvailable` and `MinActiveCount` are zero for `n < 4`). [3](#0-2) [4](#0-3) 

`getQualifiedValidators` then calls `committeeWithFallback`:

```go
func committeeWithFallback(nodes valset.NodeMap) (committee valset.NodeMap, fellBack bool) {
    committee = nodes.Committee()          // FilterByState(ValActive).ExcludeSuspended() → empty
    if len(committee) > 0 {
        return committee, false
    }
    return nodes.FilterByState(valset.ValActive), true  // also empty — no ValActive exist
}
``` [5](#0-4) 

The fallback was designed for "all `ValActive` are suspended"; it cannot recover from "there are no `ValActive` at all." Both branches return an empty map.

**Downstream consensus failure**

`GetCommittee` and `GetQualifiedValidators` return empty slices. In `getRoundCommitteeState`, `committeeSize = 0` and `requiredMsgCnt = calcQuorumSize(qLen, 0)`. `GetProposer` selects from an empty list, returning an error. Block production and validation both fail. [6](#0-5) 

`verifySeals` in `BlockValidator` also fails: with an empty qualified set, `qualifiedSet.Contains(author)` is false, returning `ErrUnauthorized`. [7](#0-6) 

---

### Impact Explanation

Consensus halts permanently for the affected block number and all subsequent blocks. No new block can be proposed or validated. The chain is effectively frozen until validators re-stake above `MinStake` and survive the next epoch boundary. This is an **invalid state transition / consensus divergence** on all honest nodes — matching the allowed impact gate.

---

### Likelihood Explanation

The trigger requires all active validators to have their on-chain staking amounts drop below `MinStake` simultaneously before an epoch boundary. This can happen via:

1. **Coordinated voluntary unstaking** — all validators withdraw enough stake (a normal, unprivileged operation via their staking contracts).
2. **`MinStake` governance parameter** — `RewardMinimumStake` is `AlwaysDeprecated` for voting, so its value is fixed at genesis. However, if the genesis value is set high relative to actual stakes, or if validators collectively reduce stakes over time, the condition is reachable without any governance action.

The `applyViolationTransition` path (non-epoch blocks) correctly prevents this via `canDemoteActive`:

```go
canDemoteActive = func(targetState valset.NodeState) bool {
    return hasSlot(targetState) && newValidators.CountByState(valset.ValActive) > ctx.MinActiveCount
}
``` [8](#0-7) 

But `applyEpochTransition` has no equivalent floor, making the epoch path the only unguarded route to zero `ValActive`.

---

### Recommendation

Add a last-validator guard to `applyEpochTransition`, mirroring the permissioned path's existing protection. After the `activeValCompetitors` loop, if `CountByState(ValActive) == 0`, restore the highest-staked competitor(s) to `ValActive` unconditionally:

```go
// After the competition loop:
if nodes.CountByState(valset.ValActive) == 0 && len(activeValCompetitors) > 0 {
    // Promote the top-staked competitor regardless of MinStake to preserve liveness.
    activeValCompetitors[0].State = valset.ValActive
    activeValCompetitors[0].IdleTimeout = time.Time{}
    activeValCompetitors[0].PausedTimeout = time.Time{}
}
```

Alternatively, extend `committeeWithFallback` to fall back to the full council (all `{VA, VP}`) or even all registered nodes when `ValActive` is empty, consistent with the permissioned path's "if all demoted, none are demoted" rule. [9](#0-8) 

---

### Proof of Concept

**State before epoch block N:**
- All nodes: `{addr1: ValActive, StakingAmount: 1}, {addr2: ValActive, StakingAmount: 1}`
- `MinStake = 5_000_000`

**`applyEpochTransition` execution:**
1. `competeOrDemote(addr1)`: `1 < 5_000_000` → `addr1.State = ValInactive` (T3b)
2. `competeOrDemote(addr2)`: `1 < 5_000_000` → `addr2.State = ValInactive` (T3b)
3. `activeValCompetitors = []` — loop over competitors does not execute
4. Result: `{addr1: ValInactive, addr2: ValInactive}`

**`ApplyAllTransitions` after epoch:**
- `epochVACountForWrite = 0`
- `slotLimitsFor(0)` → `MaxSlotAvailable=0, MinActiveCount=0`
- `applyViolationTransition`: no `ValActive` to demote, no-op
- `applyTimeoutTransition`: sets `IdleTimeout` on `ValInactive` nodes, no state change yet

**`getQualifiedValidators(N+1)`:**
- `nodes.Committee()` = `FilterByState(ValActive).ExcludeSuspended()` = `{}`
- Fallback: `FilterByState(ValActive)` = `{}`
- Returns empty `AddressSet`

**`GetCommittee(N+1, 0)` = `[]`**

**`getRoundCommitteeState(N+1, 0)`:**
- `committeeSize = 0`
- `GetProposer(N+1, 0)` → error (empty proposer list)
- Consensus halts; no block N+1 can be produced or validated [3](#0-2) [10](#0-9) [6](#0-5)

### Citations

**File:** kaiax/valset/impl/transition_context.go (L133-150)
```go
func (ctx *TransitionContext) ApplyAllTransitions(nodes valset.NodeMap) *TransitionResult {
	epochVACountForWrite := uint64(0)

	if ctx.IsEpoch {
		nodes = ctx.applyEpochTransition(nodes)
		// After the epoch transition the active-validator count changes, so
		// slot limits must be recomputed before violation runs.
		epochVACountForWrite = nodes.CountByState(valset.ValActive)
		ctx.SetSlotsCtx(slotLimitsFor(epochVACountForWrite))
	}
	nodes = ctx.applyViolationTransition(nodes)
	nodes = ctx.applyTimeoutTransition(nodes)

	return &TransitionResult{
		Nodes:                nodes,
		epochVACountForWrite: epochVACountForWrite,
	}
}
```

**File:** kaiax/valset/impl/transition_context.go (L186-194)
```go
	competeOrDemote := func(addr common.Address, val *valset.Node) {
		if val.StakingAmount >= ctx.MinStake {
			activeValCompetitors = append(activeValCompetitors, sortableValidator{addr, val}) // T3a
		} else {
			if val.State != valset.ValReady {
				val.IdleTimeout = ctx.BlockTime.Add(ctx.IdleTimeout)
			}
			val.State = valset.ValInactive // T3b
		}
```

**File:** kaiax/valset/impl/transition_context.go (L218-238)
```go
	slices.SortFunc(activeValCompetitors, func(a, b sortableValidator) int {
		return cmp.Or(
			cmp.Compare(b.StakingAmount, a.StakingAmount),
			bytes.Compare(a.addr[:], b.addr[:]), // tie-breaking: address order
		)
	})
	for idx, potentialActiveVal := range activeValCompetitors {
		if uint64(idx) < ctx.MaxValActivePausedCount {
			if potentialActiveVal.State != valset.ValPaused {
				potentialActiveVal.State = valset.ValActive
				potentialActiveVal.IdleTimeout = time.Time{}
				potentialActiveVal.PausedTimeout = time.Time{}
			}
		} else {
			if potentialActiveVal.State != valset.ValReady {
				potentialActiveVal.IdleTimeout = ctx.BlockTime.Add(ctx.IdleTimeout)
			}
			potentialActiveVal.State = valset.ValInactive // T3b
		}
	}
	return newValidators
```

**File:** kaiax/valset/impl/transition_context.go (L279-281)
```go
		canDemoteActive = func(targetState valset.NodeState) bool {
			return hasSlot(targetState) && newValidators.CountByState(valset.ValActive) > ctx.MinActiveCount
		}
```

**File:** kaiax/valset/impl/transition_context.go (L410-428)
```go
func minActiveCount(n uint64) uint64 {
	if n < 4 {
		return n
	}
	return (2*n + 2) / 3
}

// maxSlotAvailable returns the maximum number of nodes allowed in
// ValPaused or ValExiting state each given epochVACount n.
func maxSlotAvailable(n uint64) uint64 {
	if n < 4 {
		return 0
	}
	return (n/3 + 1) / 2
}

// slotLimitsFor returns (maxSlotAvailable, minActiveCount) for epochVACount n.
func slotLimitsFor(n uint64) (uint64, uint64) {
	return maxSlotAvailable(n), minActiveCount(n)
```

**File:** kaiax/valset/impl/getter_demote.go (L94-97)
```go
	// If all validators are demoted, then no one is demoted.
	if demoted.Len() == len(council.List()) {
		demoted = valset.NewAddressSet(nil)
	}
```

**File:** kaiax/valset/impl/getter_permissionless.go (L37-58)
```go
func committeeWithFallback(nodes valset.NodeMap) (committee valset.NodeMap, fellBack bool) {
	committee = nodes.Committee()
	if len(committee) > 0 {
		return committee, false
	}

	// ignore SuspendedSet
	return nodes.FilterByState(valset.ValActive), true
}

// getQualifiedValidators: qualified = committee = {VA} − {Suspended} (with safety fallback).
func (v *ValsetModule) getQualifiedValidators(num uint64) (*valset.AddressSet, error) {
	nodes, err := v.getNodes(num)
	if err != nil {
		return nil, err
	}
	committee, fellBack := committeeWithFallback(nodes)
	if fellBack && v.lastSuspendFallbackLog != num {
		logger.Warn("all ValActive are suspended, ignoring suspended set for committee", "num", num)
		v.lastSuspendFallbackLog = num
	}
	return valset.NewAddressSet(committee.Addresses()), nil
```

**File:** consensus/istanbul/core/core.go (L46-74)
```go
func getRoundCommitteeState(c *core, seq, r uint64) (qualified *valset.AddressSet, committeeSet *valset.AddressSet, proposer common.Address, committeeSize uint64, requiredMsgCnt int, fNum int, err error) {
	if c.valsetModule == nil || c.govModule == nil {
		return nil, nil, common.Address{}, 0, 0, 0, istanbul.ErrNoEssentialModule
	}
	council, err := c.valsetModule.GetCouncil(seq)
	if err != nil {
		return nil, nil, common.Address{}, 0, 0, 0, err
	}
	demoted, err := c.valsetModule.GetDemotedValidators(seq)
	if err != nil {
		return nil, nil, common.Address{}, 0, 0, 0, err
	}
	// NOTE: don't use GetQualifiedValidators here because it duplicates the logic of GetDemotedValidators.
	qualified = valset.NewAddressSet(council).Subtract(valset.NewAddressSet(demoted))
	committeeAddrs, err := c.valsetModule.GetCommittee(seq, r)
	if err != nil {
		return nil, nil, common.Address{}, 0, 0, 0, err
	}
	proposer, err = c.valsetModule.GetProposer(seq, r)
	if err != nil {
		return nil, nil, common.Address{}, 0, 0, 0, err
	}
	committeeSet = valset.NewAddressSet(committeeAddrs)
	committeeSize = uint64(committeeSet.Len())

	qLen := qualified.Len()
	requiredMsgCnt = calcQuorumSize(qLen, committeeSize)
	fNum = calcFaultTolerance(qLen, committeeSize)
	return qualified, committeeSet, proposer, committeeSize, requiredMsgCnt, fNum, nil
```

**File:** blockchain/block_validator.go (L285-317)
```go
	qualified, err := v.mValset.GetQualifiedValidators(blockNum)
	if err != nil {
		return err
	}
	qualifiedSet := valset.NewAddressSet(qualified)
	if !qualifiedSet.Contains(author) {
		return consensus.ErrUnauthorized
	}

	signerSet := qualifiedSet.Copy()
	if !rules.IsPermissionless {
		council, err := v.mValset.GetCouncil(blockNum)
		if err != nil {
			return err
		}
		signerSet = valset.NewAddressSet(council).Copy()
	}
	validSeal, err := countValidCommittedSeals(committers, signerSet)
	if err != nil {
		return err
	}

	qualifiedLen := len(qualified)
	committeeSize := qualifiedLen
	if !gov.DeprecatedAt(gov.IstanbulCommitteeSize, rules) {
		committeeSize = int(v.mGov.GetParamSet(blockNum).CommitteeSize)
	}
	// Pre-permissionless uses the legacy 2f+1 quorum. sealer.Quorum now returns
	// ceil(2N/3), so compute 2f+1 explicitly to preserve historical header validity.
	if validSeal < 2*v.sealer.F(blockNum, qualifiedLen, committeeSize)+1 {
		return istanbul.ErrInvalidCommittedSeals
	}
	return nil
```
