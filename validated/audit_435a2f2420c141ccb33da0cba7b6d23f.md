### Title
Validator Below MinStake Retains `ValActive` Status and Receives Proposer Rewards When Demotion Slot Is Full — (`kaiax/valset/impl/transition_context.go`)

### Summary

`applyViolationTransition` skips the MinStake-violation demotion of a `ValActive` validator when the `ValExiting` slot is already occupied. The validator remains `ValActive`, stays eligible for proposer selection, and continues to receive KAIA proposer rewards despite holding stake below the protocol minimum. This is the direct Kaia analog of the external "over-leveraged withdrawal" pattern: a required protective check is bypassed because the system is already in a constrained state.

---

### Finding Description

`applyViolationTransition` runs every non-epoch block and enforces two violation rules. Rule 1 demotes any `ValActive` validator whose `StakingAmount` has fallen below `MinStake`:

```go
case valset.ValActive:
    if canDemoteActive(valset.ValExiting) {
        val.State = valset.ValExiting
    } else {
        logger.Trace("MinStake violation: slot full, skipping ValActive transition", ...)
    }
```

`canDemoteActive` is:

```go
canDemoteActive = func(targetState valset.NodeState) bool {
    return hasSlot(targetState) && newValidators.CountByState(valset.ValActive) > ctx.MinActiveCount
}
```

`hasSlot(ValExiting)` returns `false` when `CountByState(ValExiting) >= MaxSlotAvailable`. For a four-validator committee, `MaxSlotAvailable = 1`. If one validator is already in `ValExiting`, the slot is full and **every subsequent below-MinStake `ValActive` validator is silently skipped** — it stays `ValActive` with no demotion queued.

The comment in the code acknowledges the skip but frames it purely as a consensus-safety guard. It does not account for the fact that the skipped validator:

1. Remains in the `ValActive` pool used for proposer selection.
2. Continues to receive KAIA proposer rewards each block it is selected.
3. Is never re-evaluated for demotion until the next epoch transition (`applyEpochTransition` T3b), which may be many blocks away.

The `assignStakingRewards` function does gate *staking* rewards on `StakingAmount >= minStake`, so staking-portion rewards are withheld. However, proposer rewards flow through a separate path (`specWithProposerAndFunds`) that depends only on the validator being the block proposer — a role determined by `ValActive` membership, not by staking amount.

---

### Impact Explanation

A validator that has withdrawn its stake below `MinStake` can continue to be selected as block proposer and receive KAIA proposer rewards for every block it proposes during the window between the slot becoming full and the next epoch transition. The corrupted value is the proposer-reward KAIA credited to the validator's reward address — an unauthorized reward distribution from the protocol's minting budget.

---

### Likelihood Explanation

- `MaxSlotAvailable` is `ceil((n − ceil(2n/3)) / 2)`, which equals **1** for any committee of 3–5 validators and **2** for 6–10. The slot fills quickly under normal churn.
- After the Kaia hardfork, `StakingInfo` is sourced from the immediately preceding block, so a stake withdrawal is visible to `applyViolationTransition` within one block.
- A validator can observe on-chain state (another validator entering `ValExiting`) and time a stake withdrawal to the next block, guaranteeing the slot is full when their own violation is evaluated.
- No majority-validator collusion is required; a single validator acting alone can exploit this once any peer enters `ValExiting`.

---

### Recommendation

Track validators that were skipped due to a full slot in a "pending demotion" set. Re-evaluate them at every subsequent block until the slot frees, rather than waiting for the next epoch. Alternatively, at epoch transition, explicitly re-check all `ValActive` validators for MinStake compliance before running the top-N competition, ensuring no below-MinStake validator survives into the new epoch as `ValActive` regardless of slot state.

---

### Proof of Concept

**Setup:** 4 validators `{A, B, C, D}`, all `ValActive`, `MaxSlotAvailable = 1`, `MinActiveCount = 3`.

**Block N:**
- Validator A's PFS exceeds threshold → `canDemoteActive(ValExiting)` = true → A transitions to `ValExiting`. Slot is now full.

**Block N+1:**
- Validator B withdraws stake to `StakingAmount < MinStake` (visible via previous-block staking info).
- `applyViolationTransition` evaluates B: `StakingAmount < MinStake`, state = `ValActive`.
- `canDemoteActive(ValExiting)`: `hasSlot(ValExiting)` = **false** (A occupies the 1 slot).
- Demotion skipped. B remains `ValActive`.

**Blocks N+1 … epoch boundary:**
- B is included in proposer rotation. Each block B proposes, it receives the full KAIA proposer reward despite holding zero qualifying stake.
- A transitions `ValExiting → ValInactive` at the next epoch (T1), freeing the slot — but B has already collected rewards for every block it proposed in the interim. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** kaiax/valset/impl/transition_context.go (L269-316)
```go
func (ctx *TransitionContext) applyViolationTransition(m valset.NodeMap) valset.NodeMap {
	var (
		newValidators = m.Copy()
		// Slot/count helpers check the in-progress state of newValidators.
		// Counts change as validators transition within the loop, so these cannot be replaced with a contract call.
		hasSlot = func(state valset.NodeState) bool {
			return newValidators.CountByState(state) < ctx.MaxSlotAvailable
		}
		// canDemoteActive additionally ensures enough ValActive remain for consensus.
		// Used only when transitioning FROM ValActive (reducing active count).
		canDemoteActive = func(targetState valset.NodeState) bool {
			return hasSlot(targetState) && newValidators.CountByState(valset.ValActive) > ctx.MinActiveCount
		}
	)

	// Iterate in deterministic address order. Slot-limited transitions depend on
	// which validator is processed first, so random map iteration would be nondeterministic.
	sortedAddrs := newValidators.Addresses()

	// rule1: staking amount dropped below MinimumStake
	for _, addr := range sortedAddrs {
		val := newValidators[addr]
		if val.StakingAmount >= ctx.MinStake {
			continue
		}
		switch val.State {
		case valset.ValActive:
			// ValActive → ValExiting (slot + minActiveCount: removing an active validator reduces consensus participants)
			if canDemoteActive(valset.ValExiting) {
				logger.Trace("MinStake violation: ValActive → ValExiting", "addr", addr, "staking", val.StakingAmount, "minStake", ctx.MinStake)
				val.State = valset.ValExiting
			} else {
				logger.Trace("MinStake violation: slot full, skipping ValActive transition", "addr", addr, "staking", val.StakingAmount)
			}
		case valset.ValPaused:
			// ValPaused → ValExiting (slot only: ValPaused is already not in active set)
			if hasSlot(valset.ValExiting) {
				logger.Trace("MinStake violation: ValPaused → ValExiting", "addr", addr, "staking", val.StakingAmount, "minStake", ctx.MinStake)
				val.State = valset.ValExiting
			} else {
				logger.Trace("MinStake violation: slot full, skipping ValPaused transition", "addr", addr, "staking", val.StakingAmount)
			}
		case valset.ValReady:
			// ValReady → ValInactive (no slot check, not in active set)
			logger.Trace("MinStake violation: ValReady → ValInactive", "addr", addr, "staking", val.StakingAmount, "minStake", ctx.MinStake)
			val.State = valset.ValInactive
		}
	}
```

**File:** kaiax/valset/impl/transition_context_test.go (L547-561)
```go
	t.Run("minStake violation: skip when slot full", func(t *testing.T) {
		m := NodeMap{
			addr1: {State: ValActive, StakingAmount: belowMinStake},
			addr2: {State: ValActive, StakingAmount: belowMinStake},
			addr3: {State: ValActive, StakingAmount: aboveMinStake},
			addr4: {State: ValActive, StakingAmount: aboveMinStake},
		}
		ctx := violationCtx(t, ctxOpts{
			MaxSlotAvailable: slotMax,
			MinActiveCount:   minActive,
		})
		out := ctx.applyViolationTransition(m)
		assert.Equal(t, 1, int(out.CountByState(ValExiting)), "only 1 can exit")
		assert.Equal(t, 3, int(out.CountByState(ValActive)), "3 remain ValActive")
	})
```

**File:** kaiax/reward/impl/getter.go (L486-507)
```go
// assignStakingRewards assigns staking rewards to stakers according to their staking amounts.
// Returns the allocation and the remainder.
func assignStakingRewards(config *reward.RewardConfig, stakersReward *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		cns               = si.ConsolidatedNodes()
		minStake          = config.MinimumStake.Uint64()
		totalExcessInt    = uint64(0) // sum of excess stakes (the amount over minStake) over all stakers
		cnTotalStakingMap = make(map[common.Address]uint64)
		isPrague          = config.Rules.IsPrague
	)
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it.
		if cn.StakingAmount >= minStake {
			// Calculate total staking amount once
			cnTotalStakingAmount := cn.StakingAmount
			if isPrague && cn.CLStakingInfo != nil {
				cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount
			}
			totalExcessInt += cnTotalStakingAmount - minStake
			cnTotalStakingMap[cn.RewardAddr] = cnTotalStakingAmount
		}
	}
```
