### Title
Loss of Reward Eligibility and State Reset via Tiny Withdrawals - ([File: kaiax/reward/impl/getter.go])

### Summary
A vulnerability exists in the reward distribution and validator state transition logic where a tiny withdrawal (unstaking) that causes the total stake to drop even slightly below the `reward.minimumstake` or `reward.stakingrewardthreshold` leads to an immediate and irreversible loss of reward eligibility and a reset of accumulated state (such as `IdleTimeout`). This is analogous to the external report where a tiny withdrawal resets the `lastDepositTime` and wipes out accumulated bonuses.

### Finding Description
In the Kaia reward module, specifically in `assignStakingRewards` and `assignStakingRewardsFlex` within `kaiax/reward/impl/getter.go`, reward distribution is binary based on whether a validator's stake meets the threshold. If a validator withdraws an amount that brings their total stake (including Consensus Liquidity) even one unit below the `minStake` or `stakingrewardthreshold`, they are immediately excluded from the reward allocation for that block and all subsequent blocks until they restake [1](#0-0) .

Furthermore, in the permissionless validator set module (`kaiax/valset/impl/transition_context.go`), a stake drop below `MinStake` triggers an immediate state transition to `ValInactive` or `ValExiting` [2](#0-1) . This transition resets accumulated timers like `IdleTimeout` and `PausedTimeout` to zero or fresh values, effectively wiping out the validator's "tenure" or accumulated progress toward remaining in the active set [3](#0-2) .

### Impact Explanation
The impact is a native asset reward loss for validators. A small, potentially accidental withdrawal that crosses the threshold results in:
1. Immediate loss of all staking rewards for the period, even if the validator was above the threshold for 99% of the time.
2. Forced demotion of the validator state, which resets accumulated timers used for liveness and maintenance (e.g., `IdleTimeout`).
3. Requirement to restake and wait for the next epoch/interval to regain eligibility, leading to significant financial loss (KAIA rewards).

### Likelihood Explanation
The likelihood is high for validators managing their stake dynamically or those using the service-chain bridge for automated transfers. Since the thresholds (`reward.minimumstake`) are fixed values, any transaction that reduces the balance below this exact amount triggers the reset.

### Recommendation
Implement a "weighted" or "pro-rata" reward calculation that accounts for the time spent above the threshold during the interval, rather than a binary check at the time of distribution. For state transitions, introduce a grace period or a "hysteresis" buffer where tiny fluctuations below the threshold do not trigger an immediate state reset or demotion.

### Proof of Concept
1. A validator has exactly `5,000,000 KAIA` staked (the `minStake`).
2. The validator initiates a withdrawal of `1 KAIA` via the `CnStaking` contract.
3. During the next block's `FinalizeState`, the `RewardModule` calls `GetDeferredReward`, which invokes `assignStakingRewards` [4](#0-3) .
4. `assignStakingRewards` checks `cn.StakingAmount >= minStake`. Since `4,999,999 < 5,000,000`, the validator is skipped and receives `0` rewards [5](#0-4) .
5. Simultaneously, the `ValsetModule` applies `applyViolationTransition`, seeing the stake is below `MinStake`, and transitions the validator from `ValActive` to `ValExiting`, resetting their `IdleTimeout` [6](#0-5) .

### Citations

**File:** kaiax/reward/impl/getter.go (L497-507)
```go
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

**File:** kaiax/valset/impl/transition_context.go (L186-195)
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
	}
```

**File:** kaiax/valset/impl/transition_context.go (L224-230)
```go
	for idx, potentialActiveVal := range activeValCompetitors {
		if uint64(idx) < ctx.MaxValActivePausedCount {
			if potentialActiveVal.State != valset.ValPaused {
				potentialActiveVal.State = valset.ValActive
				potentialActiveVal.IdleTimeout = time.Time{}
				potentialActiveVal.PausedTimeout = time.Time{}
			}
```

**File:** kaiax/valset/impl/transition_context.go (L295-299)
```go
		case valset.ValActive:
			// ValActive → ValExiting (slot + minActiveCount: removing an active validator reduces consensus participants)
			if canDemoteActive(valset.ValExiting) {
				logger.Trace("MinStake violation: ValActive → ValExiting", "addr", addr, "staking", val.StakingAmount, "minStake", ctx.MinStake)
				val.State = valset.ValExiting
```

**File:** kaiax/reward/impl/blockstate.go (L46-55)
```go
	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```
