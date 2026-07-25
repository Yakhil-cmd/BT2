### Title
Silent KAIA Staking-Reward Burn via Aliased `CLPoolAddr` in `assignStakingRewards` — (File: `kaiax/reward/impl/getter.go`)

### Summary

In the Prague hardfork path of `assignStakingRewards` and `assignStakingRewardsFlex`, staking rewards are written into the `alloc` map using direct assignment (`=`) rather than additive accumulation (`+=`). When a validator's `CLPoolAddr` equals another validator's `RewardAddr`, the second write silently overwrites the first, permanently burning the victim validator's staking reward. The `remaining` counter is decremented by the full reward amount for both validators, but the overwritten amount is credited to no one.

### Finding Description

`assignStakingRewards` iterates over `ConsolidatedNodes()` — a deduplicated list keyed by `RewardAddr` — and for each eligible node in the Prague path writes two entries into the `alloc` map:

```go
// kaiax/reward/impl/getter.go lines 521-525
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount                    // direct assignment
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount      // direct assignment
}
remaining.Sub(remaining, reward)                       // decremented by full reward
``` [1](#0-0) 

`ConsolidatedNodes()` guarantees uniqueness of `RewardAddr` across the `cns` slice, so the first assignment is safe. However, `CLPoolAddr` is an independent field sourced from the `CLRegistry` contract and is **not** deduplicated against any other address in the loop. If validator CN1 registers `CLPoolAddr = CN2.RewardAddr`, the iteration produces:

1. **CN2 processed first**: `alloc[B] = cnAmount2` (CN2's staking reward)
2. **CN1 processed second**: `alloc[A] = cnAmount1`, then `alloc[B] = clAmount1` — **overwrites** CN2's entry

`remaining` was decremented by `reward2` in step 1 and by `reward1` in step 2, so the full budget is consumed. Yet `alloc[B]` holds only `clAmount1` instead of `cnAmount2 + clAmount1`. The difference `cnAmount2` is silently burned — not credited to any address, not returned as remainder to the proposer.

The identical pattern exists in `assignStakingRewardsFlex`:

```go
// kaiax/reward/impl/getter.go lines 474-477
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
}
``` [2](#0-1) 

The `alloc` map is then iterated in the callers and fed into `spec.IncRecipient`, which correctly uses `+=`:

```go
// kaiax/reward/impl/getter.go lines 363-365
for addr, amount := range stakersAlloc {
    spec.IncRecipient(addr, amount)
}
``` [3](#0-2) 

`IncRecipient` itself is additive:

```go
// kaiax/reward/spec.go lines 110-116
func (spec *RewardSpec) IncRecipient(addr common.Address, amount *big.Int) {
    _, ok := spec.Rewards[addr]
    if !ok {
        spec.Rewards[addr] = big.NewInt(0)
    }
    spec.Rewards[addr].Add(spec.Rewards[addr], amount)
}
``` [4](#0-3) 

The bug is entirely in the intermediate `alloc` map construction, not in the final `state.AddBalance` calls. `FinalizeState` distributes exactly what `spec.Rewards` contains:

```go
// kaiax/reward/impl/blockstate.go lines 53-55
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [5](#0-4) 

### Impact Explanation

The corrupted value is the `alloc` map entry for the victim validator's `RewardAddr`. The entry is overwritten with the attacker's CL reward (`clAmount`) instead of accumulating both values. The `remaining` variable (which becomes `kip82Remainder` and flows to the proposer) is decremented by the full reward for both validators, so the proposer also receives less than expected. The net effect is that `cnAmount_victim` KAIA is permanently burned — removed from the distributed reward pool without being credited to any address. This constitutes an unauthorized burn of KAIA staking rewards affecting system-managed block reward funds.

**Concrete example** (Kore+Prague, `stakersReward = 100 KAIA`, `minStake = 5M`):
- CN2: `RewardAddr = B`, stake = 10M, excess = 5M → `reward2 = 83.33 KAIA`
- CN1: `RewardAddr = A`, `CLPoolAddr = B`, CNStake = 6M, CLStake = 2M, excess = 1M → `reward1 = 16.67 KAIA`, `cnAmount1 = 12.5`, `clAmount1 = 4.17`

After the loop: `alloc = {A: 12.5, B: 4.17}`. Expected: `{A: 12.5, B: 87.5}`. **83.33 KAIA silently burned.**

### Likelihood Explanation

Active on any chain running the Prague hardfork (`IsPrague = true`) with CL staking enabled. The trigger requires a validator to register a `CLPoolAddr` equal to another validator's `RewardAddr` in the `CLRegistry` contract. Validators are semi-trusted participants; if `CLRegistry` does not validate that `CLPoolAddr` is a deployed CL pool contract (e.g., via interface check), any validator can register an arbitrary address. The `ConsolidatedNodes()` ordering is deterministic and based on AddressBook registration order, making the overwrite predictable once the address collision is established.

### Recommendation

Replace direct assignment with additive accumulation in both `assignStakingRewards` and `assignStakingRewardsFlex`:

```go
// Instead of:
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount

// Use:
if _, ok := alloc[cn.RewardAddr]; !ok { alloc[cn.RewardAddr] = big.NewInt(0) }
alloc[cn.RewardAddr].Add(alloc[cn.RewardAddr], cnAmount)

if _, ok := alloc[cn.CLStakingInfo.CLPoolAddr]; !ok { alloc[cn.CLStakingInfo.CLPoolAddr] = big.NewInt(0) }
alloc[cn.CLStakingInfo.CLPoolAddr].Add(alloc[cn.CLStakingInfo.CLPoolAddr], clAmount)
```

Additionally, `CLRegistry` should enforce that `CLPoolAddr` is a valid CL pool contract and cannot equal any registered `RewardAddr` in the AddressBook.

### Proof of Concept

1. Deploy a Kaia node at Prague hardfork with CL staking enabled.
2. Register two validators in AddressBook: CN2 with `RewardAddr = B`, CN1 with `RewardAddr = A`.
3. CN1 registers in `CLRegistry` with `CLPoolAddr = B` (CN2's reward address).
4. Both validators stake above `minStake`. CN2 is ordered before CN1 in `ConsolidatedNodes()`.
5. At block finalization, `assignStakingRewards` is called. Observe:
   - `alloc[B]` is first set to CN2's staking reward (`cnAmount2`).
   - CN1's iteration sets `alloc[B] = clAmount1`, overwriting CN2's reward.
   - `remaining` was decremented by both `reward1` and `reward2`.
6. `spec.Rewards[B]` = `clAmount1` only. `state.AddBalance(B, clAmount1)` is called.
7. CN2's staking reward (`cnAmount2`) is never credited. Verify by checking `B`'s balance delta equals only `clAmount1`, not `cnAmount2 + clAmount1`. [6](#0-5) [7](#0-6)

### Citations

**File:** kaiax/reward/impl/getter.go (L363-365)
```go
	for addr, amount := range stakersAlloc {
		spec.IncRecipient(addr, amount)
	}
```

**File:** kaiax/reward/impl/getter.go (L421-484)
```go
// assignStakingRewardsFlex assigns staking rewards to stakers according to their staking amounts.
// Returns the allocation and the remainder.
func assignStakingRewardsFlex(config *reward.RewardConfig, budget *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		minStake  = config.MinimumStake.Uint64()
		threshold = config.StakingRewardThreshold.Uint64()
		isPrague  = config.Rules.IsPrague

		cns            = si.ConsolidatedNodes()
		excessInt      = make(map[common.Address]uint64)
		totalExcessInt = uint64(0)
	)

	// Calculate the excess stakes (the amount over the threshold) for each CN.
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it. Even if (CNStaking + CLStaking) could be more than minStake,
		// the CNStaking alone must be at least minStake to be eligible.
		if cn.StakingAmount < minStake {
			continue
		}

		amount := cn.StakingAmount
		if isPrague && cn.CLStakingInfo != nil {
			amount += cn.CLStakingInfo.CLStakingAmount
		}

		// Excess is the amount over the threshold (not over minStake).
		if amount > threshold {
			excessInt[cn.RewardAddr] = amount - threshold
			totalExcessInt += excessInt[cn.RewardAddr]
		}
	}

	// Distribute the budget to the CNs based on the excess stakes.
	var (
		totalExcess = new(big.Int).SetUint64(totalExcessInt)
		remaining   = new(big.Int).Set(budget)
		alloc       = make(map[common.Address]*big.Int)
	)
	for _, cn := range cns {
		if excessInt[cn.RewardAddr] <= 0 {
			continue
		}
		excess := new(big.Int).SetUint64(excessInt[cn.RewardAddr])

		// The KAIA unit will cancel out:
		// reward (kei) = excess (KAIA) * budget (kei) / totalExcess (KAIA)
		reward := new(big.Int).Div(new(big.Int).Mul(excess, budget), totalExcess)
		if reward.Sign() <= 0 {
			continue
		}

		// If Prague and CL is configured for this CN, split the reward between CN and CL.
		if isPrague && cn.CLStakingInfo != nil {
			cnAmount, clAmount := cn.Split(reward)
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
		} else {
			alloc[cn.RewardAddr] = reward
		}
		remaining.Sub(remaining, reward)
	}
	return alloc, remaining
}
```

**File:** kaiax/reward/impl/getter.go (L486-534)
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

	var (
		totalExcess = new(big.Int).SetUint64(totalExcessInt)
		remaining   = new(big.Int).Set(stakersReward)
		alloc       = make(map[common.Address]*big.Int)
	)
	for _, cn := range cns {
		cnTotalStakingAmount := cnTotalStakingMap[cn.RewardAddr]
		if cnTotalStakingAmount > minStake {
			// The KAIA unit will cancel out:
			// reward (kei) = excess (KAIA) * stakersReward (kei) / totalExcess (KAIA)
			excess := new(big.Int).SetUint64(cnTotalStakingAmount - minStake)
			if reward := new(big.Int).Div(new(big.Int).Mul(excess, stakersReward), totalExcess); reward.Sign() > 0 {
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
				} else {
					alloc[cn.RewardAddr] = reward
				}
				remaining.Sub(remaining, reward)
			}
		}
	}
	return alloc, remaining
}
```

**File:** kaiax/reward/spec.go (L110-116)
```go
func (spec *RewardSpec) IncRecipient(addr common.Address, amount *big.Int) {
	_, ok := spec.Rewards[addr]
	if !ok {
		spec.Rewards[addr] = big.NewInt(0)
	}
	spec.Rewards[addr].Add(spec.Rewards[addr], amount)
}
```

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```
