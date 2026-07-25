### Title
Staking Reward Overwrite via Duplicate `CLPoolAddr` Silently Drops KAIA from Block Reward Distribution — (`kaiax/reward/impl/getter.go`)

### Summary

`assignStakingRewards` and `assignStakingRewardsFlex` build a per-address allocation map using bare `=` assignment instead of accumulation. When two consolidated validator nodes share the same `CLPoolAddr`, the second assignment silently overwrites the first. The `remaining` budget counter is decremented for both validators, but only one CL pool reward survives in `alloc`. The missing KAIA is never credited to any address during `FinalizeState`, causing a permanent loss of block reward KAIA.

### Finding Description

**Root cause — `assignStakingRewards` (Kore/Prague path):** [1](#0-0) 

For each consolidated node `cn`, the code writes:

```go
alloc[cn.RewardAddr] = cnAmount                    // line 524
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount      // line 525
remaining.Sub(remaining, reward)                   // line 529
```

`alloc` is a plain `map[common.Address]*big.Int` initialised once before the loop: [2](#0-1) 

The same pattern exists in `assignStakingRewardsFlex`: [3](#0-2) 

`ConsolidatedNodes()` guarantees uniqueness of `cn.RewardAddr`, so the `cnAmount` write is safe. However, **no uniqueness guarantee exists for `cn.CLStakingInfo.CLPoolAddr` across different consolidated nodes**. The code comment only asserts "One CLStakingInfo per validator is guaranteed by CLRegistry" — it says nothing about two distinct validators sharing the same `CLPoolAddr`. [4](#0-3) 

**Accounting invariant broken:**

If CN1 (RewardAddr R1, CLPoolAddr P) and CN2 (RewardAddr R2, CLPoolAddr P) are both eligible:

| Step | `alloc[P]` | `remaining` |
|------|-----------|-------------|
| Process CN1 | `clAmount1` | `budget − reward1` |
| Process CN2 | `clAmount2` ← **overwrites** | `budget − reward1 − reward2` |

After the loop: `sum(alloc) = cnAmount1 + cnAmount2 + clAmount2`, but `budget − remaining = reward1 + reward2 = cnAmount1 + clAmount1 + cnAmount2 + clAmount2`. The gap `clAmount1` is never placed in `alloc`.

**Execution path to `FinalizeState`:** [5](#0-4) 

`spec.Rewards` is populated from `alloc` via `IncRecipient`: [6](#0-5) 

Because `clAmount1` was never placed in `alloc`, it is never placed in `spec.Rewards`, and `state.AddBalance` is never called for it. The KAIA is not minted to any address.

**Secondary analog — `consolidateNodes()` silent CL overwrite:**

When two nodes sharing the same `RewardAddr` both have `CLStakingInfo` entries in the CLRegistry, `consolidateNodes()` silently overwrites the first: [7](#0-6) 

The test suite acknowledges this scenario as "not feasible in real" but does not enforce it: [8](#0-7) 

This causes the first CL pool's staking amount to be excluded from the total, understating the consolidated node's share and silently zeroing the first CL pool's reward.

### Impact Explanation

Every block processed under the Prague/Osaka hardfork where two eligible validators share a `CLPoolAddr` (or two nodes in the same consolidated group both have CLStakingInfos) results in `clAmount1` of KAIA being permanently unissued. The `kip82Remainder` returned to the proposer is also reduced by `clAmount1`, so no recipient is compensated. This is an incorrect reward distribution affecting KAIA at the `FinalizeState` level on every such block.

### Likelihood Explanation

The CLRegistry comment asserts uniqueness per validator but does not assert uniqueness of `CLPoolAddr` across validators. If the CLRegistry contract does not enforce `CLPoolAddr` uniqueness across different `CLNodeId` registrations, a registered validator (semi-trusted actor) can register the same `CLPoolAddr` as another validator, triggering the overwrite every block. The `consolidateNodes()` variant can be triggered by any two nodes in the same AddressBook consolidated group that both register CL pools — a valid product flow.

### Recommendation

1. In `assignStakingRewards` and `assignStakingRewardsFlex`, replace bare assignment with accumulation for the `CLPoolAddr` entry:

```go
// Before
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount

// After
if _, ok := alloc[cn.CLStakingInfo.CLPoolAddr]; !ok {
    alloc[cn.CLStakingInfo.CLPoolAddr] = new(big.Int)
}
alloc[cn.CLStakingInfo.CLPoolAddr].Add(alloc[cn.CLStakingInfo.CLPoolAddr], clAmount)
```

2. In `consolidateNodes()`, accumulate `CLStakingAmount` rather than overwriting `CLStakingInfo` when two nodes in the same consolidated group both have CL entries, or enforce at the CLRegistry level that `CLPoolAddr` is unique across all registered validators.

3. Add a sanity check asserting `sum(alloc values) == budget − remaining` before returning from both functions.

### Proof of Concept

```
Given Prague hardfork active, two validators:
  CN1: RewardAddr=R1, CLPoolAddr=P, CNStaking=6_000_000, CLStaking=1_000_000
  CN2: RewardAddr=R2, CLPoolAddr=P, CNStaking=6_000_000, CLStaking=1_000_000
  minStake=5_000_000, stakersReward=1e18

assignStakingRewards:
  totalExcessInt = (6m-5m) + (6m-5m) = 2_000_000
  cnTotalStakingMap = {R1: 7_000_000, R2: 7_000_000}

  Process CN1:
    excess = 2_000_000, reward = 1e18/2 = 5e17
    Split(5e17): cnAmount1 = 5e17*6/7 ≈ 4.28e17, clAmount1 = 5e17*1/7 ≈ 7.14e16
    alloc[R1] = 4.28e17
    alloc[P]  = 7.14e16   ← first write
    remaining = 5e17

  Process CN2:
    excess = 2_000_000, reward = 5e17
    Split(5e17): cnAmount2 ≈ 4.28e17, clAmount2 ≈ 7.14e16
    alloc[R2] = 4.28e17
    alloc[P]  = 7.14e16   ← OVERWRITES clAmount1
    remaining = 0

  Return: alloc = {R1: 4.28e17, R2: 4.28e17, P: 7.14e16}, remainder = 0
  sum(alloc) ≈ 9.28e17  ≠  budget (1e18)
  Lost: clAmount1 ≈ 7.14e16 kei of KAIA never distributed
``` [9](#0-8) [10](#0-9) [5](#0-4)

### Citations

**File:** kaiax/reward/impl/getter.go (L460-482)
```go
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
```

**File:** kaiax/reward/impl/getter.go (L509-513)
```go
	var (
		totalExcess = new(big.Int).SetUint64(totalExcessInt)
		remaining   = new(big.Int).Set(stakersReward)
		alloc       = make(map[common.Address]*big.Int)
	)
```

**File:** kaiax/reward/impl/getter.go (L514-533)
```go
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
```

**File:** kaiax/staking/staking_info.go (L151-159)
```go
	if len(si.CLStakingInfos) > 0 {
		for _, clsi := range si.CLStakingInfos {
			// If the nodeId of CLStakingInfo is not found in nToR, it means the validator is not in the AddressBook.
			// So we skip it.
			if r, ok := nToR[clsi.CLNodeId]; ok {
				// One CLStakingInfo per validator is guaranteed by CLRegistry.
				cmap[r].CLStakingInfo = clsi
			}
		}
```

**File:** kaiax/reward/impl/blockstate.go (L46-56)
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
	return nil
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

**File:** kaiax/staking/staking_info_test.go (L258-268)
```go
					// CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)
					{
						CLNodeId:        n3,
						CLPoolAddr:      clPool2,
						CLStakingAmount: clStakingAmount2,
					},
				},
			},
			expectedConsolidated: []consolidatedNode{
				{[]common.Address{n1, n3}, []common.Address{s1, s3}, r1, a1 + a3, &CLStakingInfo{n3, clPool2, clStakingAmount2}},
				{[]common.Address{n2, n4}, []common.Address{s2, s4}, r2, a2 + a4, nil},
```
