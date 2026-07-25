### Title
`assignStakingRewards` / `assignStakingRewardsFlex` Overwrite CL Pool Reward Allocation When Multiple Validators Share the Same `CLPoolAddr` — (`File: kaiax/reward/impl/getter.go`)

---

### Summary

In the Prague-era (KIP-226) staking reward distribution path, both `assignStakingRewards` and `assignStakingRewardsFlex` build an `alloc` map using plain `=` assignment for `CLPoolAddr` entries. If two consolidated validators share the same `CLPoolAddr` in the CLRegistry, the second write silently overwrites the first, permanently losing the first validator's CL reward. The `remaining` counter is still decremented for both, so the lost amount is neither distributed to the CL pool nor returned to the proposer — it simply vanishes from the on-chain reward accounting.

---

### Finding Description

In `assignStakingRewards` (Prague path):

```go
// kaiax/reward/impl/getter.go lines 521-525
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount                    // safe: RewardAddr is unique per consolidated node
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount      // BUG: plain = overwrites if CLPoolAddr is shared
}
remaining.Sub(remaining, reward)                       // decremented regardless
```

The same pattern appears in `assignStakingRewardsFlex` at lines 474–481.

`ConsolidatedNodes()` guarantees uniqueness of `RewardAddr` across consolidated nodes, so the `alloc[cn.RewardAddr] = cnAmount` line is safe. However, `CLPoolAddr` is sourced from the CLRegistry — a separate registry — and no uniqueness constraint on `CLPoolAddr` across different validators is enforced anywhere in the Go code or in `consolidateNodes()`.

The `consolidateNodes()` function at `kaiax/staking/staking_info.go:151-159` only guards against duplicate `CLNodeId` per validator ("One CLStakingInfo per validator is guaranteed by CLRegistry"), but does **not** prevent two different validators from registering the same `CLPoolAddr`:

```go
// staking_info.go lines 151-159
for _, clsi := range si.CLStakingInfos {
    if r, ok := nToR[clsi.CLNodeId]; ok {
        cmap[r].CLStakingInfo = clsi   // keyed by CLNodeId, not CLPoolAddr
    }
}
```

**Concrete overwrite scenario:**

- CN1: `RewardAddr=R1`, `CLStakingInfo.CLPoolAddr=P`
- CN2: `RewardAddr=R2`, `CLStakingInfo.CLPoolAddr=P` (same pool)

Loop iteration over CN1: `alloc[P] = clAmount1`
Loop iteration over CN2: `alloc[P] = clAmount2` ← **overwrites clAmount1**

`remaining` was decremented by `reward1 + reward2`. The `alloc` map now holds `cnAmount1 + cnAmount2 + clAmount2`. The missing `clAmount1` is subtracted from `remaining` but never placed in `alloc`, so it is distributed to no one.

Total distributed = `alloc_total + remaining`
= `(cnAmount1 + cnAmount2 + clAmount2) + (stakersReward − reward1 − reward2)`
= `stakersReward − clAmount1`

`clAmount1` is permanently lost from the reward distribution.

---

### Impact Explanation

- **Incorrect KAIA reward distribution**: The shared CL pool address `P` receives only `clAmount2` instead of `clAmount1 + clAmount2`.
- **Permanent loss of `clAmount1` KAIA per block**: The amount is neither credited to the CL pool nor returned to the proposer via `remaining`. It is silently dropped from `FinalizeState`'s `state.AddBalance` loop.
- **Affects every block** after Prague hardfork where the collision exists, compounding over time.
- Matches the allowed impact gate: unauthorized/incorrect reward distribution affecting KAIA.

---

### Likelihood Explanation

The CLRegistry mock (`contracts/testing/reward/CLRegistryMock.sol`) returns `(nodeIds, gcIds, clPools)` with no uniqueness enforcement on `clPools`. The production CLRegistry is a system contract, but the Go parsing layer at `kaiax/staking/impl/getter.go:292-302` blindly copies all `(CLNodeId, CLPoolAddr, CLStakingAmount)` tuples without checking for duplicate `CLPoolAddr` values. A validator who controls their own CL pool registration can register the same pool address as another validator, triggering the overwrite on every subsequent block. This is a semi-trusted (single-validator) trigger, not majority collusion.

---

### Recommendation

Replace the plain `=` assignments for `CLPoolAddr` entries in both functions with accumulation, mirroring the `IncRecipient` pattern used elsewhere in the reward spec:

```go
// assignStakingRewards (and analogously assignStakingRewardsFlex)
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount
    // Use += instead of = to handle shared CLPoolAddr
    if existing, ok := alloc[cn.CLStakingInfo.CLPoolAddr]; ok {
        existing.Add(existing, clAmount)
    } else {
        alloc[cn.CLStakingInfo.CLPoolAddr] = new(big.Int).Set(clAmount)
    }
}
```

Alternatively, add a uniqueness check on `CLPoolAddr` during `consolidateNodes()` or during CLRegistry result parsing in `kaiax/staking/impl/getter.go`.

---

### Proof of Concept

**Setup (Prague hardfork active):**
- Validator A: `RewardAddr=0xA`, `CLPoolAddr=0xP`, `StakingAmount=10M KAIA`
- Validator B: `RewardAddr=0xB`, `CLPoolAddr=0xP` (same pool), `StakingAmount=10M KAIA`
- `stakersReward = 1000 kei`, `minStake = 5M KAIA`

**Execution of `assignStakingRewards`:**

1. Both validators have `cnTotalStakingAmount > minStake`, so both are eligible.
2. `totalExcessInt = (10M−5M) + (10M−5M) = 10M`
3. For Validator A: `reward_A = 5M/10M * 1000 = 500 kei`. `Split(500)` → `cnAmount_A=250, clAmount_A=250`. `alloc[0xA]=250`, `alloc[0xP]=250`. `remaining=500`.
4. For Validator B: `reward_B = 500 kei`. `Split(500)` → `cnAmount_B=250, clAmount_B=250`. `alloc[0xB]=250`, **`alloc[0xP]=250` (overwrites 250)**. `remaining=0`.

**Result:** `alloc = {0xA:250, 0xB:250, 0xP:250}`. Total = 750 kei. But `stakersReward=1000` and `remaining=0`. The missing 250 kei (`clAmount_A`) is never distributed. `FinalizeState` calls `state.AddBalance` only for entries in `spec.Rewards`, so 250 kei of KAIA is permanently unaccounted for per block. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** kaiax/reward/impl/getter.go (L473-481)
```go
		// If Prague and CL is configured for this CN, split the reward between CN and CL.
		if isPrague && cn.CLStakingInfo != nil {
			cnAmount, clAmount := cn.Split(reward)
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
		} else {
			alloc[cn.RewardAddr] = reward
		}
		remaining.Sub(remaining, reward)
```

**File:** kaiax/reward/impl/getter.go (L521-529)
```go
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
				} else {
					alloc[cn.RewardAddr] = reward
				}
				remaining.Sub(remaining, reward)
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

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```
