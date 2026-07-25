### Title
Staking Reward Overwrite When `CLPoolAddr == RewardAddr` Silently Destroys KAIA Per Block — (`kaiax/reward/impl/getter.go`)

### Summary

In `assignStakingRewards` and `assignStakingRewardsFlex` (Prague hardfork path), when a validator's `CLPoolAddr` equals their `RewardAddr`, the `alloc` map is written twice with the same key using direct assignment (`=`). The second write silently overwrites the first, causing the `cnAmount` portion of that validator's staking reward to be permanently lost — neither credited to the validator nor to the proposer — while `remaining` is still decremented by the full `reward`. This is the direct Go analog of the KIBToken self-transfer overwrite bug.

### Finding Description

In `assignStakingRewards` (and identically in `assignStakingRewardsFlex`), the Prague-hardfork branch splits a validator's staking reward between their CN reward address and their CL pool address:

```go
cnAmount, clAmount := cn.Split(reward)
alloc[cn.RewardAddr] = cnAmount          // write 1
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount  // write 2 — overwrites write 1 if same address
``` [1](#0-0) 

If `cn.RewardAddr == cn.CLStakingInfo.CLPoolAddr`, write 2 overwrites write 1. The `alloc` entry for that address ends up holding only `clAmount` instead of `cnAmount + clAmount`. However, `remaining` is still decremented by the full `reward = cnAmount + clAmount`:

```go
remaining.Sub(remaining, reward)
``` [2](#0-1) 

The returned `remaining` becomes `kip82Remainder`, which is added to the proposer's reward. Since `remaining` was already reduced by the full `reward`, the proposer does not receive the lost `cnAmount` either. The `cnAmount` is simply not distributed to anyone.

The same pattern exists in `assignStakingRewardsFlex`: [3](#0-2) 

By contrast, `specWithProposerAndFunds` correctly uses `IncRecipient` (which accumulates via `Add`) for the same-address scenario, so the proposer path handles address collisions safely: [4](#0-3) 

The staking reward path uses raw map assignment and has no such protection.

The `alloc` map is then iterated by the callers and fed into `spec.IncRecipient`, which calls `state.AddBalance` at finalization: [5](#0-4) 

### Impact Explanation

For every block in which a validator has `CLPoolAddr == RewardAddr`, the `cnAmount` portion of that validator's staking reward is permanently lost. It is:
- Not credited to the validator's address (overwritten by `clAmount`)
- Not credited to the proposer (already subtracted from `remaining`)
- Not credited to any other recipient

The total KAIA distributed per block is reduced by `cnAmount`. This is an incorrect reward distribution affecting KAIA, a protected asset. The `RewardSpec.Validate()` check only verifies non-negative amounts and does not catch this silent loss. [6](#0-5) 

### Likelihood Explanation

The trigger requires:
1. Prague hardfork active (`isPrague = true`)
2. A validator registered in both AddressBook (`RewardAddr`) and CLRegistry (`CLPoolAddr`)
3. The two addresses are identical

There is no on-chain enforcement preventing `CLPoolAddr == RewardAddr`. A validator who misconfigures their CL pool registration to use their reward address as the pool address would silently lose a fraction of their staking rewards every block. The `CLStakingInfo` is sourced from the CLRegistry contract and the `RewardAddr` from AddressBook — two independent registrations with no cross-check. [7](#0-6) [8](#0-7) 

### Recommendation

Replace direct map assignment with accumulation in both `assignStakingRewards` and `assignStakingRewardsFlex`, mirroring the pattern already used by `IncRecipient`:

```go
// Instead of:
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount

// Use:
if _, ok := alloc[cn.RewardAddr]; !ok {
    alloc[cn.RewardAddr] = new(big.Int)
}
alloc[cn.RewardAddr].Add(alloc[cn.RewardAddr], cnAmount)

if _, ok := alloc[cn.CLStakingInfo.CLPoolAddr]; !ok {
    alloc[cn.CLStakingInfo.CLPoolAddr] = new(big.Int)
}
alloc[cn.CLStakingInfo.CLPoolAddr].Add(alloc[cn.CLStakingInfo.CLPoolAddr], clAmount)
```

Alternatively, add an explicit guard: if `cn.RewardAddr == cn.CLStakingInfo.CLPoolAddr`, assign the full `reward` to that address rather than splitting and overwriting.

### Proof of Concept

Given:
- `stakersReward = 1000 kei`
- One eligible validator: `RewardAddr = 0xABC`, `CLPoolAddr = 0xABC` (same), `StakingAmount = 6_000_000`, `CLStakingAmount = 2_000_000`, `minStake = 5_000_000`
- `cn.Split(reward)` → `cnAmount = 750`, `clAmount = 250` (proportional to 6M:2M)

Execution in `assignStakingRewards`:
1. `alloc[0xABC] = 750` (cnAmount)
2. `alloc[0xABC] = 250` (clAmount, **overwrites**)
3. `remaining -= 1000`

Result: `alloc = {0xABC: 250}`, `remaining = 0`

`kip82Remainder = 0` → proposer gets nothing extra.

At `FinalizeState`, `state.AddBalance(0xABC, 250)` is called. The validator receives 250 kei instead of 1000 kei. The 750 kei (`cnAmount`) is permanently lost from the block's reward distribution. [9](#0-8) [10](#0-9)

### Citations

**File:** kaiax/reward/impl/getter.go (L474-481)
```go
		if isPrague && cn.CLStakingInfo != nil {
			cnAmount, clAmount := cn.Split(reward)
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
		} else {
			alloc[cn.RewardAddr] = reward
		}
		remaining.Sub(remaining, reward)
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

**File:** kaiax/reward/impl/getter.go (L583-587)
```go
		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
```

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```

**File:** kaiax/reward/spec.go (L118-125)
```go
func (spec *RewardSpec) Validate() error {
	for addr, amount := range spec.Rewards {
		if amount.Sign() < 0 {
			return errNegativeRewardAmount(addr, amount)
		}
	}
	return nil
}
```

**File:** kaiax/staking/staking_info.go (L59-64)
```go
// CLStakingInfo is the staking info from the consensus liquidity since Prague HF.
type CLStakingInfo struct {
	CLNodeId        common.Address `json:"clNodeId"`
	CLPoolAddr      common.Address `json:"clPoolAddr"`
	CLStakingAmount uint64         `json:"clStakingAmount"`
}
```

**File:** kaiax/staking/staking_info.go (L150-160)
```go
	// CLStakingInfo can only exist after Prague HF.
	if len(si.CLStakingInfos) > 0 {
		for _, clsi := range si.CLStakingInfos {
			// If the nodeId of CLStakingInfo is not found in nToR, it means the validator is not in the AddressBook.
			// So we skip it.
			if r, ok := nToR[clsi.CLNodeId]; ok {
				// One CLStakingInfo per validator is guaranteed by CLRegistry.
				cmap[r].CLStakingInfo = clsi
			}
		}
	}
```

**File:** kaiax/staking/staking_info.go (L169-187)
```go
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
	if c.CLStakingInfo == nil {
		return amount, big.NewInt(0)
	}

	var (
		cnAmountBig = big.NewInt(int64(c.StakingAmount))
		clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
		totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
	)

	clAmount := new(big.Int).Mul(clAmountBig, amount)
	clAmount = clAmount.Div(clAmount, totalAmount)

	// The remaining amount is for the CN.
	cnAmount := big.NewInt(0).Sub(amount, clAmount)

	return cnAmount, clAmount
}
```
