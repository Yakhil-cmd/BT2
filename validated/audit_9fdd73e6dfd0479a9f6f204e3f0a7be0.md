### Title
Missing Zero-Address Guard on `CLPoolAddr` Causes Permanent KAIA Staking-Reward Burn — (`kaiax/reward/impl/getter.go`)

---

### Summary

After the Prague hardfork, staking rewards are split between a validator's AddressBook reward address and its consensus-liquidity pool address (`CLPoolAddr`). Neither the staking-info parser nor the reward-distribution functions check whether `CLPoolAddr` is the zero address before crediting it. If a validator's CLRegistry entry carries a zero `CLPoolAddr`, the CL portion of every block's staking reward is silently credited to `address(0)`, permanently burning it.

---

### Finding Description

`CLStakingInfo.CLPoolAddr` is populated directly from the on-chain CLRegistry result without any zero-address validation:

In `parsePermissionlessCallResult`:
```go
clStakingInfos[i] = &staking.CLStakingInfo{
    CLNodeId:        clRes.NodeIds[i],
    CLPoolAddr:      clRes.ClPools[i],   // no zero-address check
    CLStakingAmount: ...,
}
``` [1](#0-0) 

Identically in `parseCallResult`: [2](#0-1) 

The resulting `CLStakingInfo` is stored in `StakingInfo.CLStakingInfos` and later consolidated into `consolidatedNode.CLStakingInfo` without any zero-address check: [3](#0-2) 

During reward distribution, `assignStakingRewards` (Kore path) and `assignStakingRewardsFlex` (Flex path) both call `cn.Split(reward)` and write the CL portion directly into the allocation map keyed by `CLPoolAddr`:

```go
cnAmount, clAmount := cn.Split(reward)
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount  // no zero-address guard
``` [4](#0-3) [5](#0-4) 

The same unchecked write occurs for the proposer's CL split in both `specWithProposerAndFunds` and `specWithProposerAndFundsFlex`: [6](#0-5) [7](#0-6) 

`FinalizeState` then iterates `spec.Rewards` and calls `state.AddBalance(addr, amount)` for every entry, including any entry keyed to `address(0)`:

```go
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [8](#0-7) 

`address(0)` is an uncontrolled sink; balance added to it is permanently inaccessible.

---

### Impact Explanation

**Impact: High.** Every block in which the affected validator is eligible for staking rewards, the CL portion — proportional to `CLStakingAmount / (StakingAmount + CLStakingAmount)` — is minted and immediately burned to `address(0)`. This is a permanent, per-block loss of KAIA from the reward pool. The `Split` function confirms the CL share can be a substantial fraction of the total reward: [9](#0-8) 

---

### Likelihood Explanation

**Likelihood: Low.** The trigger requires a validator's CLRegistry entry to carry a zero `CLPoolAddr`. This can occur if:
- The CLRegistry contract itself does not enforce a non-zero pool address on registration, and a validator registers with `address(0)` (by mistake or maliciously against their own rewards), or
- A future upgrade or misconfiguration introduces a zero entry.

The Go parsing layer provides no defense-in-depth check, so any zero value that reaches it flows through to `FinalizeState` unchallenged.

---

### Recommendation

Add a zero-address guard in both parsing functions before storing `CLPoolAddr`:

```go
// In parsePermissionlessCallResult and parseCallResult:
if common.EmptyAddress(clRes.ClPools[i]) {
    logger.Error("CLPoolAddr is zero, skipping CL entry", "nodeId", clRes.NodeIds[i])
    continue
}
```

Additionally, add a guard in `assignStakingRewards`, `assignStakingRewardsFlex`, `specWithProposerAndFunds`, and `specWithProposerAndFundsFlex` before writing to `CLPoolAddr`:

```go
if !common.EmptyAddress(cn.CLStakingInfo.CLPoolAddr) {
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
} else {
    // redirect to cn.RewardAddr or treat as remainder
    alloc[cn.RewardAddr] = new(big.Int).Add(alloc[cn.RewardAddr], clAmount)
}
```

---

### Proof of Concept

1. A validator registers in CLRegistry with `CLPoolAddr = address(0)` and `CLStakingAmount > 0`.
2. `GetStakingInfo` is called for a block after Prague hardfork; `parsePermissionlessCallResult` stores `CLPoolAddr = 0x000...000` in `CLStakingInfo` without rejection.
3. `consolidateNodes` attaches this `CLStakingInfo` to the validator's `consolidatedNode`.
4. `assignStakingRewards` computes `cn.Split(reward)` → `clAmount > 0`, then sets `alloc[address(0)] = clAmount`.
5. `specWithProposerAndFunds` similarly sets `spec.Rewards[address(0)] += clAmount` for the proposer path.
6. `FinalizeState` calls `state.AddBalance(address(0), clAmount)` — KAIA is minted to the zero address and permanently burned every block. [10](#0-9) [11](#0-10)

### Citations

**File:** kaiax/staking/impl/getter.go (L214-220)
```go
		for i := range clRes.NodeIds {
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
		}
```

**File:** kaiax/staking/impl/getter.go (L293-301)
```go
	if len(clRes.NodeIds) > 0 {
		clStakingInfos = make(staking.CLStakingInfos, len(clRes.NodeIds))
		for i := range clRes.NodeIds {
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
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

**File:** kaiax/reward/impl/getter.go (L473-478)
```go
		// If Prague and CL is configured for this CN, split the reward between CN and CL.
		if isPrague && cn.CLStakingInfo != nil {
			cnAmount, clAmount := cn.Split(reward)
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
		} else {
```

**File:** kaiax/reward/impl/getter.go (L514-530)
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
```

**File:** kaiax/reward/impl/getter.go (L583-587)
```go
		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
```

**File:** kaiax/reward/impl/getter.go (L633-637)
```go
		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
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
