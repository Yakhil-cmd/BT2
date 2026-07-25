### Title
Division-by-Zero Panic in `consolidatedNode.Split()` Crashes `FinalizeState` When Proposer Has Both CN and CL Staking Amounts Truncated to Zero — (`kaiax/staking/staking_info.go`)

---

### Summary

`consolidatedNode.Split()` divides by `totalAmount = cnAmountBig + clAmountBig` with no zero guard. Both values originate from staking amounts that are truncated to whole-KAIA units (divided by `1e18`) during `StakingInfo` parsing. If a block proposer has `CLStakingInfo != nil` but both `StakingAmount` and `CLStakingAmount` truncate to zero, `FinalizeState()` panics with a division-by-zero, crashing the node and causing consensus divergence.

---

### Finding Description

**Root cause — `consolidatedNode.Split()` in `kaiax/staking/staking_info.go`:** [1](#0-0) 

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
    clAmount = clAmount.Div(clAmount, totalAmount)   // ← panics if totalAmount == 0
    cnAmount := big.NewInt(0).Sub(amount, clAmount)
    return cnAmount, clAmount
}
```

There is no check that `totalAmount > 0` before the division.

**How both values reach zero — truncation during `StakingInfo` parsing:**

In `kaiax/staking/impl/getter.go`, raw wei amounts from the AddressBook and CLRegistry are divided by `params.KAIA` (1 × 10¹⁸) and stored as `uint64`: [2](#0-1) 

```go
stakingAmounts[i] = big.NewInt(0).Div(a, big.NewInt(params.KAIA)).Uint64()
// ...
CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
```

Any validator whose CNStaking balance is less than 1 KAIA gets `StakingAmount = 0`; any CL pool with less than 1 KAIA gets `CLStakingAmount = 0`. This is the **division-before-use** precision loss that is the direct analog of the Blend M-10 bug class.

**Unguarded call site — proposer reward split in `kaiax/reward/impl/getter.go`:** [3](#0-2) 

```go
// Handle CLStakingInfo for proposer after Prague
cns := si.ConsolidatedNodes()
for _, cn := range cns {
    if cn.RewardAddr != config.Rewardbase { continue }
    if cn.CLStakingInfo == nil { break }

    cnAmount, clAmount := cn.Split(proposer)   // ← no zero-amount guard
    newSpec.IncRecipient(cn.RewardAddr, cnAmount)
    newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
    return newSpec
}
```

The identical pattern exists in `specWithProposerAndFundsFlex`: [4](#0-3) 

**Contrast with guarded call sites:**

`assignStakingRewards` and `assignStakingRewardsFlex` only call `cn.Split()` after confirming `cnTotalStakingAmount > minStake` or `amount > threshold`, which guarantees `totalAmount > 0`: [5](#0-4) [6](#0-5) 

The proposer path has no equivalent guard.

**Full call chain:**

```
FinalizeState()
  → getDeferredRewardFull()
    → getDeferredRewardFullKore() / getDeferredRewardFullFlex()
      → specWithProposerAndFunds() / specWithProposerAndFundsFlex()
        → cn.Split(proposer)   ← panic: division by zero
``` [7](#0-6) 

---

### Impact Explanation

Go's `big.Int.Div()` panics on a zero divisor. A panic inside `FinalizeState()` crashes the node mid-block-finalization. The affected validator's KAIA block reward is never distributed (incorrect reward accounting), and the node diverges from the rest of the network (consensus divergence on an honest node). If the validator is repeatedly selected as proposer, the node crashes on every such block until the staking state changes.

---

### Likelihood Explanation

The trigger requires all three conditions simultaneously after the Prague hardfork:

1. A validator is registered in the AddressBook with a CNStaking balance **< 1 KAIA** (truncates to `StakingAmount = 0`).
2. The same validator has a CL pool registered in CLRegistry with a balance **< 1 KAIA** (truncates to `CLStakingAmount = 0`).
3. That validator is selected as block proposer.

Realistic scenarios:
- A validator in the process of withdrawing CNStaking whose balance drops below 1 KAIA before the AddressBook entry is removed, while their CL pool is still registered with minimal or zero balance.
- A validator who registered a CL pool but has not yet deposited into it, and whose CNStaking balance is negligible.
- Private/test networks with small staking amounts.

---

### Recommendation

Add a zero guard in `consolidatedNode.Split()` before dividing:

```go
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
    if c.CLStakingInfo == nil {
        return amount, big.NewInt(0)
    }
    cnAmountBig := big.NewInt(int64(c.StakingAmount))
    clAmountBig := big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
    totalAmount := new(big.Int).Add(cnAmountBig, clAmountBig)

    if totalAmount.Sign() == 0 {
        // Both amounts are zero; assign everything to CN to avoid panic.
        return amount, big.NewInt(0)
    }

    clAmount := new(big.Int).Mul(clAmountBig, amount)
    clAmount = clAmount.Div(clAmount, totalAmount)
    cnAmount := new(big.Int).Sub(amount, clAmount)
    return cnAmount, clAmount
}
```

Additionally, consider filtering out validators with `StakingAmount == 0 && CLStakingAmount == 0` in `consolidateNodes()` or in the proposer-reward path, consistent with the guards already present in `assignStakingRewards`.

---

### Proof of Concept

1. Enable Prague hardfork on a test network.
2. Register validator `V` in AddressBook with 0.5 KAIA staked in CNStaking → `StakingAmount = 0` after truncation.
3. Register a CL pool for `V` in CLRegistry with 0.5 KAIA staked → `CLStakingAmount = 0` after truncation.
4. Wait for `V` to be selected as block proposer.
5. `FinalizeState()` reaches `specWithProposerAndFunds()`, finds `cn.RewardAddr == config.Rewardbase` and `cn.CLStakingInfo != nil`, calls `cn.Split(proposer)`.
6. Inside `Split`: `totalAmount = 0 + 0 = 0`; `clAmount.Div(clAmount, totalAmount)` → **panic: runtime error: integer divide by zero**.
7. Node crashes; consensus diverges.

### Citations

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

**File:** kaiax/staking/impl/getter.go (L286-300)
```go
	for i, a := range amounts {
		stakingAmounts[i] = big.NewInt(0).Div(a, big.NewInt(params.KAIA)).Uint64()
	}

	// Collect the CL registry results to StakingInfo fields.
	// If there is no CL registry result, it will be nil.
	var clStakingInfos staking.CLStakingInfos
	if len(clRes.NodeIds) > 0 {
		clStakingInfos = make(staking.CLStakingInfos, len(clRes.NodeIds))
		for i := range clRes.NodeIds {
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
```

**File:** kaiax/reward/impl/getter.go (L334-368)
```go
// getDeferredRewardFullKore is for non-Simple policy and after Kore.
func getDeferredRewardFullKore(config *reward.RewardConfig, execFee, burntFee, blobFee *big.Int, si *staking.StakingInfo) (*reward.RewardSpec, error) {
	var (
		spec             = reward.NewRewardSpec()
		minted           = new(big.Int).Set(config.MintingAmount)
		distributableFee = new(big.Int).Sub(execFee, burntFee)
	)

	// Distribute using RewardRatio first. Unlike Legacy, fees are not distributed here
	// because fees are exclusively allocated to proposer. By the way, remainder goes to KIF.
	validators, kif, kef := config.RewardRatio.Split(minted)
	proposer, stakers := config.Kip82Ratio.Split(validators)
	ratioRemainder := calcRemainder(minted, proposer, stakers, kif, kef)
	kif.Add(kif, ratioRemainder)

	// Further distribute using Kip82Ratio. By the way, remainder goes to proposer.
	// After Prague, if the CLStaking is not nil, the proposer and staking rewards are proportionally distributed to both CN and CL.
	// For proposer rewards, see `specWithProposerAndFunds`.
	stakersAlloc, kip82Remainder := assignStakingRewards(config, stakers, si)
	proposer.Add(proposer, kip82Remainder)
	stakers.Sub(stakers, kip82Remainder)

	// Proposer gets the fees.
	proposer.Add(proposer, distributableFee)

	spec.Minted = minted
	spec.TotalFee = new(big.Int).Add(execFee, blobFee)
	spec.BurntFee = new(big.Int).Add(burntFee, blobFee)
	spec.Stakers = stakers
	for addr, amount := range stakersAlloc {
		spec.IncRecipient(addr, amount)
	}
	spec = specWithProposerAndFunds(spec, config, proposer, kif, kef, si)
	return spec, nil
}
```

**File:** kaiax/reward/impl/getter.go (L460-481)
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
```

**File:** kaiax/reward/impl/getter.go (L516-530)
```go
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

**File:** kaiax/reward/impl/getter.go (L572-588)
```go
	// Handle CLStakingInfo for proposer after Prague
	cns := si.ConsolidatedNodes()
	for _, cn := range cns {
		if cn.RewardAddr != config.Rewardbase {
			continue
		}
		if cn.CLStakingInfo == nil {
			// Early exit if there's no CL for proposer
			break
		}

		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
	}
```

**File:** kaiax/reward/impl/getter.go (L622-638)
```go
	// Handle CLStakingInfo for proposer after Prague
	cns := si.ConsolidatedNodes()
	for _, cn := range cns {
		if cn.RewardAddr != config.Rewardbase {
			continue
		}
		if cn.CLStakingInfo == nil {
			// Early exit if there's no CL for proposer
			break
		}

		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
	}
```
