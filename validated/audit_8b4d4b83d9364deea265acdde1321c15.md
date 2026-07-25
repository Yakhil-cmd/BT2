### Title
Division by Zero in `consolidatedNode.Split` Panics All Nodes During Block Finalization — (`kaiax/staking/staking_info.go`)

---

### Summary

`consolidatedNode.Split` divides by `totalAmount = cn.StakingAmount + cn.CLStakingInfo.CLStakingAmount` with no zero-guard. It is called unconditionally from `specWithProposerAndFunds` and `specWithProposerAndFundsFlex` during block finalization whenever the proposer has a non-nil `CLStakingInfo`. If both staking amounts round to zero (each < 1 KAIA), every node panics while finalizing that block, halting the chain.

---

### Finding Description

`consolidatedNode.Split` in `kaiax/staking/staking_info.go` computes the CL/CN reward split:

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
``` [1](#0-0) 

Both `StakingAmount` and `CLStakingInfo.CLStakingAmount` are stored as `uint64` in whole-KAIA units, truncated from the raw balance via integer division by `params.KAIA`:

```go
CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
``` [2](#0-1) 

If the staking contract holds < 1 KAIA and the CL pool also holds < 1 KAIA, both truncate to 0, making `totalAmount = 0`.

`Split` is called without any zero-check in two reward-finalization paths:

**`specWithProposerAndFunds`** (Kore/Prague path):
```go
cnAmount, clAmount := cn.Split(proposer)
``` [3](#0-2) 

**`specWithProposerAndFundsFlex`** (Osaka/Flex path):
```go
cnAmount, clAmount := cn.Split(proposer)
``` [4](#0-3) 

Both functions are invoked from `getDeferredRewardFullKore` / `getDeferredRewardFullFlex`, which are called by `GetDeferredReward` during `FinalizeState` — the mandatory end-of-block state transition executed by every node. [5](#0-4) 

The two other `Split` call-sites in `assignStakingRewards` and `assignStakingRewardsFlex` are guarded by `cnTotalStakingAmount > minStake` / `excessInt > 0`, so `totalAmount > 0` is guaranteed there. The proposer-reward paths have no equivalent guard. [6](#0-5) 

---

### Impact Explanation

`FinalizeState` is called by every full node when importing a block. A Go integer division by zero is an unrecoverable runtime panic. If the panic is not caught by a `recover()` in the import pipeline, the node process crashes. Because every honest node must process every block, a single block proposed by the affected validator causes a **network-wide crash and chain halt**. This is an invalid state transition / consensus divergence impact: honest nodes cannot advance past that block height.

---

### Likelihood Explanation

Three conditions must hold simultaneously:

1. **Prague (or Osaka) hardfork is active** — required for `CLStakingInfo` to be populated.
2. **The proposer is registered in the CLRegistry** (`CLStakingInfo != nil`) but both its AddressBook staking contract and its CL pool hold < 1 KAIA (so both amounts truncate to 0 after `/ params.KAIA`).
3. **The validator is qualified to propose.** The valset module demotes validators whose `StakingAmount < minStake`, but includes a critical fallback:

```go
// If all validators are demoted, then no one is demoted.
if demoted.Len() == len(council.List()) {
    demoted = valset.NewAddressSet(nil)
}
``` [7](#0-6) 

Additionally, in `single` governance mode the governing node is unconditionally qualified regardless of staking amount: [8](#0-7) 

Either escape hatch allows a validator with `StakingAmount = 0` to be a proposer. The scenario is low-probability on a healthy mainnet but is reachable without any privileged access: a validator operator simply needs to register in the CLRegistry while holding negligible balances in both contracts.

---

### Recommendation

Add a zero-check at the top of `Split` before dividing:

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
    // Guard: if total staking is zero, all reward goes to the CN address.
    if totalAmount.Sign() == 0 {
        return amount, big.NewInt(0)
    }
    clAmount := new(big.Int).Mul(clAmountBig, amount)
    clAmount = clAmount.Div(clAmount, totalAmount)
    cnAmount := new(big.Int).Sub(amount, clAmount)
    return cnAmount, clAmount
}
```

---

### Proof of Concept

**Setup (post-Prague, WeightedRandom policy):**

1. All council validators have `StakingAmount = 0` (staking contracts hold < 1 KAIA each). The `getDemotedValidatorsIstanbul` fallback fires — no one is demoted, all are qualified.
2. Validator V is registered in the CLRegistry with `CLStakingAmount = 0` (CL pool holds < 1 KAIA). `consolidateNodes()` attaches a non-nil `CLStakingInfo` with `CLStakingAmount = 0` to V's `consolidatedNode`.
3. V is selected as proposer for block N.

**Execution path:**

```
FinalizeState(block N)
  → GetDeferredReward(block N)
    → getDeferredRewardFull(...)
      → getDeferredRewardFullKore(...)
        → specWithProposerAndFunds(..., si)
          → cn.Split(proposer)   // cn.StakingAmount=0, cn.CLStakingInfo.CLStakingAmount=0
            → totalAmount = 0+0 = 0
            → clAmount.Div(clAmount, totalAmount)  // integer division by zero → PANIC
```

Every node importing block N crashes. The chain halts at height N−1. [9](#0-8) [10](#0-9)

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

**File:** kaiax/staking/impl/getter.go (L215-219)
```go
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

**File:** kaiax/reward/impl/getter.go (L514-531)
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
```

**File:** kaiax/reward/impl/getter.go (L580-587)
```go
			break
		}

		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
```

**File:** kaiax/reward/impl/getter.go (L622-637)
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
```

**File:** kaiax/valset/impl/getter_demote.go (L94-97)
```go
	// If all validators are demoted, then no one is demoted.
	if demoted.Len() == len(council.List()) {
		demoted = valset.NewAddressSet(nil)
	}
```

**File:** kaiax/valset/impl/getter_demote.go (L99-102)
```go
	// Under single governance mode, governing node cannot be demoted.
	if singleMode && demoted.Contains(governingNode) {
		demoted.Remove(governingNode)
	}
```
