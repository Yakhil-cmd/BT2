### Title
Division by Zero in `consolidatedNode.Split()` Panics Block Finalization When Proposer Has Zero Total Staking — (`kaiax/staking/staking_info.go`)

---

### Summary

After the Prague hardfork, `consolidatedNode.Split()` in `kaiax/staking/staking_info.go` divides by `totalAmount = StakingAmount + CLStakingAmount` without guarding against the case where both values are zero. This is called unconditionally for the block proposer in `specWithProposerAndFunds` and `specWithProposerAndFundsFlex` during `FinalizeState()`. A proposer whose staking contract and CL pool both hold less than 1 KAIA (rounding to 0 in KAIA units) triggers a Go runtime panic, halting block finalization on every honest node that processes that block.

---

### Finding Description

`consolidatedNode.Split()` is responsible for proportionally splitting a reward amount between a validator's CN staking contract and its consensus-liquidity (CL) pool:

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
    ...
}
``` [1](#0-0) 

The only guard is `c.CLStakingInfo == nil`. There is no guard for `totalAmount == 0`.

`Split()` is called for the proposer in both `specWithProposerAndFunds` and `specWithProposerAndFundsFlex`:

```go
// Handle CLStakingInfo for proposer after Prague
cns := si.ConsolidatedNodes()
for _, cn := range cns {
    if cn.RewardAddr != config.Rewardbase { continue }
    if cn.CLStakingInfo == nil { break }

    cnAmount, clAmount := cn.Split(proposer)   // ← no totalAmount check
    ...
}
``` [2](#0-1) [3](#0-2) 

Both staking amounts are rounded down to KAIA units (integer division by `params.KAIA = 1e18`) when the `StakingInfo` is built:

```go
CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64()
``` [4](#0-3) 

Any balance below 1 KAIA (10¹⁸ kei) rounds to 0. A validator whose staking contract holds < 1 KAIA **and** whose CL pool holds < 1 KAIA will produce `StakingAmount = 0` and `CLStakingAmount = 0`, making `totalAmount = 0`.

The staking-reward distribution paths (`assignStakingRewards`, `assignStakingRewardsFlex`) are safe because they gate `Split()` behind `cnTotalStakingAmount > minStake` or `excessInt > 0`. The proposer-reward path has no such gate. [5](#0-4) 

---

### Impact Explanation

`specWithProposerAndFunds` / `specWithProposerAndFundsFlex` are called from `getDeferredRewardFullKore` / `getDeferredRewardFullFlex`, which are called from `GetDeferredReward`, which is called from `FinalizeState()` at the end of every block. A panic here crashes block finalization on every node that attempts to import the block, causing a chain halt (consensus divergence / DoS of all honest nodes).

`big.Int.Div()` panics on a zero divisor per Go's specification. This is not a graceful error return — it is an unrecoverable runtime panic.

---

### Likelihood Explanation

The trigger requires three conditions to coincide after the Prague hardfork:

1. A validator is registered in AddressBook with a staking contract holding < 1 KAIA (rounds to 0).
2. The same validator is registered in CLRegistry with a CL pool holding < 1 KAIA (rounds to 0).
3. That validator is selected as block proposer.

Condition 3 is reachable even with zero staking: the test suite explicitly documents that "validators can be qualified with zero stakes, if all are understaked," and the proposer-list fallback places each validator once when all weights are zero. [6](#0-5) 

---

### Recommendation

Add a zero-total guard at the top of `Split()`, mirroring the existing `CLStakingInfo == nil` guard:

```go
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
    if c.CLStakingInfo == nil {
        return amount, big.NewInt(0)
    }

    cnAmountBig := big.NewInt(int64(c.StakingAmount))
    clAmountBig := big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
    totalAmount := new(big.Int).Add(cnAmountBig, clAmountBig)

    // Guard: if both staking amounts are zero, all reward goes to CN.
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

```go
// Reproduces the panic in consolidatedNode.Split() when both staking amounts are zero.
package staking_test

import (
    "math/big"
    "testing"
    "github.com/kaiachain/kaia/kaiax/staking"
)

func TestSplitZeroTotalPanic(t *testing.T) {
    // Validator registered in CLRegistry but both balances < 1 KAIA → round to 0
    cn := staking.NewConsolidatedNodeForTest(
        0, // StakingAmount = 0 (staking contract < 1 KAIA)
        &staking.CLStakingInfo{
            CLStakingAmount: 0, // CL pool < 1 KAIA
        },
    )
    // This panics: runtime error: integer divide by zero
    cn.Split(big.NewInt(1e18))
}
```

The panic path in production is:

```
FinalizeState()
  → GetDeferredReward()
    → getDeferredRewardFull()
      → getDeferredRewardFullKore()
        → specWithProposerAndFunds()
          → cn.Split(proposer)          ← panic: integer divide by zero
``` [7](#0-6) [8](#0-7)

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

**File:** kaiax/reward/impl/getter.go (L596-642)
```go
func specWithProposerAndFunds(spec *reward.RewardSpec, config *reward.RewardConfig, proposer, kif, kef *big.Int, si *staking.StakingInfo) *reward.RewardSpec {
	newSpec := spec.Copy()

	// If KIF or KEF address is not set, proposer takes it.
	if common.EmptyAddress(si.KIFAddr) {
		newSpec.KIF = common.Big0
		proposer.Add(proposer, kif)
	} else {
		newSpec.KIF = kif
		newSpec.IncRecipient(si.KIFAddr, kif)
	}

	if common.EmptyAddress(si.KEFAddr) {
		newSpec.KEF = common.Big0
		proposer.Add(proposer, kef)
	} else {
		newSpec.KEF = kef
		newSpec.IncRecipient(si.KEFAddr, kef)
	}

	newSpec.Proposer = proposer
	if !config.Rules.IsPrague || si.CLStakingInfos == nil {
		newSpec.IncRecipient(config.Rewardbase, proposer)
		return newSpec
	}

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

	newSpec.IncRecipient(config.Rewardbase, proposer)
	return newSpec
}
```

**File:** kaiax/staking/impl/getter.go (L296-300)
```go
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
```

**File:** kaiax/valset/impl/getter_proposers_test.go (L189-196)
```go
		{
			desc:         "zero stakes",
			qualified:    numsToAddrs(0, 1, 2, 3), // Note: validators can be qualified with zero stakes, if all are understaked.
			amounts:      []uint64{0, 0, 0, 0},
			useGini:      false,
			expectedFreq: []int{1, 1, 1, 1},
			expectedList: numsToAddrs(1, 3, 0, 2),
		},
```
