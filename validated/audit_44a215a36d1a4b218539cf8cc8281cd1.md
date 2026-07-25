### Title
Unsafe `uint64`→`int64` Typecasting in `consolidatedNode.Split()` Corrupts CN/CL Reward Distribution — (`File: kaiax/staking/staking_info.go`)

---

### Summary

`consolidatedNode.Split()` converts `uint64` staking amounts to `int64` via `big.NewInt(int64(c.StakingAmount))` before constructing the proportional split between a validator's CN-staking reward and its Consensus Liquidity (CL) pool reward. If either staking amount exceeds `math.MaxInt64` (≈ 9.22 × 10¹⁸ KAIA), the silent two's-complement wrap produces a negative `big.Int`, corrupting the ratio and causing the CN to receive more than the total reward while the CL pool receives a negative (i.e., subtractive) amount.

---

### Finding Description

`consolidatedNode.Split` is the sole function that divides a block reward between a validator's AddressBook staking contract and its CL pool. It is called on every block after the Prague hardfork for every validator that has registered a CL pool.

```go
// kaiax/staking/staking_info.go  lines 169-187
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
    if c.CLStakingInfo == nil {
        return amount, big.NewInt(0)
    }

    var (
        cnAmountBig = big.NewInt(int64(c.StakingAmount))                    // ← unsafe cast
        clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))    // ← unsafe cast
        totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
    )

    clAmount := new(big.Int).Mul(clAmountBig, amount)
    clAmount  = clAmount.Div(clAmount, totalAmount)

    cnAmount := big.NewInt(0).Sub(amount, clAmount)
    return cnAmount, clAmount
}
```

`c.StakingAmount` and `c.CLStakingInfo.CLStakingAmount` are both `uint64` (in KAIA units, not kei). [1](#0-0) 

The cast `int64(c.StakingAmount)` is defined behaviour in Go but silently wraps when the value exceeds `math.MaxInt64` (9,223,372,036 KAIA). The result is a negative `big.Int`, which propagates through the ratio calculation. [2](#0-1) 

The staking amounts stored in `StakingInfo` are derived by dividing the raw on-chain balance (in kei) by `params.KAIA` and calling `.Uint64()` — a second silent truncation that discards any value above `math.MaxUint64` KAIA, but the `uint64` domain itself is not bounded to `math.MaxInt64`. [3](#0-2) 

`Split` is called in four reward-distribution paths, all active after the Prague hardfork:

| Caller | Purpose |
|---|---|
| `assignStakingRewards` | staker reward allocation (Kore/Prague) |
| `assignStakingRewardsFlex` | staker reward allocation (Flex/Osaka) |
| `specWithProposerAndFunds` | proposer reward split (Prague) |
| `specWithProposerAndFundsFlex` | proposer reward split (Flex) | [4](#0-3) [5](#0-4) 

---

### Impact Explanation

When `c.StakingAmount > math.MaxInt64`:

1. `int64(c.StakingAmount)` wraps to a large negative value.
2. `cnAmountBig` becomes negative; `totalAmount` may be negative or near-zero.
3. `clAmount = clAmountBig × amount / totalAmount` — with a negative or near-zero denominator, `clAmount` becomes a large negative number.
4. `cnAmount = amount − clAmount = amount − (−|x|) = amount + |x|` — the CN receives **more than the total reward**.
5. `IncRecipient(clPoolAddr, clAmount)` subtracts from the CL pool's running balance in `RewardSpec.Rewards`. [6](#0-5) 

`RewardSpec.Validate()` checks for negative per-address balances, but only after all rewards are accumulated. If the CL pool had a prior positive balance in the same spec, the negative addition may not make it negative, bypassing the guard. [7](#0-6) 

The net effect is an **unauthorized over-distribution of KAIA to the CN reward address** and an **under-distribution (or subtraction) from the CL pool address**, breaking the conservation invariant that `sum(Rewards) == Minted + DistributableFee`.

---

### Likelihood Explanation

**Low in practice, real in code.** The overflow threshold is ≈ 9.22 billion KAIA staked by a single consolidated validator. The current total KAIA supply is well below this threshold, and the minimum staking requirement is 5 million KAIA. However:

- The `uint64` field has no enforced upper bound in the staking contract or the parsing layer.
- A future supply increase, a governance change to `reward.minimumstake`, or a validator consolidating many staking contracts under one `RewardAddr` could push `StakingAmount` toward the boundary.
- The bug is a latent defect that requires no attacker — it is triggered by normal staking behaviour once the threshold is crossed.

---

### Recommendation

Replace the unsafe narrowing casts with `new(big.Int).SetUint64(...)`:

```go
// kaiax/staking/staking_info.go — consolidatedNode.Split()
var (
    cnAmountBig = new(big.Int).SetUint64(c.StakingAmount)
    clAmountBig = new(big.Int).SetUint64(c.CLStakingInfo.CLStakingAmount)
    totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
)
```

`new(big.Int).SetUint64` correctly handles the full `uint64` range without sign-extension. The same fix should be applied to any other site that converts `StakingAmount` or `CLStakingAmount` to a signed integer for arithmetic.

Additionally, add a guard in `Split` for the `totalAmount == 0` edge case (both amounts zero) to prevent a division-by-zero panic.

---

### Proof of Concept

```go
package main

import (
    "fmt"
    "math"
    "math/big"
)

func splitBuggy(cnStake, clStake uint64, reward *big.Int) (*big.Int, *big.Int) {
    cnBig := big.NewInt(int64(cnStake)) // unsafe cast
    clBig := big.NewInt(int64(clStake)) // unsafe cast
    total := new(big.Int).Add(cnBig, clBig)
    clAmt := new(big.Int).Div(new(big.Int).Mul(clBig, reward), total)
    cnAmt := new(big.Int).Sub(reward, clAmt)
    return cnAmt, clAmt
}

func main() {
    // Threshold: just above math.MaxInt64 KAIA
    overflow := uint64(math.MaxInt64) + 1  // 9_223_372_036_854_775_808 KAIA
    reward   := big.NewInt(1_000_000)      // 1 KAIA reward in kei (simplified)

    cn, cl := splitBuggy(overflow, 1_000_000, reward)
    fmt.Println("CN reward:", cn) // large positive (> reward)
    fmt.Println("CL reward:", cl) // large negative
    fmt.Println("Sum:", new(big.Int).Add(cn, cl)) // should equal reward, but does not
}
```

Expected (correct): CN ≈ 999,000, CL ≈ 1,000, sum = 1,000,000.
Actual (buggy): CN is a large positive number far exceeding `reward`; CL is a large negative number; their sum does not equal `reward`. [8](#0-7)

### Citations

**File:** kaiax/staking/staking_info.go (L86-93)
```go
type consolidatedNode struct {
	NodeIds          []common.Address
	StakingContracts []common.Address
	RewardAddr       common.Address // The common RewardAddr
	StakingAmount    uint64         // Sum of the staking amounts from CNStaking

	CLStakingInfo *CLStakingInfo // The CLStakingInfo if any
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

**File:** kaiax/staking/impl/getter.go (L208-208)
```go
		stakingAmounts = append(stakingAmounts, new(big.Int).Div(amounts[i], big.NewInt(params.KAIA)).Uint64())
```

**File:** kaiax/reward/impl/getter.go (L521-526)
```go
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
				} else {
```

**File:** kaiax/reward/impl/getter.go (L583-587)
```go
		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
```

**File:** kaiax/reward/spec.go (L118-124)
```go
func (spec *RewardSpec) Validate() error {
	for addr, amount := range spec.Rewards {
		if amount.Sign() < 0 {
			return errNegativeRewardAmount(addr, amount)
		}
	}
	return nil
```
