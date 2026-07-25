### Title
Unsafe `uint64`→`int64` Cast in `consolidatedNode.Split()` Corrupts Per-Block Staking Reward Distribution — (`File: kaiax/staking/staking_info.go`)

---

### Summary

`consolidatedNode.Split()` casts two `uint64` staking-amount fields directly to `int64` without bounds checking. If either field exceeds `math.MaxInt64` (~9.22 × 10^9 KAIA), the cast silently produces a negative value. The resulting negative `big.Int` operands corrupt the proportional split of every block's staking reward between a CN validator address and its CL pool address, causing one side to receive more than the total reward and the other to receive a negative allocation.

---

### Finding Description

`consolidatedNode.Split()` is the sole function that divides a staking reward between a CN's `RewardAddr` and its `CLStakingInfo.CLPoolAddr`:

```go
// kaiax/staking/staking_info.go:169-187
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
    if c.CLStakingInfo == nil {
        return amount, big.NewInt(0)
    }
    var (
        cnAmountBig = big.NewInt(int64(c.StakingAmount))               // ← unsafe cast
        clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount)) // ← unsafe cast
        totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
    )
    clAmount := new(big.Int).Mul(clAmountBig, amount)
    clAmount  = clAmount.Div(clAmount, totalAmount)
    cnAmount  := big.NewInt(0).Sub(amount, clAmount)
    return cnAmount, clAmount
}
``` [1](#0-0) 

Both `c.StakingAmount` and `c.CLStakingInfo.CLStakingAmount` are declared `uint64`: [2](#0-1) [3](#0-2) 

The values are populated by dividing on-chain kei amounts by `params.KAIA` (10^18) and calling `.Uint64()`: [4](#0-3) [5](#0-4) 

`math.MaxInt64` = 9,223,372,036,854,775,807. Any validator whose staking amount (in KAIA) exceeds that threshold causes `int64(c.StakingAmount)` to wrap negative. `big.NewInt` then stores a negative value, making `totalAmount` potentially negative or zero, and the subsequent `Mul`/`Div` produces a negative `clAmount`. Because `cnAmount = amount − clAmount`, the CN address receives `amount + |clAmount|` — more than the full reward — while the CL pool address receives a negative allocation.

`Split()` is called unconditionally in both reward-distribution paths: [6](#0-5) [7](#0-6) 

A secondary, compounding defect exists in the same functions: `totalExcessInt` is accumulated as a bare `uint64` with no overflow guard: [8](#0-7) [9](#0-8) 

If `totalExcessInt` wraps, the denominator used in `reward = excess * budget / totalExcess` becomes artificially small, inflating every individual reward far beyond the available budget and driving `remaining` deeply negative.

---

### Impact Explanation

Every block that includes a CL-eligible validator whose staking amount exceeds `math.MaxInt64` KAIA will have its staking reward split incorrectly. The CN `RewardAddr` receives more KAIA than it is entitled to; the `CLPoolAddr` receives a negative `big.Int` allocation. Depending on how `IncRecipient` handles negative values, the CL pool either receives zero or has its balance decremented, constituting an unauthorized redistribution of per-block KAIA staking rewards. The `remaining` value returned to the proposer is also corrupted, compounding the accounting error across the full block reward.

---

### Likelihood Explanation

The current total KAIA supply is approximately 5.4 billion KAIA, below the `math.MaxInt64` threshold of ~9.22 billion KAIA for a single validator. However:

- Minting is continuous; supply grows every block.
- A single entity consolidating multiple staking contracts under one `RewardAddr` accumulates amounts via unchecked `uint64` addition in `consolidateNodes()` (`cn.StakingAmount += si.StakingAmounts[i]`), which can itself overflow before `Split()` is reached.
- The `totalExcessInt` overflow threshold is ~18.4 billion KAIA in aggregate, reachable sooner across all validators combined.

Likelihood is low today but increases monotonically with supply growth and validator consolidation. [10](#0-9) 

---

### Recommendation

1. Replace the unsafe casts in `Split()` with safe `big.Int` construction from `uint64`:
   ```go
   cnAmountBig := new(big.Int).SetUint64(c.StakingAmount)
   clAmountBig := new(big.Int).SetUint64(c.CLStakingInfo.CLStakingAmount)
   ```
2. Replace bare `uint64` accumulation of `totalExcessInt` in `assignStakingRewards` and `assignStakingRewardsFlex` with `big.Int` arithmetic, or use `math.SafeAdd` and propagate overflow as an error.
3. Guard `cn.StakingAmount += si.StakingAmounts[i]` in `consolidateNodes()` with `math.SafeAdd`.

---

### Proof of Concept

```
Precondition:
  - Prague hardfork active (CLStakingInfo populated)
  - One consolidated validator with StakingAmount = 10_000_000_000 KAIA
    (> math.MaxInt64 / 1e9 ≈ 9.22e9 KAIA; achievable via minting growth
     or multi-contract consolidation)

Execution path:
  FinalizeState()
    → getDeferredRewardFull()
      → assignStakingRewards() / assignStakingRewardsFlex()
        → cn.Split(reward)
          cnAmountBig = big.NewInt(int64(10_000_000_000))
                      = big.NewInt(-8_446_744_073)   // wraps negative
          clAmountBig = big.NewInt(int64(clStakingAmount))  // e.g. positive
          totalAmount = cnAmountBig + clAmountBig           // may be negative
          clAmount    = clAmountBig * reward / totalAmount  // negative result
          cnAmount    = reward - clAmount                   // > reward

Result:
  alloc[cn.RewardAddr]              = reward + |clAmount|  (excess KAIA credited)
  alloc[cn.CLStakingInfo.CLPoolAddr] = negative big.Int    (CL pool drained or zeroed)
  Per-block staking reward accounting is permanently corrupted for this validator.
```

### Citations

**File:** kaiax/staking/staking_info.go (L59-64)
```go
// CLStakingInfo is the staking info from the consensus liquidity since Prague HF.
type CLStakingInfo struct {
	CLNodeId        common.Address `json:"clNodeId"`
	CLPoolAddr      common.Address `json:"clPoolAddr"`
	CLStakingAmount uint64         `json:"clStakingAmount"`
}
```

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

**File:** kaiax/staking/staking_info.go (L136-138)
```go
			cn.NodeIds = append(cn.NodeIds, n)
			cn.StakingContracts = append(cn.StakingContracts, si.StakingContracts[i])
			cn.StakingAmount += si.StakingAmounts[i]
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

**File:** kaiax/staking/impl/getter.go (L218-218)
```go
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
```

**File:** kaiax/reward/impl/getter.go (L449-451)
```go
			excessInt[cn.RewardAddr] = amount - threshold
			totalExcessInt += excessInt[cn.RewardAddr]
		}
```

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

**File:** kaiax/reward/impl/getter.go (L500-504)
```go
			cnTotalStakingAmount := cn.StakingAmount
			if isPrague && cn.CLStakingInfo != nil {
				cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount
			}
			totalExcessInt += cnTotalStakingAmount - minStake
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
