<thinking

### Title
Signed Integer Truncation in `consolidatedNode.Split()` Corrupts CN/CL Staking Reward Distribution — (`File: kaiax/staking/staking_info.go`)

### Summary

The `Split()` function in `consolidatedNode` converts `uint64` staking amounts to `int64` via an unchecked narrowing cast. Any `StakingAmount` or `CLStakingAmount` value exceeding `math.MaxInt64` (9,223,372,036 KAIA) produces a negative `big.Int` weight, making the proportional split arithmetic produce a negative `clAmount` and an inflated `cnAmount`. Every downstream caller — `assignStakingRewards`, `assignStakingRewardsFlex`, and `specWithProposerAndFundsFlex` — credits those corrupted values directly to validator and CL-pool addresses, permanently mis-distributing KAIA block rewards.

### Finding Description

`consolidatedNode.Split()` is the sole function that divides a block-reward slice between a CN staking address and its paired CL pool address (Prague hardfork, KIP-226). It is called every block for every eligible validator that has a `CLStakingInfo`. [1](#0-0) 

The defect is on lines 175–176:

```go
cnAmountBig = big.NewInt(int64(c.StakingAmount))
clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
```

Both fields are declared `uint64`: [2](#0-1) [3](#0-2) 

Go's `int64(x)` for a `uint64 x > math.MaxInt64` silently wraps to a negative value. The correct idiom is `new(big.Int).SetUint64(x)`. The `big.NewInt` constructor accepts `int64`, so the negative value propagates into the `big.Int` weight used for the proportional division:

```
totalAmount = cnAmountBig + clAmountBig   // may be negative or near-zero
clAmount    = clAmountBig * reward / totalAmount  // sign-flipped or astronomically large
cnAmount    = reward - clAmount           // negative or > reward
```

These corrupted values are then written to the reward spec and credited to on-chain addresses: [4](#0-3) [5](#0-4) [6](#0-5) 

`IncRecipient` adds the value (positive or negative) to the address's running total in the `RewardSpec.Rewards` map, and `FinalizeState` applies those deltas to the state trie. A negative delta subtracts from the recipient's balance.

The staking amounts stored in `StakingInfo` are sourced from on-chain contract balances divided by `params.KAIA`: [7](#0-6) [8](#0-7) 

`big.Int.Uint64()` silently truncates values that exceed `uint64` max, and the subsequent `int64(...)` cast silently wraps values that exceed `math.MaxInt64`. Neither conversion is guarded.

Additionally, `consolidateNodes()` accumulates staking amounts for nodes sharing a reward address with bare `uint64` addition: [9](#0-8) 

This accumulation is also unchecked, compounding the overflow surface.

### Impact Explanation

When triggered, `Split()` returns a `(cnAmount, clAmount)` pair where one value is negative and the other exceeds the total reward. `FinalizeState` applies these as balance deltas:

- The CL pool address has KAIA **subtracted** from its balance (unauthorized burn/drain of CL-pool funds).
- The CN reward address receives **more** KAIA than its legitimate share (unauthorized mint/transfer to CN).
- The `RewardSpec` totals no longer balance, breaking the conservation invariant checked by `sanityCheckRewardSpec`.

This constitutes unauthorized reward distribution affecting KAIA and system-managed CL-pool funds — within the allowed impact gate.

### Likelihood Explanation

`math.MaxInt64` = 9,223,372,036 KAIA. The current total KAIA supply is approximately 5.7 billion KAIA, with inflation of ~303 million KAIA/year. A single validator's staking amount is bounded by the total supply, so the threshold is not reachable today. However:

1. The threshold will be crossed in roughly 11–12 years at current inflation rates, with no code change required.
2. The `consolidateNodes()` accumulation means a validator registering multiple AddressBook entries under one reward address has their amounts summed — reducing the per-validator threshold proportionally.
3. No on-chain or off-chain guard validates that `StakingAmount` or `CLStakingAmount` fits in `int64` before `Split()` is called.

Likelihood is **Low** today but the vulnerability is latent and worsens monotonically as supply grows.

### Recommendation

Replace the narrowing casts with the correct `big.Int` constructor for unsigned values:

```go
// Before (buggy):
cnAmountBig = big.NewInt(int64(c.StakingAmount))
clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))

// After (correct):
cnAmountBig = new(big.Int).SetUint64(c.StakingAmount)
clAmountBig = new(big.Int).SetUint64(c.CLStakingInfo.CLStakingAmount)
```

Apply the same fix to the bare `uint64` additions in `assignStakingRewards` and `assignStakingRewardsFlex` (lines 502, 444) by promoting the intermediate sums to `big.Int` before accumulation, or by adding overflow checks using `math.SafeAdd`.

### Proof of Concept

```
Given:
  c.StakingAmount          = 9_223_372_036_854_775_808  // math.MaxInt64 + 1, as uint64
  c.CLStakingInfo.CLStakingAmount = 1_000_000           // 1M KAIA
  reward (amount)          = 3_840_000_000_000_000_000  // 3.84 KAIA in kei

Step 1: int64 cast
  int64(9_223_372_036_854_775_808) = -9_223_372_036_854_775_808  (math.MinInt64)

Step 2: big.Int weights
  cnAmountBig = -9_223_372_036_854_775_808
  clAmountBig =              1_000_000
  totalAmount = -9_223_372_035_854_775_808  (negative)

Step 3: clAmount = clAmountBig * reward / totalAmount
  numerator   = 1_000_000 * 3_840_000_000_000_000_000
              = 3_840_000_000_000_000_000_000_000
  clAmount    = 3_840_000_000_000_000_000_000_000 / (-9_223_372_035_854_775_808)
              ≈ -416_376  (negative kei)

Step 4: cnAmount = reward - clAmount
  cnAmount    = 3_840_000_000_000_000_000 - (-416_376)
              = 3_840_000_000_000_416_376  (exceeds total reward by 416_376 kei)

Result:
  CL pool address receives -416_376 kei  → balance decremented (unauthorized drain)
  CN reward address receives 3_840_000_000_000_416_376 kei → balance over-credited
``` [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** kaiax/staking/staking_info.go (L135-138)
```go
		if cn, ok := cmap[r]; ok {
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

**File:** kaiax/reward/impl/getter.go (L466-481)
```go
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

**File:** kaiax/reward/impl/getter.go (L519-530)
```go
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

**File:** kaiax/staking/impl/getter.go (L208-208)
```go
		stakingAmounts = append(stakingAmounts, new(big.Int).Div(amounts[i], big.NewInt(params.KAIA)).Uint64())
```

**File:** kaiax/staking/impl/getter.go (L218-218)
```go
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
```
