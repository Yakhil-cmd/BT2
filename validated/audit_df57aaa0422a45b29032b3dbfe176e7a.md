### Title
Unchecked `uint64`→`int64` Cast in `consolidatedNode.Split` Corrupts Per-Block KAIA Reward Distribution — (`kaiax/staking/staking_info.go`)

---

### Summary

`consolidatedNode.Split` in `kaiax/staking/staking_info.go` converts both `c.StakingAmount` and `c.CLStakingInfo.CLStakingAmount` (both `uint64`, denominated in KAIA) to `int64` via a bare `big.NewInt(int64(...))` cast. If either value exceeds `math.MaxInt64` (~9.22 × 10⁹ KAIA), the cast silently wraps to a negative integer, producing a corrupted `totalAmount` denominator. Every call to `Split` in the block-finalization reward path then distributes incorrect KAIA amounts to the CN reward address and the CL pool address.

---

### Finding Description

The vulnerable code is:

```go
// kaiax/staking/staking_info.go  lines 174-177
var (
    cnAmountBig = big.NewInt(int64(c.StakingAmount))                    // ← unsafe cast
    clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))    // ← unsafe cast
    totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
)
clAmount := new(big.Int).Mul(clAmountBig, amount)
clAmount  = clAmount.Div(clAmount, totalAmount)
cnAmount  := big.NewInt(0).Sub(amount, clAmount)
``` [1](#0-0) 

`c.StakingAmount` is declared as `uint64` (the sum of all CNStaking contract amounts sharing one reward address, in KAIA). `c.CLStakingInfo.CLStakingAmount` is also `uint64` (CL pool stake, in KAIA). [2](#0-1) 

When either value exceeds `math.MaxInt64` = 9,223,372,036 KAIA, `int64(value)` wraps to a negative number. `big.NewInt` of a negative number produces a negative `big.Int`, so `totalAmount` can become zero or negative. The resulting `clAmount` is then negative (positive numerator / negative denominator), and `cnAmount = amount − clAmount` becomes larger than `amount`.

`Split` is called in four production reward-distribution functions that run at every block finalization:

| Call site | Purpose |
|---|---|
| `assignStakingRewards` line 523 | Kore-era staker reward split |
| `assignStakingRewardsFlex` line 475 | Osaka/flex-era staker reward split |
| `specWithProposerAndFunds` line 633 | Proposer reward split |
| `specWithProposerAndFundsFlex` line 583 | Flex proposer reward split | [3](#0-2) [4](#0-3) 

The corrupted `cnAmount` / `clAmount` values are written directly into `spec.Rewards` and applied to state via `state.AddBalance`:

```go
// kaiax/reward/impl/blockstate.go  lines 53-55
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [5](#0-4) 

A negative `clAmount` passed to `AddBalance` subtracts KAIA from the CL pool address, while the CN reward address receives more than the full reward — an unauthorized transfer.

---

### Impact Explanation

If `totalAmount` becomes zero: integer division panics, crashing the node during `FinalizeState` (consensus halt on the proposer node).

If `totalAmount` becomes negative: `clAmount` is negative, so:
- `state.AddBalance(CLPoolAddr, negative)` **drains** KAIA from the CL pool.
- `state.AddBalance(CNRewardAddr, amount + |clAmount|)` **mints** excess KAIA to the CN reward address.

Both outcomes are unauthorized asset movements affecting KAIA and bridged assets held in CL pool contracts.

---

### Likelihood Explanation

The current Kaia total supply is approximately 5.4 billion KAIA. `math.MaxInt64` is ~9.22 billion KAIA. A single validator's `StakingAmount` (the sum across all CNStaking contracts sharing one reward address, accumulated at `consolidateNodes` line 138) cannot currently exceed the total supply. [6](#0-5) 

However:
1. The minting amount is governance-controlled and can be raised, accelerating supply growth toward the threshold.
2. The `consolidateNodes` accumulation (`cn.StakingAmount += si.StakingAmounts[i]`) is itself an unchecked `uint64` addition — if a reward address registers enough CNStaking contracts, the sum could overflow `uint64` entirely, producing an arbitrary small value that then passes the `>= minStake` check with a corrupted amount.
3. The `CLStakingAmount` is parsed with `.Uint64()` (silent truncation) from an on-chain `big.Int`, so a malformed CL registry entry could inject an arbitrary `uint64` value. [7](#0-6) 

---

### Recommendation

Replace the unsafe casts with `new(big.Int).SetUint64(...)`:

```go
// kaiax/staking/staking_info.go  Split()
var (
    cnAmountBig = new(big.Int).SetUint64(c.StakingAmount)
    clAmountBig = new(big.Int).SetUint64(c.CLStakingInfo.CLStakingAmount)
    totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
)
```

Also add a guard for `totalAmount.Sign() <= 0` before the division to prevent a panic.

Apply the same fix to the `totalExcessInt` accumulation in `assignStakingRewards` and `assignStakingRewardsFlex`, which accumulate `uint64` excess values across all validators without overflow protection. [8](#0-7) 

---

### Proof of Concept

```
Precondition: a validator's consolidated StakingAmount > math.MaxInt64 KAIA
              (e.g., via governance raising mintingAmount, or multiple CNStaking
               contracts sharing one RewardAddr summing past the threshold)

1. At block N, FinalizeState calls GetDeferredReward → getDeferredRewardFull
   → assignStakingRewards (or Flex variant)
   → cn.Split(reward) where cn.StakingAmount = 9_223_372_036_854_775_808

2. int64(9_223_372_036_854_775_808) = -9_223_372_036_854_775_808  (wraps)
   cnAmountBig = big.NewInt(-9_223_372_036_854_775_808)  // negative
   clAmountBig = big.NewInt(1_000_000_000)               // e.g. 1B KAIA CL stake
   totalAmount = -9_223_372_035_854_775_808              // negative

3. clAmount = 1_000_000_000 * reward / (-9_223_372_035_854_775_808)
            = negative value

4. cnAmount = reward - clAmount = reward + |clAmount| > reward

5. state.AddBalance(CLPoolAddr,   negative) → drains CL pool
   state.AddBalance(CNRewardAddr, >reward)  → excess KAIA credited to CN
```

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

**File:** kaiax/staking/staking_info.go (L135-148)
```go
		if cn, ok := cmap[r]; ok {
			cn.NodeIds = append(cn.NodeIds, n)
			cn.StakingContracts = append(cn.StakingContracts, si.StakingContracts[i])
			cn.StakingAmount += si.StakingAmounts[i]
		} else {
			cmap[r] = &consolidatedNode{
				NodeIds:          []common.Address{n},
				StakingContracts: []common.Address{si.StakingContracts[i]},
				RewardAddr:       r,
				StakingAmount:    si.StakingAmounts[i],
			}
			rList = append(rList, r)
		}
	}
```

**File:** kaiax/staking/staking_info.go (L174-184)
```go
	var (
		cnAmountBig = big.NewInt(int64(c.StakingAmount))
		clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
		totalAmount = new(big.Int).Add(cnAmountBig, clAmountBig)
	)

	clAmount := new(big.Int).Mul(clAmountBig, amount)
	clAmount = clAmount.Div(clAmount, totalAmount)

	// The remaining amount is for the CN.
	cnAmount := big.NewInt(0).Sub(amount, clAmount)
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

**File:** kaiax/reward/impl/getter.go (L492-506)
```go
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
```

**File:** kaiax/reward/impl/getter.go (L519-529)
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
```

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```

**File:** kaiax/staking/impl/getter.go (L214-219)
```go
		for i := range clRes.NodeIds {
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
```
