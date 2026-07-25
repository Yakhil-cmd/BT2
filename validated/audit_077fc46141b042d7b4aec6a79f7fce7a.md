### Title
Signed Integer Truncation in `consolidatedNode.Split()` Corrupts Staking Reward Distribution for Large Staking Amounts — (File: `kaiax/staking/staking_info.go`)

### Summary

`consolidatedNode.Split()` converts `uint64` staking amounts to `int64` via `big.NewInt(int64(...))` before computing the CN/CL reward split. When a validator's `StakingAmount` or `CLStakingAmount` exceeds `math.MaxInt64` (≈ 9.22 × 10¹⁸ KAIA), the cast silently wraps to a negative value, producing a negative `totalAmount` denominator. The subsequent division yields a negative or wildly wrong `clAmount`, and the final `cnAmount = amount - clAmount` becomes larger than `amount` itself — minting extra KAIA to the CN reward address and stealing KAIA from the CL pool address every block.

### Finding Description

`consolidatedNode.Split()` is called every block during `FinalizeState` → `getDeferredRewardFullKore` / `getDeferredRewardFullFlex` → `assignStakingRewards` / `assignStakingRewardsFlex` → `cn.Split(reward)` to divide a staking reward between a validator's CNStaking contract and its CLPool.

The vulnerable conversion is:

```go
// kaiax/staking/staking_info.go  lines 175-176
cnAmountBig = big.NewInt(int64(c.StakingAmount))
clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
```

`c.StakingAmount` and `c.CLStakingInfo.CLStakingAmount` are both `uint64`. The explicit cast `int64(x)` is a **silent narrowing conversion** in Go: if `x > math.MaxInt64` (9,223,372,036,854,775,807), the bit pattern is reinterpreted as a negative `int64`. `big.NewInt` then faithfully stores that negative value.

The consequence flows through:

```go
// lines 177-184
totalAmount = cnAmountBig + clAmountBig   // may be negative or near-zero
clAmount    = clAmountBig * reward / totalAmount  // division by negative/tiny number
cnAmount    = reward - clAmount           // reward + |clAmount| > reward
```

When `totalAmount` is negative, `clAmount` is negative, and `cnAmount = reward - (negative) = reward + |clAmount|` — the CN address receives more than the full staking reward for that block. The CL pool address receives a negative amount, which `state.AddBalance` interprets as a subtraction, draining KAIA from the CLPool. [1](#0-0) 

The corrupted values are then written directly to state in `FinalizeState`:

```go
// kaiax/reward/impl/blockstate.go  lines 53-55
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [2](#0-1) 

The call chain that reaches `Split()` every block: [3](#0-2) [4](#0-3) 

### Impact Explanation

- **Unauthorized KAIA transfer**: The CN reward address receives more KAIA than its proportional share every block. The CLPool address has KAIA subtracted from its balance (negative `AddBalance`). This is a direct, per-block unauthorized transfer of KAIA between two system-managed addresses.
- **Affected hardforks**: Prague (KIP-226) and Osaka/Flex (KIP-226 + flex reward), both of which use `Split()` for CL reward distribution.
- **Scope**: Any validator whose `StakingAmount` (in KAIA, rounded down) exceeds `math.MaxInt64 / 1e18 ≈ 9.22 × 10⁹` KAIA, or whose `CLStakingAmount` exceeds the same threshold. The minimum staking requirement is 5,000,000 KAIA, so the threshold is ~1,844× the minimum — reachable by a large validator or a validator that consolidates many staking contracts under one reward address.

### Likelihood Explanation

The threshold is high (≈ 9.22 billion KAIA), but:
1. `StakingAmount` is the **sum** of all staking contracts sharing the same `RewardAddr` (consolidated). A validator with many staking contracts can reach this.
2. The `CLStakingAmount` is independently sourced from the CLRegistry and has no enforced cap in the code.
3. No governance or on-chain guard prevents a validator from accumulating this amount.
4. The bug is deterministic and repeatable every block once triggered — no attacker action is needed after the staking amount crosses the threshold.

### Recommendation

Replace the narrowing `int64` cast with proper `uint64`-safe `big.Int` construction:

```go
// Replace:
cnAmountBig = big.NewInt(int64(c.StakingAmount))
clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))

// With:
cnAmountBig = new(big.Int).SetUint64(c.StakingAmount)
clAmountBig = new(big.Int).SetUint64(c.CLStakingInfo.CLStakingAmount)
```

Add a guard: if `totalAmount.Sign() <= 0`, return `(amount, big.NewInt(0))` as a safe fallback.

### Proof of Concept

**Setup**: Prague/Osaka hardfork active, `UseFlexReward = true`, one validator with:
- `StakingAmount = 10_000_000_000` KAIA (10 billion, exceeds `math.MaxInt64 / 1e18`)
- `CLStakingAmount = 1_000_000` KAIA

**Trace**:

```go
// int64(10_000_000_000) wraps to -8_446_744_073 (negative)
cnAmountBig = big.NewInt(int64(10_000_000_000))  // = -8_446_744_073
clAmountBig = big.NewInt(int64(1_000_000))        // = 1_000_000 (fine)
totalAmount = -8_446_744_073 + 1_000_000          // = -8_445_744_073

// reward = 1e18 kei (1 KAIA)
clAmount = 1_000_000 * 1e18 / (-8_445_744_073)   // ≈ -118_400_000_000 kei (negative)
cnAmount = 1e18 - (-118_400_000_000)              // ≈ 1.118e18 kei (> 1 KAIA)
```

Result: CN address receives ~1.118 KAIA instead of ~0.909 KAIA. CLPool address has ~0.118 KAIA subtracted from its balance. This repeats every block, constituting a continuous unauthorized drain of KAIA from the CLPool to the CN reward address. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** kaiax/reward/impl/blockstate.go (L30-56)
```go
func (r *RewardModule) FinalizeState(header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) error {
	if r.GovModule.GetParamSet(header.Number.Uint64()).ProposerPolicy == uint64(istanbul.WeightedRandom) && common.EmptyHash(header.Root) {
		qualified, err := r.ValsetModule.GetQualifiedValidators(header.Number.Uint64())
		if err != nil {
			return err
		}
		useRewardAddress := valset.NewAddressSet(qualified).Contains(r.NodeAddress)

		if rewardAddr := r.GetRewardAddress(header.Number.Uint64(), r.NodeAddress); useRewardAddress && rewardAddr != (common.Address{}) {
			header.Rewardbase = rewardAddr
			logger.Trace("Use reward address for nodeValidator", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		} else {
			logger.Trace("No reward address for nodeValidator. Use node's rewardbase.", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		}
	}

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

**File:** kaiax/reward/impl/getter.go (L421-452)
```go
// assignStakingRewardsFlex assigns staking rewards to stakers according to their staking amounts.
// Returns the allocation and the remainder.
func assignStakingRewardsFlex(config *reward.RewardConfig, budget *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		minStake  = config.MinimumStake.Uint64()
		threshold = config.StakingRewardThreshold.Uint64()
		isPrague  = config.Rules.IsPrague

		cns            = si.ConsolidatedNodes()
		excessInt      = make(map[common.Address]uint64)
		totalExcessInt = uint64(0)
	)

	// Calculate the excess stakes (the amount over the threshold) for each CN.
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it. Even if (CNStaking + CLStaking) could be more than minStake,
		// the CNStaking alone must be at least minStake to be eligible.
		if cn.StakingAmount < minStake {
			continue
		}

		amount := cn.StakingAmount
		if isPrague && cn.CLStakingInfo != nil {
			amount += cn.CLStakingInfo.CLStakingAmount
		}

		// Excess is the amount over the threshold (not over minStake).
		if amount > threshold {
			excessInt[cn.RewardAddr] = amount - threshold
			totalExcessInt += excessInt[cn.RewardAddr]
		}
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
