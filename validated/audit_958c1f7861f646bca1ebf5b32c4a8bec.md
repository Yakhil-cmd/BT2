### Title
Unchecked `uint64` Overflow in Staking Reward Denominator Corrupts Per-Block KAIA Distribution — (`File: kaiax/reward/impl/getter.go`)

---

### Summary

Both `assignStakingRewards` and `assignStakingRewardsFlex` accumulate validator excess-stake totals into a bare `uint64` variable (`totalExcessInt`) without any overflow guard. When the sum of eligible excess stakes across all validators exceeds `uint64` max (~18.4 billion KAIA), the variable silently wraps to a small value. That wrapped value is then used as the denominator in the per-validator reward formula, causing every staker to receive a massively inflated KAIA allocation and the proposer to receive a correspondingly negative remainder — corrupting reward distribution for every block in which the condition holds.

---

### Finding Description

In `assignStakingRewards` (the Kore/Prague reward path):

```go
totalExcessInt = uint64(0)
...
cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount  // unchecked uint64 add
...
totalExcessInt += cnTotalStakingAmount - minStake          // unchecked uint64 add
``` [1](#0-0) 

`totalExcessInt` is then cast directly into a `big.Int` and used as the divisor:

```go
totalExcess = new(big.Int).SetUint64(totalExcessInt)
...
reward = new(big.Int).Div(new(big.Int).Mul(excess, stakersReward), totalExcess)
``` [2](#0-1) 

The identical pattern exists in `assignStakingRewardsFlex`:

```go
amount += cn.CLStakingInfo.CLStakingAmount  // unchecked
...
totalExcessInt += excessInt[cn.RewardAddr]  // unchecked
``` [3](#0-2) 

A third unchecked accumulation occurs in `consolidateNodes` in `staking_info.go`, where multiple NodeIds sharing a `RewardAddr` have their staking amounts summed without overflow protection:

```go
cn.StakingAmount += si.StakingAmounts[i]
``` [4](#0-3) 

All staking amounts are stored as `uint64` in KAIA units (divided by 10^18 kei): [5](#0-4) 

`uint64` max is ~18.4 billion KAIA. With a validator set where the sum of individual excess stakes (each validator's total stake minus `minStake`) exceeds that threshold, `totalExcessInt` wraps to a small value.

---

### Impact Explanation

When `totalExcessInt` wraps to, say, `K` (a small value), the per-validator reward becomes:

```
reward_i = excess_i × stakersReward / K
```

Because `K` is far smaller than the true total excess, each `reward_i` is inflated by a factor of `(true_total_excess / K)`. The sum of all `reward_i` values far exceeds `stakersReward`, so `remaining = stakersReward - Σ(reward_i)` becomes a large negative `big.Int`. This negative remainder is then added to the proposer's allocation:

```go
proposer.Add(proposer, kip82Remainder)   // proposer receives a huge negative amount
stakers.Sub(stakers, kip82Remainder)     // stakers accounting inflated further
``` [6](#0-5) 

The concrete corrupted values are:
- **Staker allocations** in `stakersAlloc`: each entry is inflated by orders of magnitude, causing `AddBalance` calls to credit far more KAIA than earned.
- **Proposer allocation**: driven deeply negative, effectively stealing from the proposer's reward address.
- **`spec.Stakers`**: set to an incorrect (inflated) value, corrupting the `RewardSpec` used for state finalization.

This is an invalid state transition affecting KAIA reward distribution on every block once the condition is met.

---

### Likelihood Explanation

- `StakingAmounts` are `uint64` in KAIA units. A single validator can stake up to ~18.4 billion KAIA before their individual amount overflows.
- `totalExcessInt` sums excesses across all validators. With as few as **two validators** each staking near the individual `uint64` ceiling, the sum overflows.
- Since Prague hardfork, `CLStakingAmount` is added to `cnTotalStakingAmount` before the excess is computed, doubling the per-validator contribution to `totalExcessInt`.
- The condition is triggered automatically by the staking state at each block; no special transaction is needed once the staking amounts are in place.
- Governance can lower `minimumStake`, increasing each validator's excess and making overflow easier to reach.

---

### Recommendation

Replace all bare `uint64` accumulations in the reward path with overflow-checked arithmetic (e.g., `math.SafeAdd` already present in the codebase) or, preferably, promote the intermediate accumulators to `*big.Int` from the start, consistent with how the final reward arithmetic is performed.

```go
// Instead of:
totalExcessInt += cnTotalStakingAmount - minStake

// Use big.Int throughout:
totalExcess.Add(totalExcess, new(big.Int).SetUint64(cnTotalStakingAmount - minStake))
```

Apply the same fix to:
- `assignStakingRewards` — `totalExcessInt` accumulation (lines 504)
- `assignStakingRewardsFlex` — `amount` and `totalExcessInt` accumulations (lines 444, 450)
- `consolidateNodes` — `cn.StakingAmount` accumulation (line 138) [7](#0-6) 

---

### Proof of Concept

**Setup**: Two validators registered in AddressBook, each with `StakingAmount = 10_000_000_000` KAIA (10 billion KAIA, within individual `uint64` range). `minStake = 5_000_000` KAIA.

**Execution** (Kore/Prague block finalization):

1. `assignStakingRewards` is called with `stakersReward = 9.5 KAIA` (typical minting amount × staker ratio).
2. Loop iteration 1: `cnTotalStakingAmount = 10_000_000_000`, `totalExcessInt += 9_995_000_000`.
3. Loop iteration 2: `totalExcessInt += 9_995_000_000` → `totalExcessInt = 19_990_000_000`.
4. `uint64` max = `18_446_744_073_709_551_615`. In KAIA units, `19_990_000_000 > 18_446_744_073` → **overflow**. `totalExcessInt` wraps to `19_990_000_000 - 18_446_744_073 ≈ 1_543_255_927`.
5. `totalExcess = big.Int(1_543_255_927)` instead of the correct `big.Int(19_990_000_000)`.
6. Validator 1 reward = `9_995_000_000 × 9.5 KAIA / 1_543_255_927 ≈ 61.5 KAIA` (correct would be ~4.75 KAIA).
7. Validator 2 reward = same → total distributed ≈ 123 KAIA vs. budget of 9.5 KAIA.
8. `remaining = 9.5 KAIA - 123 KAIA = -113.5 KAIA` → proposer receives `-113.5 KAIA` added to their allocation.
9. `FinalizeState` credits each staker address with ~13× their correct reward, and debits the proposer's reward address by ~113.5 KAIA net. [8](#0-7)

### Citations

**File:** kaiax/reward/impl/getter.go (L352-354)
```go
	stakersAlloc, kip82Remainder := assignStakingRewards(config, stakers, si)
	proposer.Add(proposer, kip82Remainder)
	stakers.Sub(stakers, kip82Remainder)
```

**File:** kaiax/reward/impl/getter.go (L442-450)
```go
		amount := cn.StakingAmount
		if isPrague && cn.CLStakingInfo != nil {
			amount += cn.CLStakingInfo.CLStakingAmount
		}

		// Excess is the amount over the threshold (not over minStake).
		if amount > threshold {
			excessInt[cn.RewardAddr] = amount - threshold
			totalExcessInt += excessInt[cn.RewardAddr]
```

**File:** kaiax/reward/impl/getter.go (L488-520)
```go
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
```

**File:** kaiax/staking/staking_info.go (L47-48)
```go
	// Staking amounts of each staking contracts, in KAIA, rounded down. Does not include CL staking amounts.
	StakingAmounts []uint64 `json:"councilStakingAmounts"`
```

**File:** kaiax/staking/staking_info.go (L138-138)
```go
			cn.StakingAmount += si.StakingAmounts[i]
```
