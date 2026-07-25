### Title
Staking Reward `cnAmount` Silently Lost When `CLPoolAddr == RewardAddr` Due to Map Overwrite in `assignStakingRewards` / `assignStakingRewardsFlex` - (`File: kaiax/reward/impl/getter.go`)

---

### Summary

In the Prague/Osaka reward distribution path, both `assignStakingRewards` and `assignStakingRewardsFlex` use **direct map assignment** (`alloc[addr] = value`) when splitting a validator's staking reward between its AddressBook reward address (`cn.RewardAddr`) and its consensus-liquidity pool address (`cn.CLStakingInfo.CLPoolAddr`). If a validator registers the same address for both roles, the second assignment silently overwrites the first. The `remaining` counter is decremented by the full `reward` amount regardless, so the overwritten `cnAmount` is neither credited to any recipient nor returned to the proposer as a remainder — it is permanently lost from the block's reward distribution.

---

### Finding Description

In `assignStakingRewards` (and identically in `assignStakingRewardsFlex`), the Prague-era split path is:

```go
// kaiax/reward/impl/getter.go lines 521-525
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount                    // direct assignment
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount      // direct assignment — overwrites if same key
}
remaining.Sub(remaining, reward)                       // always subtracts full reward
```

`IncRecipient` (used everywhere else in the reward pipeline) accumulates with `+=`. Here, raw map assignment is used instead. When `cn.CLStakingInfo.CLPoolAddr == cn.RewardAddr`:

1. `alloc[addr] = cnAmount` — sets the entry.
2. `alloc[addr] = clAmount` — **overwrites** it; `cnAmount` is gone.
3. `remaining.Sub(remaining, reward)` — subtracts `cnAmount + clAmount` from `remaining`.

`remaining` is returned as `kip82Remainder` and added to the proposer:

```go
// kaiax/reward/impl/getter.go lines 352-354
stakersAlloc, kip82Remainder := assignStakingRewards(config, stakers, si)
proposer.Add(proposer, kip82Remainder)
stakers.Sub(stakers, kip82Remainder)
```

Because `remaining` was already decremented by the full `reward`, the proposer does **not** receive `cnAmount` as a remainder either. `cnAmount` is absent from both `alloc` and `remaining` — it is effectively burned.

The same overwrite pattern exists in `assignStakingRewardsFlex`:

```go
// kaiax/reward/impl/getter.go lines 474-477
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
}
```

No guard anywhere in the pipeline checks `cn.CLStakingInfo.CLPoolAddr != cn.RewardAddr`. Neither `consolidateNodes()`, `parseCallResult()`, nor `parsePermissionlessCallResult()` enforce this invariant. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Every block in which a validator has `CLPoolAddr == RewardAddr`, the `cnAmount` fraction of that validator's staking reward is permanently unallocated. It is subtracted from `remaining` (so the proposer does not receive it as a remainder) and is not present in `alloc` (so it is not credited to any address in `FinalizeState`). The net effect is that `cnAmount` kei of KAIA is silently burned each block, violating the invariant that `Minted + TotalFee - BurntFee == sum(Rewards)`. The `sanityCheckRewardSpec` test enforces this invariant but is only exercised in unit tests with well-separated addresses. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The trigger requires a validator to register the same address as both their AddressBook `RewardAddr` and their CLRegistry `CLPoolAddr`. This is a valid semi-trusted operation: validators control both registrations independently, and no cross-contract validation prevents it. It can occur accidentally (operator reuse of a single hot wallet address) or deliberately. The condition is persistent — once configured, every block produces the loss until the validator reconfigures. [7](#0-6) [8](#0-7) 

---

### Recommendation

Replace direct map assignment with accumulating assignment (matching `IncRecipient` semantics) in both `assignStakingRewards` and `assignStakingRewardsFlex`:

```go
// Before (both functions):
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount

// After:
if _, ok := alloc[cn.RewardAddr]; !ok {
    alloc[cn.RewardAddr] = new(big.Int)
}
alloc[cn.RewardAddr].Add(alloc[cn.RewardAddr], cnAmount)

if _, ok := alloc[cn.CLStakingInfo.CLPoolAddr]; !ok {
    alloc[cn.CLStakingInfo.CLPoolAddr] = new(big.Int)
}
alloc[cn.CLStakingInfo.CLPoolAddr].Add(alloc[cn.CLStakingInfo.CLPoolAddr], clAmount)
```

Alternatively, add an explicit guard in `consolidateNodes()` or `parseCallResult()` / `parsePermissionlessCallResult()` that rejects or logs a warning when `CLPoolAddr == RewardAddr`. [9](#0-8) [10](#0-9) 

---

### Proof of Concept

Configure a `StakingInfo` where one validator has `CLPoolAddr == RewardAddr`:

```go
si := &staking.StakingInfo{
    NodeIds:          []common.Address{common.HexToAddress("0xa01")},
    StakingContracts: []common.Address{common.HexToAddress("0xb01")},
    RewardAddrs:      []common.Address{common.HexToAddress("0xc01")},
    StakingAmounts:   []uint64{6_000_000},
    KIFAddr:          common.HexToAddress("0xd01"),
    KEFAddr:          common.HexToAddress("0xd02"),
    CLStakingInfos: staking.CLStakingInfos{
        {
            CLNodeId:        common.HexToAddress("0xa01"),
            CLPoolAddr:      common.HexToAddress("0xc01"), // same as RewardAddr
            CLStakingAmount: 1_000_000,
        },
    },
}
config := &reward.RewardConfig{
    MinimumStake: big.NewInt(5_000_000),
    Rules:        params.Rules{IsPrague: true},
}
stakersReward := big.NewInt(1e18)
alloc, remainder := assignStakingRewards(config, stakersReward, si)
// Expected: alloc[0xc01] = 1e18, remainder = 0
// Actual:   alloc[0xc01] = clAmount (< 1e18), remainder = 0
// cnAmount is lost; sum(alloc) + remainder < stakersReward
```

`cn.Split(reward)` returns `cnAmount = reward * CNStaking / (CNStaking + CLStaking)` and `clAmount = reward - cnAmount`. With the overwrite, only `clAmount` is credited. `cnAmount` (~833 milliKAIA per 1 KAIA stakers reward in this example) is permanently unallocated each block. [11](#0-10) [12](#0-11)

### Citations

**File:** kaiax/reward/impl/getter.go (L352-354)
```go
	stakersAlloc, kip82Remainder := assignStakingRewards(config, stakers, si)
	proposer.Add(proposer, kip82Remainder)
	stakers.Sub(stakers, kip82Remainder)
```

**File:** kaiax/reward/impl/getter.go (L473-482)
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
	}
```

**File:** kaiax/reward/impl/getter.go (L514-533)
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
	}
	return alloc, remaining
```

**File:** kaiax/reward/spec.go (L110-116)
```go
func (spec *RewardSpec) IncRecipient(addr common.Address, amount *big.Int) {
	_, ok := spec.Rewards[addr]
	if !ok {
		spec.Rewards[addr] = big.NewInt(0)
	}
	spec.Rewards[addr].Add(spec.Rewards[addr], amount)
}
```

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```

**File:** kaiax/reward/impl/getter_test.go (L1436-1443)
```go
	sumRewards := new(big.Int)
	for _, amount := range spec.Rewards {
		sumRewards.Add(sumRewards, amount)
		assert.True(t, amount.Sign() >= 0, msg)
	}

	assert.Equal(t, sumSummary, sumParts, msg)
	assert.Equal(t, sumSummary, sumRewards, msg)
```

**File:** kaiax/staking/staking_info.go (L38-51)
```go
	NodeIds          []common.Address `json:"councilNodeAddrs"`
	StakingContracts []common.Address `json:"councilStakingAddrs"`
	RewardAddrs      []common.Address `json:"councilRewardAddrs"`

	// Treasury fund addresses
	KEFAddr common.Address `json:"kefAddr"` // KEF contract address (or KCF, KIR)
	KIFAddr common.Address `json:"kifAddr"` // KIF contract address (or KFF, KGF, PoC)
	KPFAddr common.Address `json:"kpfAddr"` // KPF contract address

	// Staking amounts of each staking contracts, in KAIA, rounded down. Does not include CL staking amounts.
	StakingAmounts []uint64 `json:"councilStakingAmounts"`

	// Staking info from the consensus liquidity since Prague HF.
	CLStakingInfos CLStakingInfos `json:"clStakingInfos"`
```

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
