### Title
Silent CLStakingInfo Overwrite in `consolidateNodes` Causes Incorrect KAIA Reward Distribution — (`kaiax/staking/staking_info.go`)

---

### Summary

`consolidateNodes()` in `kaiax/staking/staking_info.go` silently overwrites the first `CLStakingInfo` entry when two NodeIds sharing the same `RewardAddr` each have a registered CL pool. The `consolidatedNode` struct holds only a single `*CLStakingInfo` pointer; the second CL entry unconditionally replaces the first. All downstream reward-distribution functions (`assignStakingRewards`, `assignStakingRewardsFlex`, `specWithProposerAndFundsFlex`) then compute the wrong split ratio and send the first CL pool's entire KAIA reward allocation to zero.

---

### Finding Description

`StakingInfo.consolidateNodes()` merges AddressBook entries that share a `RewardAddr` into a single `consolidatedNode`, correctly summing their `StakingAmount` values. It then attaches CL staking data from `CLStakingInfos`:

```go
// kaiax/staking/staking_info.go  lines 151-159
if len(si.CLStakingInfos) > 0 {
    for _, clsi := range si.CLStakingInfos {
        if r, ok := nToR[clsi.CLNodeId]; ok {
            // One CLStakingInfo per validator is guaranteed by CLRegistry.
            cmap[r].CLStakingInfo = clsi   // ← unconditional overwrite
        }
    }
}
``` [1](#0-0) 

The comment's invariant ("one CLStakingInfo per validator") is scoped to *NodeId*, not to *RewardAddr*. The AddressBook explicitly supports multiple NodeIds per validator sharing one RewardAddr (the consolidation feature). If NodeIds N1 and N3 both map to RewardAddr R1, and both are independently registered in the CLRegistry with distinct CL pools (clPool1, clPool2), then `CLStakingInfos` will contain two entries — one for N1 and one for N3. The loop processes them sequentially:

1. Iteration 1: `cmap[R1].CLStakingInfo = clsi_for_N1` (clPool1, amount1)
2. Iteration 2: `cmap[R1].CLStakingInfo = clsi_for_N3` (clPool2, amount2) — **overwrites**

clPool1's entry is permanently lost. The `consolidatedNode` for R1 now carries only `clStakingAmount2`, even though `StakingAmount` correctly sums A1+A3.

The existing test case explicitly documents this behavior and dismisses it as "not feasible in real":

```go
// kaiax/staking/staking_info_test.go  line 258
// CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)
``` [2](#0-1) 

That assumption is not enforced by any on-chain or off-chain guard.

---

### Impact Explanation

Every reward-distribution function that calls `ConsolidatedNodes()` is affected:

**`assignStakingRewards` / `assignStakingRewardsFlex`** — both compute the total staking amount as `cn.StakingAmount + cn.CLStakingInfo.CLStakingAmount`. With only one CL amount instead of the correct sum, the excess-stake denominator is understated, inflating every other validator's share. The split itself (`cn.Split(reward)`) then sends the entire CL portion to clPool2 only; clPool1 receives zero:

```go
// kaiax/reward/impl/getter.go  lines 521-525
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount  // only clPool2 credited
}
``` [3](#0-2) 

**`Split()`** uses only the surviving CL's amount in the ratio:

```go
// kaiax/staking/staking_info.go  lines 174-184
cnAmountBig = big.NewInt(int64(c.StakingAmount))          // A1+A3 (correct)
clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount)) // only amount2 (wrong)
totalAmount = cnAmountBig + clAmountBig                   // missing amount1
``` [4](#0-3) 

Concrete result per affected block:
- clPool1 receives **0 KAIA** instead of its proportional share.
- clPool2 and the CN reward address receive **inflated KAIA** because the denominator is too small.
- The total distributed amount is unchanged (no tokens are created or destroyed), but the allocation is wrong every block for as long as the configuration persists.

---

### Likelihood Explanation

The trigger requires a validator to:
1. Register two or more NodeIds in AddressBook under the same `RewardAddr` — explicitly supported and documented as the consolidation feature.
2. Register each of those NodeIds in the CLRegistry with a distinct CL pool — a valid, independent operation.

Neither step requires privileged access beyond being a registered validator. The CLRegistry enforces uniqueness per NodeId, not per RewardAddr, so both registrations succeed without error. The bug then fires silently on every block processed after the Prague hardfork for that validator.

---

### Recommendation

Replace the single `*CLStakingInfo` field in `consolidatedNode` with a slice, and accumulate all CL entries that resolve to the same `RewardAddr`:

```go
// In consolidatedNode struct
CLStakingInfos []*CLStakingInfo  // was: CLStakingInfo *CLStakingInfo

// In consolidateNodes loop
if r, ok := nToR[clsi.CLNodeId]; ok {
    cmap[r].CLStakingInfos = append(cmap[r].CLStakingInfos, clsi)
}
```

Update `Split()` to sum all CL amounts and distribute proportionally to each CL pool address. Update `assignStakingRewards`, `assignStakingRewardsFlex`, and `specWithProposerAndFundsFlex` accordingly.

Alternatively, add an on-chain guard in the CLRegistry that rejects registration of a NodeId whose RewardAddr already has a registered CL pool.

---

### Proof of Concept

The existing test case in `kaiax/staking/staking_info_test.go` already demonstrates the overwrite:

```
NodeIds:     [N1, N2, N3, N4]
RewardAddrs: [R1, R2, R1, R2]   // N1 and N3 share R1
CLStakingInfos: [
  {CLNodeId: N1, CLPoolAddr: clPool1, CLStakingAmount: amount1},
  {CLNodeId: N3, CLPoolAddr: clPool2, CLStakingAmount: amount2},
]

Expected (current, buggy) consolidated node for R1:
  StakingAmount = A1+A3          (correct)
  CLStakingInfo = {N3, clPool2, amount2}   // clPool1 silently dropped
``` [5](#0-4) 

To trigger the reward impact:
1. Deploy AddressBook with N1→R1 and N3→R1 (same RewardAddr, both `ValActive`).
2. Register N1→clPool1 and N3→clPool2 in CLRegistry.
3. Advance past the Prague hardfork.
4. Call `kaia_getReward` for any block: clPool1 will show 0 reward; clPool2 and R1 will show inflated amounts.

The root cause is at `kaiax/staking/staking_info.go` line 157 (`cmap[r].CLStakingInfo = clsi`) and the single-pointer `CLStakingInfo` field in the `consolidatedNode` struct at line 92. [6](#0-5) [7](#0-6)

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

**File:** kaiax/staking/staking_info.go (L151-159)
```go
	if len(si.CLStakingInfos) > 0 {
		for _, clsi := range si.CLStakingInfos {
			// If the nodeId of CLStakingInfo is not found in nToR, it means the validator is not in the AddressBook.
			// So we skip it.
			if r, ok := nToR[clsi.CLNodeId]; ok {
				// One CLStakingInfo per validator is guaranteed by CLRegistry.
				cmap[r].CLStakingInfo = clsi
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

**File:** kaiax/staking/staking_info_test.go (L243-271)
```go
		"4 nodes consolidated to 2 nodes and one node has two CLs": {
			stakingInfo: &StakingInfo{
				SourceBlockNum:   3 * 86400,
				NodeIds:          []common.Address{n1, n2, n3, n4},
				StakingContracts: []common.Address{s1, s2, s3, s4},
				RewardAddrs:      []common.Address{r1, r2, r1, r2},
				KEFAddr:          kef,
				KIFAddr:          kif,
				StakingAmounts:   []uint64{a1, a2, a3, a4},
				CLStakingInfos: CLStakingInfos{
					{
						CLNodeId:        n1,
						CLPoolAddr:      clPool1,
						CLStakingAmount: clStakingAmount1,
					},
					// CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)
					{
						CLNodeId:        n3,
						CLPoolAddr:      clPool2,
						CLStakingAmount: clStakingAmount2,
					},
				},
			},
			expectedConsolidated: []consolidatedNode{
				{[]common.Address{n1, n3}, []common.Address{s1, s3}, r1, a1 + a3, &CLStakingInfo{n3, clPool2, clStakingAmount2}},
				{[]common.Address{n2, n4}, []common.Address{s2, s4}, r2, a2 + a4, nil},
			},
			expectedGini: 0.15,
		},
```

**File:** kaiax/reward/impl/getter.go (L521-525)
```go
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
```
