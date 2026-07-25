### Title
Silent CL Pool Reward Overwrite in Multi-NodeId Consolidation Causes Zero Rewards for Overwritten CL Pool — (`kaiax/staking/staking_info.go`)

---

### Summary

When a validator registers multiple NodeIds in AddressBook sharing the same `RewardAddr`, and each of those NodeIds has a separate CL pool registered in CLRegistry, `consolidateNodes()` silently overwrites the first CL pool's `CLStakingInfo` with the last one encountered. The downstream `Split()` call distributes rewards to only the surviving CL pool; the overwritten CL pool receives zero KAIA block rewards.

---

### Finding Description

In `consolidateNodes()`, the CL attachment loop is:

```go
for _, clsi := range si.CLStakingInfos {
    if r, ok := nToR[clsi.CLNodeId]; ok {
        // One CLStakingInfo per validator is guaranteed by CLRegistry.
        cmap[r].CLStakingInfo = clsi   // ← unconditional overwrite
    }
}
``` [1](#0-0) 

The comment "One CLStakingInfo per validator is guaranteed by CLRegistry" is correct at the NodeId level — CLRegistry maps one CL pool per NodeId. However, the consolidation logic treats multiple NodeIds that share the same `RewardAddr` as a single "validator". If NodeId N1 and NodeId N3 both map to `RewardAddr` R1 in AddressBook, and both have CL pools registered in CLRegistry, the second iteration of the loop overwrites `cmap[R1].CLStakingInfo` with the second CL pool, silently discarding the first.

The test suite explicitly documents this behavior:

```go
// CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)
{CLNodeId: n3, CLPoolAddr: clPool2, CLStakingAmount: clStakingAmount2},
``` [2](#0-1) 

The resulting `consolidatedNode` carries only one `CLStakingInfo`. The `Split()` function then divides the block reward between the CN's `RewardAddr` and that single surviving CL pool:

```go
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
    cnAmountBig = big.NewInt(int64(c.StakingAmount))
    clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount))
    ...
    return cnAmount, clAmount   // only one CL pool receives clAmount
}
``` [3](#0-2) 

The overwritten CL pool address is never added to `alloc` in `assignStakingRewards()`:

```go
cnAmount, clAmount := cn.Split(reward)
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount   // only surviving pool
``` [4](#0-3) 

The same pattern applies in `assignStakingRewardsFlex()` and both `specWithProposerAndFunds*()` functions for the proposer's CL split. [5](#0-4) 

Furthermore, `cnTotalStakingAmount` in `assignStakingRewards()` is computed as `cn.StakingAmount + cn.CLStakingInfo.CLStakingAmount`, which omits the overwritten CL pool's staking amount from the total excess calculation, causing the reward share of the entire consolidated node to be understated:

```go
cnTotalStakingAmount := cn.StakingAmount
if isPrague && cn.CLStakingInfo != nil {
    cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount
}
``` [6](#0-5) 

These functions are called from `FinalizeState()` on every block, making this a live production reward distribution path: [7](#0-6) 

---

### Impact Explanation

A CL pool whose `CLStakingInfo` is overwritten during consolidation receives **zero KAIA block rewards** for every block while the condition persists, regardless of how much KAIA is staked in it. The rewards that should have gone to the overwritten CL pool are instead split between the CN's `RewardAddr` and the surviving CL pool. This is a direct, per-block loss of KAIA rewards for the overwritten CL pool's stakers.

---

### Likelihood Explanation

The preconditions are:

1. **Prague hardfork active** — already planned/active on mainnet.
2. **Validator registers multiple NodeIds with the same `RewardAddr` in AddressBook** — explicitly supported by the protocol; `consolidateNodes()` exists precisely to handle this case.
3. **Multiple of those NodeIds have CL pools registered in CLRegistry** — CLRegistry maps per NodeId, so this is independently possible for each NodeId.

Neither condition is prevented by any contract-level guard. The AddressBook does not restrict how many NodeIds share a `RewardAddr`, and CLRegistry does not check whether a NodeId's `RewardAddr` is already associated with another CL pool. The combination is therefore reachable by any validator operator who legitimately uses both features.

---

### Recommendation

In `consolidateNodes()`, instead of storing a single `*CLStakingInfo`, accumulate all CL pools for a consolidated node into a slice. Update `Split()` and `assignStakingRewards()`/`assignStakingRewardsFlex()` to iterate over all CL pools and distribute rewards proportionally to each:

```go
// In consolidatedNode:
CLStakingInfos []*CLStakingInfo  // replace single pointer

// In consolidateNodes():
cmap[r].CLStakingInfos = append(cmap[r].CLStakingInfos, clsi)

// In Split() / assignStakingRewards():
// Sum all CL staking amounts, then distribute proportionally to each CL pool.
```

Alternatively, if the protocol intends to support at most one CL pool per consolidated validator, enforce this invariant explicitly at the CLRegistry contract level by checking whether any NodeId sharing the same `RewardAddr` already has a registered CL pool, and revert if so.

---

### Proof of Concept

Given Prague hardfork active and `StakingInterval` irrelevant (post-Kaia HF, `sourceNum = num - 1`):

**Setup in AddressBook:**
- NodeId N1 → StakingContract S1, RewardAddr R1, StakingAmount 6,000,000 KAIA
- NodeId N3 → StakingContract S3, RewardAddr R1, StakingAmount 4,000,000 KAIA (same RewardAddr)

**Setup in CLRegistry:**
- N1 → CLPool CL1, CLStakingAmount 2,000,000 KAIA
- N3 → CLPool CL3, CLStakingAmount 3,000,000 KAIA

**Expected reward split** (total CN staking = 10M, total CL = 5M, total = 15M):
- R1 receives: reward × 10/15
- CL1 receives: reward × 2/15
- CL3 receives: reward × 3/15

**Actual behavior** after `consolidateNodes()` overwrites CL1 with CL3:
- `cn.StakingAmount` = 10M, `cn.CLStakingInfo` = CL3 (2M overwritten, 3M kept)
- `cnTotalStakingAmount` = 10M + 3M = 13M (CL1's 2M excluded from excess)
- `Split(reward)` → R1 gets reward × 10/13, CL3 gets reward × 3/13
- **CL1 receives 0 KAIA**

The existing test at `kaiax/staking/staking_info_test.go:243-271` already demonstrates the overwrite behavior, confirming the root cause is present in the production code path. [8](#0-7)

### Citations

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

**File:** kaiax/reward/impl/getter.go (L499-503)
```go
			// Calculate total staking amount once
			cnTotalStakingAmount := cn.StakingAmount
			if isPrague && cn.CLStakingInfo != nil {
				cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount
			}
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

**File:** kaiax/reward/impl/blockstate.go (L46-56)
```go
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
