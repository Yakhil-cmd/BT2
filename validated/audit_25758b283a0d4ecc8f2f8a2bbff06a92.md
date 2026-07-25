### Title
Silent Overwrite of Multiple CLStakingInfos Per Consolidated Validator Causes Incorrect KAIA Staking Reward Distribution — (`kaiax/staking/staking_info.go`)

### Summary

In `consolidateNodes()`, when a validator registers multiple NodeIds in AddressBook (a supported and explicitly documented feature) and each NodeId has a corresponding `CLStakingInfo` entry in CLRegistry, the consolidation loop silently overwrites all but the last CL entry for that validator. The dropped CL pool addresses never receive staking rewards, and the CN/CL reward split ratio is computed using only the surviving CL's staking amount, producing incorrect KAIA distribution every block.

### Finding Description

`StakingInfo.consolidateNodes()` first consolidates AddressBook entries by `RewardAddr`, correctly summing all `StakingAmounts` from multiple NodeIds into one `consolidatedNode`. It then iterates over `CLStakingInfos` and assigns each to the matching consolidated node:

```go
// One CLStakingInfo per validator is guaranteed by CLRegistry.
cmap[r].CLStakingInfo = clsi   // line 157 — plain assignment, not accumulation
``` [1](#0-0) 

This is a plain assignment. If two NodeIds (N1, N2) share the same `RewardAddr` (R1) — which is the entire purpose of the consolidation feature — and both are registered in CLRegistry, the loop processes both `CLStakingInfo` entries but the second silently overwrites the first. The first CL pool address and its staking amount are permanently lost from the consolidated node.

The test suite explicitly documents this behaviour:

```go
// CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)
``` [2](#0-1) 

The expected result confirms only the second CL survives; the first is silently dropped.

Downstream, `assignStakingRewards` and `assignStakingRewardsFlex` call `cn.Split(reward)` which uses only the surviving `CLStakingInfo`:

```go
cnAmount, clAmount := cn.Split(reward)
alloc[cn.RewardAddr] = cnAmount
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
``` [3](#0-2) 

`Split` computes the CL share as `clStakingAmount / (cnStakingAmount + clStakingAmount)`:

```go
clAmount := new(big.Int).Mul(clAmountBig, amount)
clAmount = clAmount.Div(clAmount, totalAmount)
cnAmount := big.NewInt(0).Sub(amount, clAmount)
``` [4](#0-3) 

With the first CL dropped, `totalAmount` is understated, the split ratio is wrong, and the dropped CL pool address receives zero KAIA instead of its proportional share.

The same overwrite affects the proposer reward path in `specWithProposerAndFundsFlex`: [5](#0-4) 

### Impact Explanation

Every block after the Prague hardfork, `FinalizeState` calls `GetDeferredReward` → `assignStakingRewards` → `cn.Split`. For any validator whose consolidated node has had a CL entry overwritten:

- The dropped CL pool address receives **zero** staking rewards instead of its proportional share.
- The CN reward address receives **more** than its correct share (the split denominator is too small).
- The error compounds every block for the lifetime of the misconfigured staking state.

This is an unauthorized redistribution of KAIA staking rewards — funds that should flow to a CL pool are silently redirected to the CN reward address.

### Likelihood Explanation

The trigger requires a validator to hold multiple NodeIds in AddressBook (explicitly supported — the consolidation feature exists precisely for this) and to register each NodeId in CLRegistry. The comment "One CLStakingInfo per validator is guaranteed by CLRegistry" is an unverified assumption in the Go code; CLRegistry enforces uniqueness per NodeId, not per RewardAddr. A GC operator with two NodeIds (N1, N2) sharing one RewardAddr who registers both in CLRegistry will silently trigger this bug. The test suite acknowledges the scenario exists but dismisses it as "not feasible in real" without any on-chain enforcement.

### Recommendation

Replace the plain assignment with accumulation. Since `consolidatedNode.CLStakingInfo` is a single pointer, the struct must be extended to hold a slice of CL entries, or the staking amounts must be summed and pool addresses tracked as a list:

```go
// Instead of:
cmap[r].CLStakingInfo = clsi

// Accumulate:
if cmap[r].CLStakingInfo == nil {
    cmap[r].CLStakingInfo = clsi
} else {
    cmap[r].CLStakingInfo.CLStakingAmount += clsi.CLStakingAmount
    // track additional pool addresses for reward distribution
}
```

Alternatively, add an explicit guard that returns an error if two CLStakingInfos map to the same RewardAddr, making the invariant enforced in Go rather than assumed from CLRegistry.

### Proof of Concept

Given:
- AddressBook: `NodeIds=[N1,N2]`, `RewardAddrs=[R1,R1]`, `StakingAmounts=[5M,5M]`
- CLRegistry: `N1→(Pool1, 2M KAIA)`, `N2→(Pool2, 3M KAIA)`

After `consolidateNodes()`:
- `consolidatedNode{RewardAddr:R1, StakingAmount:10M, CLStakingInfo:{N2,Pool2,3M}}`
- Pool1 and its 2M KAIA CL stake are silently dropped.

In `assignStakingRewards`, `cn.Split(reward)`:
- `totalAmount = 10M + 3M = 13M` (should be `10M + 2M + 3M = 15M`)
- `clAmount = reward * 3M / 13M` (should be `reward * 5M / 15M`)
- Pool1 receives 0 KAIA; Pool2 receives less than its correct share; R1 receives the surplus. [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** kaiax/staking/staking_info.go (L124-167)
```go
func (si *StakingInfo) consolidateNodes() *[]consolidatedNode {
	// because Go map is not ordered, rList keeps track of the occurrence order of RewardAddrs.
	// to later arrange the consolidatedNodes.
	cmap := make(map[common.Address]*consolidatedNode)
	rList := make([]common.Address, 0, len(si.RewardAddrs))
	nToR := make(map[common.Address]common.Address)

	for i, n := range si.NodeIds {
		r := si.RewardAddrs[i]
		// Unique nodeId is guaranteed by AddressBook.
		nToR[n] = r
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

	carr := make([]consolidatedNode, 0, len(cmap))
	for _, r := range rList {
		carr = append(carr, *cmap[r])
	}
	return &carr
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

**File:** kaiax/reward/impl/getter.go (L486-534)
```go
// assignStakingRewards assigns staking rewards to stakers according to their staking amounts.
// Returns the allocation and the remainder.
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
}
```

**File:** kaiax/reward/impl/getter.go (L572-591)
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

	newSpec.IncRecipient(config.Rewardbase, proposer)
	return newSpec
```
