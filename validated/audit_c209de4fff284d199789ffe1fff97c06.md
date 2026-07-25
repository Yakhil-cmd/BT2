### Title
Silent CL Staking Amount Overwrite Causes First Consensus-Liquidity Pool to Receive Zero Block Reward — (`kaiax/staking/staking_info.go`)

### Summary

When two AddressBook node IDs share the same reward address and both have a `CLStakingInfo` registered in CLRegistry, `consolidateNodes()` silently overwrites the first CL entry with the second. The first CL pool's staking amount is permanently lost from the consolidated node, causing `Split()` to compute an incorrect CN/CL split ratio and the first CL pool to receive zero KAIA every block.

### Finding Description

`consolidateNodes()` builds a `cmap` keyed by reward address. After summing AddressBook staking amounts, it iterates `si.CLStakingInfos` and maps each CL's node ID back to its reward address via `nToR`, then assigns:

```go
cmap[r].CLStakingInfo = clsi   // line 157 — plain assignment, not accumulation
``` [1](#0-0) 

If two node IDs `N1` and `N3` both resolve to the same reward address `R1` (a documented, valid AddressBook feature), and both have CLs registered, the loop processes `CL(N1)` first, then `CL(N3)` overwrites it. The resulting `consolidatedNode` for `R1` holds:

- `StakingAmount` = `A(N1) + A(N3)` — correct (summed in the first loop)
- `CLStakingInfo` = only `CL(N3)` — incorrect; `CL(N1)` is silently dropped [2](#0-1) 

The test suite even documents this behavior with the comment *"CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)"*, treating it as an acknowledged edge case rather than a guarded invariant. [3](#0-2) 

### Impact Explanation

`Split(reward)` is called inside both `assignStakingRewards` and `assignStakingRewardsFlex` to divide each validator's staking reward between the CN reward address and its CL pool:

```go
cnAmountBig = big.NewInt(int64(c.StakingAmount))          // A(N1)+A(N3)
clAmountBig = big.NewInt(int64(c.CLStakingInfo.CLStakingAmount)) // only CL(N3)
totalAmount = cnAmountBig + clAmountBig                   // missing CL(N1)
``` [4](#0-3) 

Correct denominator: `A(N1)+A(N3)+CL(N1)+CL(N3)`.  
Actual denominator: `A(N1)+A(N3)+CL(N3)`.

Consequences per block:
- **CL pool of N1** (`clPool1`) receives **0 KAIA** instead of `reward × CL(N1) / (A(N1)+A(N3)+CL(N1)+CL(N3))`.
- **CN reward address R1** receives `reward × (A(N1)+A(N3)) / (A(N1)+A(N3)+CL(N3))` — inflated.
- **CL pool of N3** (`clPool2`) receives `reward × CL(N3) / (A(N1)+A(N3)+CL(N3))` — inflated.

This incorrect distribution is applied in `FinalizeState` via `state.AddBalance`, making it a permanent, per-block KAIA misallocation. [5](#0-4) [6](#0-5) 

### Likelihood Explanation

The trigger requires two conditions that are individually valid and documented:

1. A validator registers two node IDs (`N1`, `N3`) with the **same reward address** in AddressBook — explicitly supported by `consolidateNodes()` design.
2. Both `N1` and `N3` register CLs in CLRegistry — each node ID may independently register a CL.

There is no on-chain constraint in CLRegistry that prevents two node IDs sharing a reward address from each having a CL. The developer comment "not feasible in real" is an assumption, not an enforced invariant. Any validator operating multiple node IDs under one reward address who also participates in consensus liquidity on both node IDs will silently trigger this bug every block.

### Recommendation

Replace the plain assignment with accumulation in `consolidateNodes()`:

```go
// Instead of:
cmap[r].CLStakingInfo = clsi

// Accumulate:
if existing := cmap[r].CLStakingInfo; existing != nil {
    existing.CLStakingAmount += clsi.CLStakingAmount
    // CLPoolAddr conflict: reject or sum into a canonical pool
} else {
    cmap[r].CLStakingInfo = clsi
}
```

Alternatively, change `CLStakingInfo` in `consolidatedNode` to a slice `[]*CLStakingInfo` and update `Split()` to iterate all CL entries, distributing proportionally across all CL pools. Additionally, add an explicit validation step that rejects or logs a `StakingInfo` where two node IDs sharing a reward address each carry a distinct CL, so the condition is surfaced rather than silently mishandled.

### Proof of Concept

Given:
```
NodeIds       = [N1, N3]
RewardAddrs   = [R1, R1]          // same reward address
StakingAmounts = [6_000_000, 7_000_000]
CLStakingInfos = [
  {CLNodeId: N1, CLPoolAddr: P1, CLStakingAmount: 1_000_000},
  {CLNodeId: N3, CLPoolAddr: P2, CLStakingAmount: 2_000_000},
]
```

After `consolidateNodes()`:
```
consolidatedNode{RewardAddr: R1, StakingAmount: 13_000_000, CLStakingInfo: {P2, 2_000_000}}
// P1's 1_000_000 is gone
```

`Split(reward=1e18)`:
```
totalAmount = 13_000_000 + 2_000_000 = 15_000_000
clAmount    = 1e18 * 2_000_000 / 15_000_000 ≈ 133_333_333 kei  → P2
cnAmount    = 1e18 - clAmount               ≈ 866_666_667 kei  → R1
P1 receives 0
```

Correct split (denominator = 16_000_000):
```
P1 should receive: 1e18 * 1_000_000 / 16_000_000 = 62_500_000 kei
P2 should receive: 1e18 * 2_000_000 / 16_000_000 = 125_000_000 kei
R1 should receive: 1e18 * 13_000_000 / 16_000_000 = 812_500_000 kei
```

P1 is robbed of 62.5M kei per block; R1 and P2 each receive an inflated share. This mismatch is written directly to state via `state.AddBalance` in `FinalizeState`. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** kaiax/reward/impl/blockstate.go (L30-57)
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
