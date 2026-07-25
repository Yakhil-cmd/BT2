### Title
Silent Overwrite of Duplicate CLStakingInfo During Consolidation Causes Incorrect KAIA Reward Distribution — (`kaiax/staking/staking_info.go`)

### Summary

`consolidateNodes()` in `kaiax/staking/staking_info.go` silently overwrites a validator's `CLStakingInfo` when multiple CLRegistry entries map to the same consolidated validator (same `RewardAddr`). Because AddressBook explicitly supports multiple `NodeId`s per `RewardAddr`, and CLRegistry tracks entries per `NodeId` (not per `RewardAddr`), a validator with two registered nodes can legitimately have two CL pools. The second CL pool's entry overwrites the first, causing the first pool's staked KAIA to be completely excluded from reward calculations every block.

### Finding Description

`consolidateNodes()` builds a `consolidatedNode` per unique `RewardAddr`, summing all CNStaking amounts across multiple `NodeId`s. When it then processes `CLStakingInfos`, it performs a plain assignment:

```go
// One CLStakingInfo per validator is guaranteed by CLRegistry.
cmap[r].CLStakingInfo = clsi   // line 157 — overwrites any prior entry
``` [1](#0-0) 

The comment treats the invariant as externally guaranteed, but the CLRegistry contract tracks entries by `CLNodeId` (node address), not by `RewardAddr`. AddressBook explicitly allows multiple `NodeId`s to share one `RewardAddr` — this is the documented "consolidated node" feature: [2](#0-1) 

If validator V registers nodes N1 and N3 in AddressBook (both with `RewardAddr = R1`), and both N1 and N3 register separate CL pools (P1, P3) in CLRegistry, `consolidateNodes()` processes both `CLStakingInfo` entries. The first (P1) is overwritten by the second (P3). The existing test case explicitly demonstrates this: [3](#0-2) 

The test comment acknowledges the overwrite ("CL1 will be ignored") but dismisses it as "not feasible in real" — an assumption that is not enforced in code.

Downstream, `assignStakingRewards` computes `cnTotalStakingAmount` using only the surviving CL's amount:

```go
cnTotalStakingAmount := cn.StakingAmount          // sum of all CNStaking (correct)
if isPrague && cn.CLStakingInfo != nil {
    cnTotalStakingAmount += cn.CLStakingInfo.CLStakingAmount  // only ONE CL (wrong)
}
totalExcessInt += cnTotalStakingAmount - minStake
``` [4](#0-3) 

`Split()` then divides the reward between the CN address and the surviving CL pool address, completely omitting the dropped CL pool: [5](#0-4) 

### Impact Explanation

For every block after the Prague hardfork, if a validator has two nodeIds each with a registered CL pool:

1. **The dropped CL pool (P1) receives zero KAIA rewards** despite having staked KAIA in the protocol.
2. **The validator's total staking weight used for reward allocation is understated** (e.g., 15M CNStaking + 3M CL instead of 15M CNStaking + 11M CL), reducing its proportional share of the staking reward budget.
3. **All other validators receive a larger share** than they are entitled to, because `totalExcessInt` is artificially low.
4. The dropped CL pool's reward portion flows to the `remaining` variable, which is added to the proposer's reward — an unauthorized transfer of KAIA from CL pool stakers to the block proposer.

This is a persistent, per-block incorrect KAIA reward distribution affecting system-managed funds.

### Likelihood Explanation

The trigger requires a validator to:
1. Register two `NodeId`s in AddressBook under the same `RewardAddr` — this is an explicitly supported and tested feature.
2. Register CL pools for both `NodeId`s in CLRegistry — CLRegistry tracks by `NodeId`, so this is structurally possible if the CLRegistry contract does not enforce uniqueness by `RewardAddr`.

The CLRegistry mock (`CLRegistryMockThreeCL`) returns entries indexed by `NodeId`, not `RewardAddr`, confirming the tracking granularity: [6](#0-5) 

The Go-layer assumption ("guaranteed by CLRegistry") is not verified in code and is not enforced by the data model. Any validator operating multiple nodes who also participates in consensus liquidity can trigger this condition.

### Recommendation

Replace the silent overwrite with accumulation. `consolidatedNode` should hold a slice of `CLStakingInfo` entries (one per contributing `NodeId`), and `Split()` / `assignStakingRewards()` should sum all CL amounts and distribute rewards to each CL pool proportionally:

```go
// In consolidateNodes():
if r, ok := nToR[clsi.CLNodeId]; ok {
    cmap[r].CLStakingInfos = append(cmap[r].CLStakingInfos, clsi)
}

// In Split(): sum all CLStakingAmounts, distribute to each pool
```

Alternatively, add an explicit guard that returns an error (or logs a critical warning and skips the duplicate) when two `CLStakingInfo` entries resolve to the same `RewardAddr`, rather than silently overwriting.

### Proof of Concept

The existing test case in `kaiax/staking/staking_info_test.go` already demonstrates the overwrite:

```
Input:
  NodeIds:     [N1, N2, N3, N4]
  RewardAddrs: [R1, R2, R1, R2]   // N1,N3 share R1
  CLStakingInfos: [
    {CLNodeId: N1, CLPoolAddr: P1, CLStakingAmount: 1_000_000},
    {CLNodeId: N3, CLPoolAddr: P2, CLStakingAmount: 3_000_000},  // overwrites N1's entry
  ]

Result (actual):
  consolidatedNode{R1, StakingAmount: A1+A3, CLStakingInfo: {N3, P2, 3_000_000}}
  // P1 and its 1_000_000 KAIA are silently dropped

Expected (correct):
  consolidatedNode{R1, StakingAmount: A1+A3, CLStakingInfos: [
    {N1, P1, 1_000_000},
    {N3, P2, 3_000_000},
  ]}
``` [3](#0-2) 

In `assignStakingRewards`, the reward for R1 is computed using `cnTotalStakingAmount = (A1+A3) + 3_000_000` instead of `(A1+A3) + 4_000_000`, and P1 receives `alloc[P1] = 0` while P1 stakers have locked real KAIA. The difference in `totalExcessInt` causes every other validator's reward to be inflated by the missing 1_000_000 KAIA weight, constituting an unauthorized redistribution of KAIA block rewards. [7](#0-6)

### Citations

**File:** kaiax/staking/staking_info.go (L68-93)
```go
// consolidatedNode is the refined staking information suitable for proposer selection.
// Sometimes a node would register multiple NodeIds in AddressBook,
// in which each entry has different StakingAddr and same RewardAddr.
// We treat those entries with common RewardAddr as one GC node.
//
// For example,
//
//	NodeIds          = [N1, N2, N3]
//	StakingContracts = [S1, S2, S3]
//	RewardAddrs      = [R1, R1, R3]
//	StakingAmounts   = [A1, A2, A3]
//
// can be consolidated into
//
//	CN1 = {[N1,N2], [S1,S2], R1, A1+A2}
//	CN3 = {[N3],    [S3],    R3, A3}
//
// If the node has CLStakingInfo, it will be added to the consolidatedNode.
type consolidatedNode struct {
	NodeIds          []common.Address
	StakingContracts []common.Address
	RewardAddr       common.Address // The common RewardAddr
	StakingAmount    uint64         // Sum of the staking amounts from CNStaking

	CLStakingInfo *CLStakingInfo // The CLStakingInfo if any
}
```

**File:** kaiax/staking/staking_info.go (L150-159)
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

**File:** kaiax/reward/impl/getter.go (L488-534)
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

**File:** contracts/testing/reward/CLRegistryMock.sol (L25-48)
```text
contract CLRegistryMockThreeCL is MockValues {
    function getAllCLs()
        external
        view
        returns (address[] memory, uint256[] memory, address[] memory)
    {
        address[] memory nodeIds = new address[](3);
        uint256[] memory gcIds = new uint256[](3);
        address[] memory clPools = new address[](3);

        nodeIds[0] = nodeId0;
        nodeIds[1] = nodeId1;
        nodeIds[2] = nodeId2; // Doesn't exist in AddressBookMockTwoCN

        gcIds[0] = 1;
        gcIds[1] = 2;
        gcIds[2] = 3;

        clPools[0] = 0x0000000000000000000000000000000000000e00;
        clPools[1] = 0x0000000000000000000000000000000000000e01;
        clPools[2] = 0x0000000000000000000000000000000000000e02;

        return (nodeIds, gcIds, clPools);
    }
```
