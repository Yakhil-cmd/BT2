### Title
Silent CL Staking Amount Drop When Multiple Nodes Share a Reward Address — (`kaiax/staking/staking_info.go`)

### Summary

`consolidateNodes()` in `kaiax/staking/staking_info.go` silently overwrites the first `CLStakingInfo` with the second when two AddressBook nodes share the same reward address and each has a separate CL entry in the CLRegistry. The dropped CL pool receives zero KAIA reward, and the surviving CL's split ratio is computed against only its own staking amount rather than the combined CL total, producing incorrect per-block reward distribution.

### Finding Description

The AddressBook explicitly supports multiple nodes sharing a single reward address (the "consolidation" feature). When `consolidateNodes()` processes `CLStakingInfos`, it iterates over every `CLStakingInfo` and assigns it to the consolidated node keyed by reward address:

```go
for _, clsi := range si.CLStakingInfos {
    if r, ok := nToR[clsi.CLNodeId]; ok {
        // One CLStakingInfo per validator is guaranteed by CLRegistry.
        cmap[r].CLStakingInfo = clsi   // ← plain assignment, no accumulation
    }
}
``` [1](#0-0) 

The comment "One CLStakingInfo per validator is guaranteed by CLRegistry" is incorrect. The CLRegistry guarantees uniqueness of `CLNodeId`, not uniqueness of `(CLNodeId → RewardAddr)`. When two distinct nodes `n1` and `n3` both map to reward address `r1` in the AddressBook, and both have separate CL entries in the CLRegistry, the loop first writes `n1`'s `CLStakingInfo` into `cmap[r1]`, then immediately overwrites it with `n3`'s. `n1`'s CL pool address and staking amount are permanently lost.

The test suite already documents this exact behavior and labels it "not feasible in real", but provides no enforcement:

```go
// CL1 will be ignored when being consolidated since it has duplicate CL (not feasible in real)
{CLNodeId: n3, CLPoolAddr: clPool2, CLStakingAmount: clStakingAmount2},
``` [2](#0-1) 

The resulting consolidated node carries only `n3`'s `CLStakingInfo`: [3](#0-2) 

### Impact Explanation

Every block, `FinalizeState` calls `GetDeferredReward`, which calls `assignStakingRewards` / `assignStakingRewardsFlex`, which calls `cn.Split(reward)`: [4](#0-3) 

`Split()` uses only the surviving `CLStakingInfo.CLStakingAmount` to divide the reward between the CN reward address and the CL pool: [5](#0-4) 

Concrete effects per block:
1. **`clPool1` receives zero KAIA** — it is never added to `spec.Rewards`.
2. **`clPool2` receives a wrong share** — the split denominator is `StakingAmount + clStakingAmount2` instead of `StakingAmount + clStakingAmount1 + clStakingAmount2`, so `clPool2` is under-rewarded.
3. **The CN reward address `r1` receives the surplus** — it absorbs both the missing `clPool1` share and the rounding difference for `clPool2`.

This is an unauthorized incorrect KAIA reward distribution affecting every block after Prague hardfork for any validator in this configuration.

### Likelihood Explanation

The AddressBook consolidation feature (multiple nodes sharing one reward address) is a documented, production-used feature: [6](#0-5) 

The CLRegistry is a new Prague-era contract. Any validator that (a) operates multiple nodes under one reward address and (b) registers CL entries for more than one of those nodes will silently trigger this bug. No adversarial action is required — it is a normal operational configuration. The governance council members who manage AddressBook entries are the semi-trusted actors who can reach this state.

### Recommendation

Replace the plain assignment with accumulation. Since a consolidated node can have multiple CL pools, `CLStakingInfo` should be changed to a slice, or the staking amounts should be summed and the pool addresses tracked as a list. At minimum, the `consolidateNodes()` loop should accumulate `CLStakingAmount` and track all `CLPoolAddr` values rather than silently overwriting:

```go
if r, ok := nToR[clsi.CLNodeId]; ok {
    if cmap[r].CLStakingInfo == nil {
        cmap[r].CLStakingInfo = clsi
    } else {
        // Accumulate instead of overwrite
        cmap[r].CLStakingInfo.CLStakingAmount += clsi.CLStakingAmount
        // Track additional pool addresses for reward distribution
    }
}
```

The `Split()` function and the reward allocation maps in `assignStakingRewards` / `assignStakingRewardsFlex` must also be updated to distribute rewards to all CL pool addresses proportionally.

### Proof of Concept

Given:
- AddressBook: `n1 → (s1, r1)`, `n3 → (s3, r1)` — two nodes, same reward address
- CLRegistry: `n1 → clPool1` (amount X), `n3 → clPool2` (amount Y)
- `StakingAmounts`: `a1` for `s1`, `a3` for `s3`

After `consolidateNodes()`:
- Consolidated node for `r1`: `StakingAmount = a1 + a3`, `CLStakingInfo = {n3, clPool2, Y}` — `clPool1` and amount `X` are gone.

After `Split(reward)`:
- `clAmount = Y * reward / (a1 + a3 + Y)` → sent to `clPool2`
- `cnAmount = reward - clAmount` → sent to `r1`
- `clPool1` receives **0 KAIA**

Correct behavior:
- `clAmount_total = (X + Y) * reward / (a1 + a3 + X + Y)`
- `clPool1` receives `X * reward / (a1 + a3 + X + Y)`
- `clPool2` receives `Y * reward / (a1 + a3 + X + Y)`

The test case at `kaiax/staking/staking_info_test.go` lines 243–271 already encodes this exact scenario and confirms the incorrect output, dismissing it as "not feasible in real" without any enforcement mechanism to prevent it. [7](#0-6)

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
