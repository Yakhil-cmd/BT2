### Title
Missing Zero-Address Validation for Validator Reward Addresses in `parsePermissionlessCallResult` Leads to Staking Rewards Burned to `address(0)` — (`File: kaiax/staking/impl/getter.go`)

---

### Summary

`parsePermissionlessCallResult` in `kaiax/staking/impl/getter.go` ingests validator profiles from AddressBookV2 and CL pool addresses from CLRegistry without validating that `p.RewardAddress` or `clRes.ClPools[i]` are non-zero. A validator that registers a zero reward address (or a zero CL pool address) will have staking rewards credited to `address(0)` during `FinalizeState`, permanently burning KAIA that should have been distributed to the validator.

---

### Finding Description

`parsePermissionlessCallResult` is the post-Permissionless-hardfork path for building `StakingInfo` from AddressBookV2 profiles. It filters profiles by `IsRewardEligible()` state but performs **no zero-address check** on `p.RewardAddress` or `clRes.ClPools[i]` before storing them:

```go
// kaiax/staking/impl/getter.go lines 201-208
for i, p := range profiles {
    if !valset.NodeState(p.State).IsRewardEligible() {
        continue
    }
    nodeIds = append(nodeIds, p.NodeId)
    stakingContracts = append(stakingContracts, p.StakingContract)
    rewardAddrs = append(rewardAddrs, p.RewardAddress)   // ← no zero check
    stakingAmounts = append(stakingAmounts, ...)
}
``` [1](#0-0) 

And for CL pool addresses:

```go
// kaiax/staking/impl/getter.go lines 214-220
clStakingInfos[i] = &staking.CLStakingInfo{
    CLNodeId:        clRes.NodeIds[i],
    CLPoolAddr:      clRes.ClPools[i],   // ← no zero check
    CLStakingAmount: ...,
}
``` [2](#0-1) 

Contrast this with `parseCallResult` (the legacy permissioned path), which **does** guard against zero fund addresses:

```go
// kaiax/staking/impl/getter.go lines 306-310
if len(nodeIds) != len(stakingContracts) || ... ||
    common.EmptyAddress(kefAddr) || common.EmptyAddress(kifAddr) {
    return emptyStakingInfo(num), nil
}
``` [3](#0-2) 

The zero-address guard exists for `kefAddr`/`kifAddr` in the legacy path but is entirely absent for individual validator `rewardAddrs` in both paths, and absent for all addresses in the permissionless path.

The zero-address `RewardAddr` propagates through `consolidateNodes()`: [4](#0-3) 

Into `assignStakingRewards` / `assignStakingRewardsFlex`, which write directly to the allocation map:

```go
alloc[cn.RewardAddr] = reward          // zero address if unvalidated
alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount  // zero address if unvalidated
``` [5](#0-4) [6](#0-5) 

`FinalizeState` then iterates `spec.Rewards` and calls `state.AddBalance(addr, amount)` for every entry, including `addr = common.Address{}`: [7](#0-6) 

KAIA credited to `address(0)` is permanently inaccessible — effectively burned.

---

### Impact Explanation

Any staking reward share allocated to a validator whose `RewardAddress` (or whose CL pool's `CLPoolAddr`) is `address(0)` is sent to the zero address and permanently burned. The minted KAIA is lost from the intended recipient without any error or revert. This is an incorrect reward distribution affecting KAIA.

---

### Likelihood Explanation

**Permissioned path (legacy AddressBook):** The `reviseRewardAddress` function in the mock contract shows no zero-address guard: [8](#0-7) 

If the production AddressBook contract similarly lacks a zero-address check, a validator can register `address(0)` as their reward address.

**Permissionless path (AddressBookV2):** `updateRewardAddress` accepts any `newRewardAddress`: [9](#0-8) 

If the Solidity implementation does not `require(newRewardAddress != address(0))`, a validator can set their reward address to zero. The Go-layer parser `parsePermissionlessCallResult` provides no backstop.

**CL path:** `CLPoolAddr` is sourced from CLRegistry with no zero-address filter in the Go parser.

---

### Recommendation

In `parsePermissionlessCallResult`, skip any profile whose `RewardAddress` is the zero address, and skip any CL entry whose `CLPoolAddr` is the zero address:

```go
for i, p := range profiles {
    if !valset.NodeState(p.State).IsRewardEligible() {
        continue
    }
    if common.EmptyAddress(p.RewardAddress) {
        logger.Warn("skipping profile with zero reward address", "nodeId", p.NodeId)
        continue
    }
    // ... append
}
```

And for CL entries:

```go
for i := range clRes.NodeIds {
    if common.EmptyAddress(clRes.ClPools[i]) {
        logger.Warn("skipping CL entry with zero pool address", "nodeId", clRes.NodeIds[i])
        continue
    }
    // ... append
}
```

Apply the same guard in `parseCallResult` for individual entries in `rewardAddrs`.

---

### Proof of Concept

1. After the Permissionless hardfork, a validator calls `updateRewardAddress(nodeId, address(0))` on AddressBookV2 (if the contract permits it).
2. The validator's profile is returned by `multiCallStakingInfoPermissionless` with `RewardAddress = 0x0000...0000` and `State = ValActive`.
3. `parsePermissionlessCallResult` passes the `IsRewardEligible()` check and appends `address(0)` to `rewardAddrs`.
4. `consolidateNodes()` creates a `consolidatedNode` with `RewardAddr = common.Address{}`.
5. `assignStakingRewards` computes the validator's share and writes `alloc[common.Address{}] = reward`.
6. `FinalizeState` calls `state.AddBalance(common.Address{}, reward)`.
7. The KAIA is credited to `address(0)` and is permanently inaccessible — burned instead of paid to the validator. [10](#0-9) [11](#0-10)

### Citations

**File:** kaiax/staking/impl/getter.go (L182-234)
```go
// parsePermissionlessCallResult converts ABv2 multicall results into StakingInfo,
// keeping only reward-eligible nodes (KIP-286); amounts are effective stake (KIP-287).
func parsePermissionlessCallResult(num uint64, profiles []multicall.Profile, amounts []*big.Int, kefAddr, kifAddr, kpfAddr common.Address, clRes clRegistryResult) (*staking.StakingInfo, error) {
	if len(profiles) == 0 {
		return emptyStakingInfo(num), nil
	}
	if len(profiles) != len(amounts) {
		logger.Error("length of profiles and amounts differ", "sourceNum", num, "profileLen", len(profiles), "amountLen", len(amounts))
		return nil, staking.ErrAddressBookResult
	}
	if len(clRes.NodeIds) != len(clRes.ClPools) || len(clRes.NodeIds) != len(clRes.StakingAmounts) {
		logger.Error("length of CL registry result fields differ", "sourceNum", num, "nodeLen", len(clRes.NodeIds), "poolLen", len(clRes.ClPools), "amountLen", len(clRes.StakingAmounts))
		return nil, staking.ErrCLRegistryResult
	}

	nodeIds := make([]common.Address, 0, len(profiles))
	stakingContracts := make([]common.Address, 0, len(profiles))
	rewardAddrs := make([]common.Address, 0, len(profiles))
	stakingAmounts := make([]uint64, 0, len(profiles))
	for i, p := range profiles {
		if !valset.NodeState(p.State).IsRewardEligible() {
			continue
		}
		nodeIds = append(nodeIds, p.NodeId)
		stakingContracts = append(stakingContracts, p.StakingContract)
		rewardAddrs = append(rewardAddrs, p.RewardAddress)
		stakingAmounts = append(stakingAmounts, new(big.Int).Div(amounts[i], big.NewInt(params.KAIA)).Uint64())
	}

	var clStakingInfos staking.CLStakingInfos
	if len(clRes.NodeIds) > 0 {
		clStakingInfos = make(staking.CLStakingInfos, len(clRes.NodeIds))
		for i := range clRes.NodeIds {
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
		}
	}

	return &staking.StakingInfo{
		SourceBlockNum:   num,
		NodeIds:          nodeIds,
		StakingContracts: stakingContracts,
		RewardAddrs:      rewardAddrs,
		KEFAddr:          kefAddr,
		KIFAddr:          kifAddr,
		KPFAddr:          kpfAddr,
		StakingAmounts:   stakingAmounts,
		CLStakingInfos:   clStakingInfos,
	}, nil
}
```

**File:** kaiax/staking/impl/getter.go (L304-311)
```go
	// Sanity check
	// Note that kpfAddr (spareAddr) can be empty even after the AddressBook is activated.
	if len(nodeIds) != len(stakingContracts) || len(nodeIds) != len(rewardAddrs) || len(nodeIds) != len(amounts) ||
		common.EmptyAddress(kefAddr) || common.EmptyAddress(kifAddr) {
		// This is an expected behavior when the AddressBook contract is not activated yet.
		logger.Trace("returning empty staking info because AddressBook is not activated", "sourceNum", num)
		return emptyStakingInfo(num), nil
	}
```

**File:** kaiax/staking/staking_info.go (L131-147)
```go
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
```

**File:** kaiax/reward/impl/getter.go (L474-480)
```go
		if isPrague && cn.CLStakingInfo != nil {
			cnAmount, clAmount := cn.Split(reward)
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
		} else {
			alloc[cn.RewardAddr] = reward
		}
```

**File:** kaiax/reward/impl/getter.go (L520-528)
```go
			if reward := new(big.Int).Div(new(big.Int).Mul(excess, stakersReward), totalExcess); reward.Sign() > 0 {
				if isPrague && cn.CLStakingInfo != nil {
					// The remaining amount will be added to the cnAmount.
					cnAmount, clAmount := cn.Split(reward)
					alloc[cn.RewardAddr] = cnAmount
					alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
				} else {
					alloc[cn.RewardAddr] = reward
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

**File:** contracts/testing/reward/AddressBookMock.sol (L271-272)
```text
        cnRewardAddressList[index] = _rewardAddress;
        emit ReviseRewardAddress(cnNodeIdList[index], prevAddress, cnRewardAddressList[index]);
```

**File:** contracts/bindings/addressbookv2/AddressBookV2.go (L2303-2308)
```go
// UpdateRewardAddress is a paid mutator transaction binding the contract method 0x394f8899.
//
// Solidity: function updateRewardAddress(address nodeId, address newRewardAddress) returns()
func (_AddressBookV2 *AddressBookV2Session) UpdateRewardAddress(nodeId common.Address, newRewardAddress common.Address) (*types.Transaction, error) {
	return _AddressBookV2.Contract.UpdateRewardAddress(&_AddressBookV2.TransactOpts, nodeId, newRewardAddress)
}
```
