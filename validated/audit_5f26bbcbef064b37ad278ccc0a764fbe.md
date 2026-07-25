### Title
Missing Zero-Address Guard for `CLPoolAddr` in Prague/Flex CL Reward Distribution Causes KAIA Permanently Sent to `address(0)` — (`kaiax/reward/impl/getter.go`)

### Summary

After the Prague hardfork, block reward distribution splits each eligible validator's staking reward between the validator's AddressBook reward address and its Consensus Liquidity (CL) pool address (`CLPoolAddr`). The code that performs this split never validates that `CLPoolAddr` is non-zero before crediting it. If the CLRegistry returns a zero pool address for a validator that has a non-zero `CLStakingAmount`, the CL portion of every block reward for that validator is permanently credited to `address(0)` — effectively burning it without accounting for it as burnt, and depriving the legitimate CL pool of its share.

### Finding Description

`FinalizeState` in `kaiax/reward/impl/blockstate.go` calls `GetDeferredReward`, which routes to `getDeferredRewardFullKore` or `getDeferredRewardFullFlex`. Both call `assignStakingRewards` / `assignStakingRewardsFlex` and then `specWithProposerAndFunds` / `specWithProposerAndFundsFlex`. All four functions contain the same pattern:

```go
// assignStakingRewards (getter.go:521-525)
if isPrague && cn.CLStakingInfo != nil {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount   // ← no zero-address guard
}
```

```go
// specWithProposerAndFunds (getter.go:633-636)
cnAmount, clAmount := cn.Split(proposer)
newSpec.IncRecipient(cn.RewardAddr, cnAmount)
newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)  // ← no zero-address guard
```

The upstream staking getter (`parsePermissionlessCallResult`, `parseCallResult`) stores whatever address the CLRegistry returns for `CLPoolAddr` without validation:

```go
// kaiax/staking/impl/getter.go:215-219
clStakingInfos[i] = &staking.CLStakingInfo{
    CLNodeId:        clRes.NodeIds[i],
    CLPoolAddr:      clRes.ClPools[i],   // ← no zero-address check
    CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
}
```

`consolidatedNode.Split` only short-circuits when `CLStakingInfo == nil`; it does not short-circuit when `CLPoolAddr` is zero:

```go
// kaiax/staking/staking_info.go:169-187
func (c consolidatedNode) Split(amount *big.Int) (*big.Int, *big.Int) {
    if c.CLStakingInfo == nil {          // only nil-pointer guard, no zero-address guard
        return amount, big.NewInt(0)
    }
    ...
    clAmount := new(big.Int).Mul(clAmountBig, amount)
    clAmount  = clAmount.Div(clAmount, totalAmount)
    cnAmount  := big.NewInt(0).Sub(amount, clAmount)
    return cnAmount, clAmount            // clAmount > 0 when CLStakingAmount > 0
}
```

`RewardSpec.Validate()` only rejects negative amounts, not zero-address recipients:

```go
// kaiax/reward/spec.go:118-124
func (spec *RewardSpec) Validate() error {
    for addr, amount := range spec.Rewards {
        if amount.Sign() < 0 {           // no zero-address check
            return errNegativeRewardAmount(addr, amount)
        }
    }
    return nil
}
```

`FinalizeState` then unconditionally calls `state.AddBalance(addr, amount)` for every entry in `spec.Rewards`, including `address(0)`:

```go
// kaiax/reward/impl/blockstate.go:53-55
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
```

`StateDB.AddBalance` creates a new state object for `address(0)` if one does not exist and credits it:

```go
// blockchain/state/statedb.go:492-496
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
    stateObject := s.GetOrNewStateObject(addr)
    if stateObject != nil {
        stateObject.AddBalance(amount)
    }
}
```

Contrast this with the fund-address handling in the same functions, which correctly guards against zero addresses:

```go
// kaiax/reward/impl/getter.go:542-563 (specWithProposerAndFundsFlex)
if common.EmptyAddress(si.KIFAddr) {
    newSpec.KIF = common.Big0
    proposer.Add(proposer, kif)          // fallback to proposer
} else {
    newSpec.KIF = kif
    newSpec.IncRecipient(si.KIFAddr, kif)
}
// ... same pattern for KEFAddr, KPFAddr
```

The CL pool address has no equivalent guard.

### Impact Explanation

When `CLPoolAddr = address(0)` and `CLStakingAmount > 0` for a validator:

- Every block, `clAmount = CLStakingAmount / (CNStakingAmount + CLStakingAmount) * reward` KAIA is credited to `address(0)`.
- No private key controls `address(0)`, so the KAIA is permanently inaccessible.
- The CL pool contract that should receive the reward does not receive it.
- The burnt-fee accounting (`spec.BurntFee`) is not updated, so the total supply tracking is incorrect.
- This is an unauthorized, irreversible transfer of KAIA away from its legitimate recipient, matching the "unauthorized transfer … affecting KAIA … or system-managed funds" impact gate.

### Likelihood Explanation

The CLRegistry is a system contract read from chain state. If a validator registers a CL entry with `CLPoolAddr = address(0)` (whether by mistake, through a CLRegistry contract bug, or through a governance-controlled upgrade that relaxes validation), the Go reward code has no defense. The staking getter stores the zero address verbatim. The reward distribution code uses it verbatim. The condition requires `CLStakingAmount > 0` alongside the zero address, which is the normal case for any registered CL entry. No majority-validator collusion is needed; a single validator's misconfigured CLRegistry entry is sufficient.

### Recommendation

1. In `parsePermissionlessCallResult` and `parseCallResult` (`kaiax/staking/impl/getter.go`), skip or reject any CLRegistry entry where `CLPoolAddr` is the zero address:

```go
if common.EmptyAddress(clRes.ClPools[i]) {
    logger.Warn("CLRegistry entry has zero CLPoolAddr, skipping", "nodeId", clRes.NodeIds[i])
    continue
}
```

2. In `assignStakingRewards`, `assignStakingRewardsFlex`, `specWithProposerAndFunds`, and `specWithProposerAndFundsFlex` (`kaiax/reward/impl/getter.go`), add a zero-address guard before crediting the CL pool, mirroring the existing KIF/KEF/KPF guards:

```go
if isPrague && cn.CLStakingInfo != nil && !common.EmptyAddress(cn.CLStakingInfo.CLPoolAddr) {
    cnAmount, clAmount := cn.Split(reward)
    alloc[cn.RewardAddr] = cnAmount
    alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
} else {
    alloc[cn.RewardAddr] = reward   // full reward to CN if CL pool is unset
}
```

3. In `consolidatedNode.Split`, add a zero-address short-circuit analogous to the `nil` check:

```go
if c.CLStakingInfo == nil || common.EmptyAddress(c.CLStakingInfo.CLPoolAddr) {
    return amount, big.NewInt(0)
}
```

4. In `RewardSpec.Validate`, add a zero-address check:

```go
if common.EmptyAddress(addr) && amount.Sign() > 0 {
    return errZeroAddressRewardRecipient(amount)
}
```

### Proof of Concept

**Setup**: Prague hardfork active. CLRegistry returns one entry:
- `CLNodeId = 0xa01` (matches an AddressBook validator)
- `CLPoolAddr = address(0)` (zero address)
- `CLStakingAmount = 1_000_000` KAIA

**Execution path**:

1. `parsePermissionlessCallResult` stores `CLPoolAddr = address(0)` in `CLStakingInfo` without validation. [1](#0-0) 

2. `consolidateNodes` attaches this `CLStakingInfo` to the consolidated node for `0xa01`. [2](#0-1) 

3. `assignStakingRewards` computes `reward > 0` for the validator (CNStaking ≥ minStake), calls `cn.Split(reward)`, and writes `alloc[address(0)] = clAmount` without checking `CLPoolAddr`. [3](#0-2) 

4. `specWithProposerAndFunds` similarly calls `cn.Split(proposer)` and calls `newSpec.IncRecipient(address(0), clAmount)` without checking `CLPoolAddr`. [4](#0-3) 

5. `RewardSpec.Validate()` passes because `clAmount > 0`. [5](#0-4) 

6. `FinalizeState` calls `state.AddBalance(address(0), clAmount)`, permanently crediting KAIA to the zero address every block. [6](#0-5) 

The KIF/KEF/KPF fund addresses have an explicit empty-address guard that redirects their share to the proposer when unset — the CL pool address has no equivalent protection. [7](#0-6)

### Citations

**File:** kaiax/staking/impl/getter.go (L214-220)
```go
		for i := range clRes.NodeIds {
			clStakingInfos[i] = &staking.CLStakingInfo{
				CLNodeId:        clRes.NodeIds[i],
				CLPoolAddr:      clRes.ClPools[i],
				CLStakingAmount: big.NewInt(0).Div(clRes.StakingAmounts[i], big.NewInt(params.KAIA)).Uint64(),
			}
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

**File:** kaiax/reward/impl/getter.go (L520-530)
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
				remaining.Sub(remaining, reward)
			}
```

**File:** kaiax/reward/impl/getter.go (L542-564)
```go
	if common.EmptyAddress(si.KIFAddr) {
		newSpec.KIF = common.Big0
		proposer.Add(proposer, kif)
	} else {
		newSpec.KIF = kif
		newSpec.IncRecipient(si.KIFAddr, kif)
	}

	if common.EmptyAddress(si.KEFAddr) {
		newSpec.KEF = common.Big0
		proposer.Add(proposer, kef)
	} else {
		newSpec.KEF = kef
		newSpec.IncRecipient(si.KEFAddr, kef)
	}

	if common.EmptyAddress(si.KPFAddr) {
		newSpec.KPF = common.Big0
		proposer.Add(proposer, kpf)
	} else {
		newSpec.KPF = kpf
		newSpec.IncRecipient(si.KPFAddr, kpf)
	}
```

**File:** kaiax/reward/impl/getter.go (L633-637)
```go
		cnAmount, clAmount := cn.Split(proposer)

		newSpec.IncRecipient(cn.RewardAddr, cnAmount)
		newSpec.IncRecipient(cn.CLStakingInfo.CLPoolAddr, clAmount)
		return newSpec
```

**File:** kaiax/reward/spec.go (L118-124)
```go
func (spec *RewardSpec) Validate() error {
	for addr, amount := range spec.Rewards {
		if amount.Sign() < 0 {
			return errNegativeRewardAmount(addr, amount)
		}
	}
	return nil
```

**File:** kaiax/reward/impl/blockstate.go (L53-55)
```go
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
```
