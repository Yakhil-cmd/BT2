### Title
`fillAllocated` Returns `nil` Instead of `err` on `GetAllocatedCount` Failure, Silently Burning All Treasury Funds — (`blockchain/system/rebalance.go`)

### Summary

In `blockchain/system/rebalance.go`, the function `fillAllocated` swallows the error from `GetAllocatedCount` by returning `nil` instead of `err`. This is the direct Go analog of the WETH missing-`return` bug: a function that should propagate a failure signal instead returns a success value, causing the caller to proceed with a corrupted (empty) data set. The consequence is that `RebalanceTreasury` executes the KIP-103/KIP-160 treasury rebalance with an empty allocated list, zeroing all treasury source balances without distributing any funds to the intended recipients — permanently burning the entire zeroed treasury balance.

### Finding Description

`fillAllocated` is responsible for populating `result.After.Allocated` with the recipient addresses and their target amounts read from the on-chain `TreasuryRebalanceV2` contract:

```go
// blockchain/system/rebalance.go, line 215-233
func (result *rebalanceResult) fillAllocated(contract RebalanceCaller, state *state.StateDB) error {
    numNewbieBigInt, err := contract.GetAllocatedCount(nil)
    if err != nil {
        logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
        return nil   // ← BUG: should be `return err`
    }
    for i := 0; i < int(numNewbieBigInt.Int64()); i++ {
        ...
        result.After.Allocated[ret.Addr] = ret.Amount
    }
    return nil
}
```

The sibling function `fillZeroed` correctly propagates the error:

```go
// blockchain/system/rebalance.go, line 196-213
func (result *rebalanceResult) fillZeroed(contract RebalanceCaller, state *state.StateDB) error {
    numRetiredBigInt, err := contract.GetZeroedCount(nil)
    if err != nil {
        logger.Error("Failed to get ZeroedCount from TreasuryRebalance contract", "err", err)
        return err   // ← correct
    }
    ...
}
```

The caller `RebalanceTreasury` checks the return value of `fillAllocated`:

```go
// blockchain/system/rebalance.go, line 281-283
if err = result.fillAllocated(caller, state); err != nil {
    return result, err
}
```

Because `fillAllocated` always returns `nil` on `GetAllocatedCount` failure, this guard never fires. `RebalanceTreasury` then proceeds with `result.After.Allocated` being an empty map.

The downstream execution path in `RebalanceTreasury`:

1. **Validation 4** (`line 303`): `totalAllocatedAmount` is 0 (empty map). For KIP-103, the check `totalZeroedAmount < 0` is always false, so it passes. For KIP-160, there is no such check at all.
2. **Execution 1** (`line 308-311`): All zeroed addresses have their balances set to 0 — funds are destroyed.
3. **Execution 2** (`line 313-319`): The loop over `result.After.Allocated` is empty — no funds are distributed.
4. **Remainder** (`line 322-323`): `remainder = totalZeroedAmount - 0 = totalZeroedAmount`. The entire zeroed balance is added to `result.Burnt`.
5. `result.Success = true` is set and the corrupted state is committed.

The outer caller `FinalizeState` only skips state changes when `RebalanceTreasury` returns a non-nil error:

```go
// kaiax/system/impl/blockstate.go, line 41-48
rebalanceResult, err := bcsystem.RebalanceTreasury(state, m.Chain, header)
if err != nil {
    logger.Error("failed to execute treasury rebalancing. State not changed", "err", err)
} else {
    logger.Info("successfully executed treasury rebalancing", ...)
}
```

Because the bug causes `RebalanceTreasury` to return `(result, nil)` with `result.Success = true`, `FinalizeState` logs a false success and commits the corrupted state.

### Impact Explanation

All KAIA held by zeroed treasury addresses is permanently burned at the KIP-103 or KIP-160 hard fork block. None of the intended allocated recipients receive any funds. The state transition is irreversible: balances are set to zero via `state.SetBalance(addr, big.NewInt(0))` and the block is finalized with `result.Success = true`. The corrupted state root is committed to the canonical chain.

### Likelihood Explanation

The trigger requires `GetAllocatedCount` to return an error. This call is an EVM execution against the deployed `TreasuryRebalanceV2` contract. Failure modes include: the contract not being deployed at the configured address, a revert in the contract, or a state/trie read error at the fork block. These are low-probability events in a well-prepared hard fork, but the bug is latent and unguarded — no test exercises the `GetAllocatedCount` failure path, and the inconsistency with `fillZeroed` (which correctly returns `err`) confirms this is an unintentional developer oversight.

### Recommendation

Change line 219 of `blockchain/system/rebalance.go` from:

```go
return nil
```

to:

```go
return err
```

This makes `fillAllocated` consistent with `fillZeroed` and ensures that any failure to read the allocated list aborts the rebalance before any state mutation occurs.

### Proof of Concept

1. At the KIP-160 fork block, `FinalizeState` calls `RebalanceTreasury`.
2. `RebalanceTreasury` constructs a `Kip160ContractCaller` pointing to the configured contract address.
3. `fillAllocated` calls `GetAllocatedCount`. If the call fails (e.g., contract not at expected address, EVM revert), the error is logged and `nil` is returned.
4. `RebalanceTreasury` proceeds: `result.After.Allocated` is empty, `totalAllocatedAmount = 0`.
5. All zeroed addresses (e.g., old treasury multisigs holding millions of KAIA) have balances set to 0.
6. No allocations are made.
7. `result.Burnt = totalZeroedAmount`, `result.Success = true`.
8. `FinalizeState` logs "successfully executed treasury rebalancing" and commits the state.
9. All treasury KAIA is permanently burned; intended recipients receive nothing. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** blockchain/system/rebalance.go (L196-201)
```go
func (result *rebalanceResult) fillZeroed(contract RebalanceCaller, state *state.StateDB) error {
	numRetiredBigInt, err := contract.GetZeroedCount(nil)
	if err != nil {
		logger.Error("Failed to get ZeroedCount from TreasuryRebalance contract", "err", err)
		return err
	}
```

**File:** blockchain/system/rebalance.go (L215-220)
```go
func (result *rebalanceResult) fillAllocated(contract RebalanceCaller, state *state.StateDB) error {
	numNewbieBigInt, err := contract.GetAllocatedCount(nil)
	if err != nil {
		logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
		return nil
	}
```

**File:** blockchain/system/rebalance.go (L280-283)
```go
	// Retrieve 2) Get Allocated
	if err = result.fillAllocated(caller, state); err != nil {
		return result, err
	}
```

**File:** blockchain/system/rebalance.go (L300-325)
```go
	// Validation 4) Check the total balance of zeroeds are bigger than the distributing amount
	totalZeroedAmount := result.totalZeroedBalance()
	totalAllocatedAmount := result.totalAllocatedBalance()
	if isKIP103 && totalZeroedAmount.Cmp(totalAllocatedAmount) < 0 {
		return result, ErrRebalanceNotEnoughBalance
	}

	// Execution 1) Clear all balances of zeroeds
	for addr := range result.Before.Zeroed {
		state.SetBalance(addr, big.NewInt(0))
		result.After.Zeroed[addr] = big.NewInt(0)
	}
	// Execution 2) Distribute KAIA to all allocateds
	for addr, balance := range result.After.Allocated {
		// if an allocated has KAIA before the allocation, it will be burnt
		currentBalance := state.GetBalance(addr)
		result.Burnt.Add(result.Burnt, currentBalance)

		state.SetBalance(addr, balance)
	}

	// Fill the remaining fields of the result
	remainder := new(big.Int).Sub(totalZeroedAmount, totalAllocatedAmount)
	result.Burnt.Add(result.Burnt, remainder)
	result.Success = true
	return result, nil
```

**File:** kaiax/system/impl/blockstate.go (L40-49)
```go
	if chainConfig.IsKIP160ForkBlock(header.Number) || chainConfig.IsKIP103ForkBlock(header.Number) {
		rebalanceResult, err := bcsystem.RebalanceTreasury(state, m.Chain, header)
		if err != nil {
			logger.Error("failed to execute treasury rebalancing. State not changed", "err", err)
		} else {
			// Memo format differs between KIP-103 and KIP-160.
			isKIP103 := chainConfig.IsKIP103ForkBlock(header.Number)
			logger.Info("successfully executed treasury rebalancing", "memo", string(rebalanceResult.Memo(isKIP103)))
		}
	}
```
