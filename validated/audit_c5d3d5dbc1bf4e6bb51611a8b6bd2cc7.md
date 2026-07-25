### Title
Swallowed Error in `fillAllocated` Causes Silent Total-Loss Burn of All Zeroed Treasury KAIA During KIP-103/KIP-160 Rebalancing — (`File: blockchain/system/rebalance.go`)

---

### Summary

`fillAllocated` in `blockchain/system/rebalance.go` returns `nil` instead of the actual error when `GetAllocatedCount` fails. Because the caller `RebalanceTreasury` checks `if err = result.fillAllocated(...); err != nil`, a swallowed error causes execution to continue with an empty allocation map. The subsequent state-mutation loop then zeros every "zeroed" treasury address and distributes nothing, permanently burning the entire zeroed balance instead of routing it to the intended recipients.

---

### Finding Description

`fillZeroed` and `fillAllocated` are symmetric helpers that populate the two sides of a treasury rebalance. `fillZeroed` correctly propagates its error:

```go
// blockchain/system/rebalance.go:197-200
numRetiredBigInt, err := contract.GetZeroedCount(nil)
if err != nil {
    logger.Error(...)
    return err   // ← correct
}
```

`fillAllocated` does not:

```go
// blockchain/system/rebalance.go:216-219
numNewbieBigInt, err := contract.GetAllocatedCount(nil)
if err != nil {
    logger.Error(...)
    return nil   // ← BUG: error is swallowed
}
```

`RebalanceTreasury` calls both helpers and gates on their return values:

```go
// blockchain/system/rebalance.go:276-283
if err = result.fillZeroed(caller, state); err != nil {
    return result, err
}
if err = result.fillAllocated(caller, state); err != nil {
    return result, err   // never reached when fillAllocated swallows the error
}
```

When `GetAllocatedCount` fails, `result.After.Allocated` is left as an empty map. Execution then proceeds through all four validation steps (Validation 4 trivially passes because `totalAllocatedAmount == 0 ≤ totalZeroedAmount`) and into the two mutation steps:

```go
// blockchain/system/rebalance.go:307-323
// Execution 1) Clear all balances of zeroeds
for addr := range result.Before.Zeroed {
    state.SetBalance(addr, big.NewInt(0))   // ← KAIA removed
}
// Execution 2) Distribute KAIA to all allocateds
for addr, balance := range result.After.Allocated {
    // empty map — nothing distributed
}
remainder := new(big.Int).Sub(totalZeroedAmount, totalAllocatedAmount)
result.Burnt.Add(result.Burnt, remainder)   // ← entire zeroed amount counted as burnt
result.Success = true
```

The state is committed with `Success = true`, zeroed addresses at zero balance, and allocated addresses untouched.

---

### Impact Explanation

All KAIA held by every "zeroed" treasury address is permanently destroyed rather than redistributed. The allocated addresses receive nothing. Because `result.Success = true` is written back to the memo stored on-chain, the rebalancing is recorded as successful, leaving no on-chain signal of the failure. The loss is irreversible once the block is finalized.

---

### Likelihood Explanation

`GetAllocatedCount` is a contract view call. It can fail if:
- The `Kip160ContractAddress` / `Kip103ContractAddress` in `ChainConfig` points to an address that does not contain the expected contract (e.g., deployment failure, wrong address in genesis).
- The contract's `getAllocatedCount` function reverts (e.g., storage corruption, unexpected state).
- The ABI binding returns a decoding error.

The hard-fork block is a one-shot event. There is no retry; if the call fails and the error is swallowed, the destructive state mutation executes immediately and is committed to the canonical chain.

---

### Recommendation

Change line 219 to propagate the error, matching the pattern used in `fillZeroed`:

```go
// blockchain/system/rebalance.go
func (result *rebalanceResult) fillAllocated(contract RebalanceCaller, state *state.StateDB) error {
    numNewbieBigInt, err := contract.GetAllocatedCount(nil)
    if err != nil {
        logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
        return err   // was: return nil
    }
    ...
}
```

---

### Proof of Concept

1. Deploy a `TreasuryRebalanceV2` contract at `Kip160ContractAddress` whose `getAllocatedCount()` reverts (or configure a wrong address so the call fails with a decoding error).
2. Populate `zeroeds` with addresses holding non-zero KAIA balances and set `status = Approved`.
3. Trigger the KIP-160 hard-fork block.
4. `fillAllocated` calls `GetAllocatedCount`, receives an error, logs it, and returns `nil`.
5. `RebalanceTreasury` continues; `result.After.Allocated` is empty.
6. All zeroed addresses are set to balance 0; no KAIA is distributed.
7. `result.Burnt` equals the full sum of zeroed balances; `result.Success = true`.
8. The block is committed. All treasury KAIA is permanently destroyed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** blockchain/system/rebalance.go (L196-213)
```go
func (result *rebalanceResult) fillZeroed(contract RebalanceCaller, state *state.StateDB) error {
	numRetiredBigInt, err := contract.GetZeroedCount(nil)
	if err != nil {
		logger.Error("Failed to get ZeroedCount from TreasuryRebalance contract", "err", err)
		return err
	}

	for i := 0; i < int(numRetiredBigInt.Int64()); i++ {
		ret, err := contract.Zeroeds(nil, big.NewInt(int64(i)))
		if err != nil {
			logger.Error("Failed to get Zeroeds from TreasuryRebalance contract", "err", err)
			return err
		}
		result.Before.Zeroed[ret] = state.GetBalance(ret)
		result.After.Zeroed[ret] = state.GetBalance(ret) // will be set as zero if rebalance succeeds
	}
	return nil
}
```

**File:** blockchain/system/rebalance.go (L215-233)
```go
func (result *rebalanceResult) fillAllocated(contract RebalanceCaller, state *state.StateDB) error {
	numNewbieBigInt, err := contract.GetAllocatedCount(nil)
	if err != nil {
		logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
		return nil
	}

	for i := 0; i < int(numNewbieBigInt.Int64()); i++ {
		ret, err := contract.Allocateds(nil, big.NewInt(int64(i)))
		if err != nil {
			logger.Error("Failed to get Allocateds from TreasuryRebalance contract", "err", err)
			return err
		}

		result.Before.Allocated[ret.Addr] = state.GetBalance(ret.Addr)
		result.After.Allocated[ret.Addr] = ret.Amount
	}
	return nil
}
```

**File:** blockchain/system/rebalance.go (L276-283)
```go
	if err = result.fillZeroed(caller, state); err != nil {
		return result, err
	}

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
