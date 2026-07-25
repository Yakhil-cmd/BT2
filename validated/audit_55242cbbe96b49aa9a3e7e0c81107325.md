Looking at the external bug's invariant — **a called function's failure return value is silently ignored, causing state to be mutated as if the operation succeeded, permanently locking/losing assets** — I searched the Kaia codebase for the same pattern in privileged state-mutation paths.

The closest match is in `blockchain/system/rebalance.go`.

---

### Title
`fillAllocated` Silently Discards `GetAllocatedCount` Error, Causing Treasury Zeroed Balances to Be Burned Without Reallocation — (`blockchain/system/rebalance.go`)

---

### Summary

`RebalanceTreasury` (KIP-103 / KIP-160 fork-block treasury rebalancing) calls `fillAllocated` to populate the allocation map before executing balance transfers. `fillAllocated` returns `nil` — not the error — when `GetAllocatedCount` fails. `RebalanceTreasury` therefore continues with an empty allocation map, burns every zeroed address's balance to zero, distributes nothing, and returns `(result, nil)` — marking the operation as successful. The caller in `FinalizeState` logs success and commits the block. Treasury KAIA is permanently destroyed.

---

### Finding Description

`fillZeroed` and `fillAllocated` are symmetric helpers. `fillZeroed` correctly propagates its error:

```go
// blockchain/system/rebalance.go  lines 196-212
func (result *rebalanceResult) fillZeroed(...) error {
    numRetiredBigInt, err := contract.GetZeroedCount(nil)
    if err != nil {
        logger.Error("Failed to get ZeroedCount ...")
        return err          // ← propagates
    }
    ...
}
``` [1](#0-0) 

`fillAllocated` does **not**:

```go
// blockchain/system/rebalance.go  lines 215-233
func (result *rebalanceResult) fillAllocated(...) error {
    numNewbieBigInt, err := contract.GetAllocatedCount(nil)
    if err != nil {
        logger.Error("Failed to get AllocatedCount ...")
        return nil          // ← BUG: swallows error, leaves After.Allocated empty
    }
    for i := 0; i < int(numNewbieBigInt.Int64()); i++ {
        ret, err := contract.Allocateds(nil, big.NewInt(int64(i)))
        if err != nil {
            return err      // ← inner loop does propagate
        }
        result.Before.Allocated[ret.Addr] = state.GetBalance(ret.Addr)
        result.After.Allocated[ret.Addr] = ret.Amount
    }
    return nil
}
``` [2](#0-1) 

`RebalanceTreasury` calls both helpers and then executes unconditionally:

```go
// blockchain/system/rebalance.go  lines 276-325
if err = result.fillAllocated(caller, state); err != nil {
    return result, err          // never reached when GetAllocatedCount fails
}
// ... validations pass because totalAllocatedAmount == 0 ≤ totalZeroedAmount ...
for addr := range result.Before.Zeroed {
    state.SetBalance(addr, big.NewInt(0))   // burns every zeroed address
}
for addr, balance := range result.After.Allocated {
    state.SetBalance(addr, balance)          // loop body never executes (empty map)
}
result.Success = true
return result, nil
``` [3](#0-2) 

The caller in `FinalizeState` then logs success and returns `nil`, committing the block:

```go
// kaiax/system/impl/blockstate.go  lines 40-48
rebalanceResult, err := bcsystem.RebalanceTreasury(state, m.Chain, header)
if err != nil {
    logger.Error("failed to execute treasury rebalancing. State not changed", "err", err)
} else {
    logger.Info("successfully executed treasury rebalancing", ...)
}
``` [4](#0-3) 

---

### Impact Explanation

At the KIP-103 or KIP-160 fork block, if `GetAllocatedCount` returns any error (contract not yet deployed at the configured address, ABI mismatch, EVM out-of-gas in the simulation, or any transient backend failure):

1. `fillAllocated` returns `nil` — no error is signalled.
2. `result.After.Allocated` is empty.
3. Validation 4 (`totalZeroedAmount >= totalAllocatedAmount`) passes trivially (0 ≤ anything).
4. Every address in `result.Before.Zeroed` has its balance set to `0` — permanently burned.
5. No new balances are distributed.
6. `result.Success = true` is written; `FinalizeState` logs "successfully executed treasury rebalancing".
7. The block is committed with the corrupted state.

The net effect is an unauthorized, irreversible burn of all treasury zeroed-address balances with zero reallocation — a direct loss of system-managed KAIA funds.

---

### Likelihood Explanation

The trigger is any failure of `GetAllocatedCount` at the exact fork block. Concrete scenarios:

- The `Kip103ContractAddress` / `Kip160ContractAddress` in `ChainConfig` points to an address where the contract is not yet deployed in the state at that block (misconfiguration or deployment race).
- The ABI binding call reverts inside the EVM simulation (e.g., the contract's `getAllocatedCount` function reverts for any reason).
- For KIP-160, the `BlockchainContractBackend` call fails due to a transient state-read error.

Because this is a one-time fork-block event, there is no retry mechanism. The corrupted state is canonical.

---

### Recommendation

Change `fillAllocated` to propagate the error from `GetAllocatedCount`, matching the behaviour of `fillZeroed`:

```go
func (result *rebalanceResult) fillAllocated(contract RebalanceCaller, state *state.StateDB) error {
    numNewbieBigInt, err := contract.GetAllocatedCount(nil)
    if err != nil {
        logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
        return err   // propagate instead of nil
    }
    ...
}
```

Additionally, `FinalizeState` in `kaiax/system/impl/blockstate.go` should propagate the error from `RebalanceTreasury` rather than swallowing it, so that a failed rebalancing causes block processing to fail rather than silently committing an incorrect state.

---

### Proof of Concept

1. Deploy a `TreasuryRebalance` contract whose `getAllocatedCount()` function reverts (or configure `Kip103ContractAddress` to an address with no code).
2. Set `Kip103CompatibleBlock` to block N and populate `Zeroeds` with funded addresses.
3. Mine block N. `fillAllocated` returns `nil`; `RebalanceTreasury` burns all zeroed balances and returns `(result{Success:true}, nil)`.
4. Observe: zeroed addresses have balance 0; no allocated addresses received funds; `FinalizeState` logged "successfully executed treasury rebalancing"; the block is canonical.
5. The burned KAIA is unrecoverable — there is no retry path analogous to `retryDeposit`.

### Citations

**File:** blockchain/system/rebalance.go (L196-212)
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

**File:** blockchain/system/rebalance.go (L276-325)
```go
	if err = result.fillZeroed(caller, state); err != nil {
		return result, err
	}

	// Retrieve 2) Get Allocated
	if err = result.fillAllocated(caller, state); err != nil {
		return result, err
	}

	// Validation 1) Check the target block number
	if blockNum, err := caller.RebalanceBlockNumber(nil); err != nil || blockNum.Cmp(header.Number) != 0 {
		return result, ErrRebalanceIncorrectBlock
	}

	// Validation 2) Check whether status is approved. It should be 2 meaning approved
	if status, err := caller.Status(nil); err != nil || status != 2 {
		return result, ErrRebalanceBadStatus
	}

	// Validation 3) Check approvals from zeroeds
	if err = caller.CheckZeroedsApproved(nil); err != nil {
		return result, err
	}

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

**File:** kaiax/system/impl/blockstate.go (L40-48)
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
```
