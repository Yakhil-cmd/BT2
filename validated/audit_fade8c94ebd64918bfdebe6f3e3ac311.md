### Title
`fillAllocated` silently swallows `GetAllocatedCount` error, enabling treasury rebalancing to burn zeroed balances without redistribution — (`blockchain/system/rebalance.go`)

---

### Summary

In `blockchain/system/rebalance.go`, the `fillAllocated` helper returns `nil` instead of the error when `GetAllocatedCount` fails. This causes `RebalanceTreasury` to proceed with an empty allocation list, burning all zeroed treasury balances without distributing them to the intended recipients — a direct, irreversible KAIA loss at the KIP-103 / KIP-160 fork block.

---

### Finding Description

`RebalanceTreasury` is a two-phase operation:

- **Phase 1 (Execution 1):** zero out ("burn") the balances of all *zeroed* addresses.
- **Phase 2 (Execution 2):** distribute KAIA to all *allocated* addresses.

Both phases are gated by a data-retrieval step that populates `result.Before.Zeroed` and `result.After.Allocated` respectively. The retrieval for zeroed addresses (`fillZeroed`) correctly propagates errors:

```go
// blockchain/system/rebalance.go  lines 196-212
func (result *rebalanceResult) fillZeroed(contract RebalanceCaller, state *state.StateDB) error {
    numRetiredBigInt, err := contract.GetZeroedCount(nil)
    if err != nil {
        logger.Error("Failed to get ZeroedCount from TreasuryRebalance contract", "err", err)
        return err   // ← correct: aborts RebalanceTreasury
    }
    ...
}
```

The retrieval for allocated addresses (`fillAllocated`) does **not**:

```go
// blockchain/system/rebalance.go  lines 215-232
func (result *rebalanceResult) fillAllocated(contract RebalanceCaller, state *state.StateDB) error {
    numNewbieBigInt, err := contract.GetAllocatedCount(nil)
    if err != nil {
        logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
        return nil   // ← BUG: should be `return err`
    }
    ...
}
```

When `GetAllocatedCount` fails, `fillAllocated` returns `nil`, leaving `result.After.Allocated` empty. `RebalanceTreasury` then continues:

```go
// blockchain/system/rebalance.go  lines 276-325
if err = result.fillZeroed(caller, state); err != nil { return result, err }
if err = result.fillAllocated(caller, state); err != nil { return result, err }  // nil returned → no abort

// Validation 4 (KIP-103 only): totalZeroedAmount >= totalAllocatedAmount
// totalAllocatedAmount == 0 (empty map) → always passes

// Execution 1: burn all zeroed balances
for addr := range result.Before.Zeroed {
    state.SetBalance(addr, big.NewInt(0))   // ← treasury funds destroyed
}
// Execution 2: distribute to allocated — empty map, nothing happens

result.Success = true
return result, nil   // ← success returned despite no redistribution
```

`FinalizeState` in `kaiax/system/impl/blockstate.go` additionally swallows any error from `RebalanceTreasury`, but in this path the function returns success, so the block is accepted with the burned-but-unredistributed state.

This is the direct Kaia analog of the zkSync `forceDeployOnAddress` bug: Phase 1 (zeroing / "constructing") completes, Phase 2 (allocation / "constructing → constructed") is silently skipped, and the system is left in a permanently broken intermediate state with no retry opportunity because the fork-block check (`IsKIP103ForkBlock` / `IsKIP160ForkBlock`) fires exactly once.

---

### Impact Explanation

All KAIA held by the zeroed treasury addresses is permanently destroyed. The allocated recipients receive nothing. Because the rebalancing fires at a single, non-repeatable fork block, the loss is irreversible. The corrupted values are the balances of every zeroed address (set to `0`) and every allocated address (unchanged at `0` instead of the intended amount).

---

### Likelihood Explanation

Requires `GetAllocatedCount` to revert while `GetZeroedCount` succeeds and the contract status is `Approved`. Realistic triggers include: the KIP-160 contract address pointing to a contract whose `getAllocatedCount` selector is absent or reverts; a gas-exhaustion edge case inside the ABI call; or a contract upgrade that changes the function selector between the approval and the fork block. The asymmetry with `fillZeroed` (which returns the error) indicates this is an unintentional omission rather than a design choice.

---

### Recommendation

In `blockchain/system/rebalance.go`, change line 219 from `return nil` to `return err`:

```go
if err != nil {
    logger.Error("Failed to get AllocatedCount from TreasuryRebalance contract", "err", err)
    return err   // propagate; abort RebalanceTreasury before any state mutation
}
```

---

### Proof of Concept

1. Deploy a `TreasuryRebalanceV2`-compatible contract at `Kip160ContractAddress` with:
   - `getZeroedCount()` returning 1 (one zeroed address with balance)
   - `getAllocatedCount()` reverting unconditionally
   - `status()` returning `2` (Approved)
   - `rebalanceBlockNumber()` returning the KIP-160 fork block
2. At the KIP-160 fork block, `FinalizeState` calls `RebalanceTreasury`.
3. `fillZeroed` succeeds; `fillAllocated` fails but returns `nil`.
4. All validations pass (`totalAllocatedAmount == 0`).
5. Execution 1 sets the zeroed address balance to `0` — KAIA burned.
6. Execution 2 iterates an empty map — nothing distributed.
7. `result.Success = true`; block is finalized and committed.
8. The zeroed treasury address has lost all its KAIA with no recipient receiving it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** blockchain/system/rebalance.go (L215-232)
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
```

**File:** blockchain/system/rebalance.go (L275-325)
```go
	// Retrieve 1) Get Zeroed
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

**File:** kaiax/system/impl/blockstate.go (L39-49)
```go
	// RebalanceTreasury can modify the global state, so use the current stateDB in-place.
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
