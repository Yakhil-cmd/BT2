### Title
EVM `Heartbeat.heartbeat()` Bypasses `isPaused()` Guard, Mutating EVM State During Pause - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
The `EVM.Heartbeat.heartbeat()` function, called unconditionally every Flow block via the system chunk transaction, invokes `InternalEVM.commitBlockProposal()` without checking `EVM.isPaused()`. This causes EVM state mutations (EVM block height advancement, storage writes, `BlockExecuted` event emissions) to continue even when the EVM is supposed to be in a fully read-only paused state.

### Finding Description
The `EVM` contract in `fvm/evm/stdlib/contract.cdc` implements a pause mechanism via `isPaused()`, which reads a boolean flag from `/storage/evmOperationsPaused`. Every state-mutating user-facing function guards itself with `pre { !EVM.isPaused(): "EVM operations are temporarily paused" }`:

- `EVM.run()` [1](#0-0) 
- `EVM.createCadenceOwnedAccount()` [2](#0-1) 
- `CadenceOwnedAccount.deploy()`, `.call()`, `.withdraw()`, `.depositNFT()`, `.withdrawNFT()`, `.depositTokens()`, `.withdrawTokens()` [3](#0-2) 

However, the `Heartbeat` resource's `heartbeat()` function calls `InternalEVM.commitBlockProposal()` with no pause check:

```cadence
access(all) resource Heartbeat {
    access(all)
    fun heartbeat() {
        InternalEVM.commitBlockProposal()   // no isPaused() check
    }
}
``` [4](#0-3) 

This `heartbeat()` is called every single Flow block by the system chunk transaction:

```cadence
let evmHeartbeat = serviceAccount.storage
    .borrow<&EVM.Heartbeat>(from: /storage/EVMHeartbeat)
evmHeartbeat?.heartbeat()
``` [5](#0-4) 

`commitBlockProposal()` in `handler.go` performs concrete EVM state mutations:
1. Writes the committed block to `LatestBlock` storage
2. Writes a new `LatestBlockProposal` for the next block
3. Emits a `BlockExecuted` event
4. Advances the EVM block height [6](#0-5) 

The `isPaused()` documentation explicitly states: *"The EVM enters a read-only mode, where all EVM state is available for reading, but no state updates are executed."* [7](#0-6) 

This invariant is violated: `commitBlockProposal()` writes EVM state on every Flow block regardless of the pause flag.

### Impact Explanation
When EVM is paused by governance:
- The EVM block height (`block.number` in Solidity) continues to advance with one empty block per Flow block.
- EVM contracts that use `block.number` for time-based logic (vesting schedules, auction deadlines, lock periods, rate limiters) will have their timers continue to tick, potentially allowing time-sensitive operations to expire or unlock during the pause window.
- `BlockExecuted` events are emitted for empty blocks, misleading off-chain indexers and bridges that rely on EVM block events to track state.
- EVM storage (`LatestBlock`, `LatestBlockProposal`) is written when the system is supposed to be fully read-only, violating the governance-intended invariant.

**Impact: Medium** — EVM state is mutated in violation of the pause invariant; time-sensitive EVM contracts are affected.

### Likelihood Explanation
This occurs automatically on every Flow block whenever EVM is paused. No attacker action is required; the system chunk transaction is a protocol-level system call that runs unconditionally. The only prerequisite is that governance has paused EVM, which is the exact scenario where the invariant must hold.

**Likelihood: High** — Triggered automatically every block during any pause period.

### Recommendation
Add an `isPaused()` guard inside `Heartbeat.heartbeat()` so that `commitBlockProposal()` is skipped when EVM is paused:

```cadence
access(all) resource Heartbeat {
    access(all)
    fun heartbeat() {
        if EVM.isPaused() {
            return
        }
        InternalEVM.commitBlockProposal()
    }
}
```

This mirrors the pattern used by all other state-mutating EVM functions and ensures that the pause truly enforces a read-only mode with no EVM state updates.

### Proof of Concept
1. Governance pauses EVM by storing `true` at `/storage/evmOperationsPaused` in the EVM contract account.
2. `EVM.isPaused()` now returns `true`. All user-facing EVM operations revert with `"EVM operations are temporarily paused"`.
3. On every subsequent Flow block, the system chunk transaction executes and calls `evmHeartbeat?.heartbeat()`.
4. `heartbeat()` calls `InternalEVM.commitBlockProposal()` without checking `isPaused()`.
5. `commitBlockProposal()` writes a new `LatestBlock` (with incremented height) and a new `LatestBlockProposal` to EVM storage, and emits a `BlockExecuted` event — all state mutations — despite EVM being paused.
6. An EVM contract with logic `require(block.number < unlockBlock)` will see `block.number` advance during the pause, potentially allowing the lock to expire while the pause was intended to freeze all EVM activity. [8](#0-7) [5](#0-4) [9](#0-8)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L622-625)
```text
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L807-810)
```text
    fun createCadenceOwnedAccount(): @CadenceOwnedAccount {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L828-831)
```text
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1194-1203)
```text
    access(all) resource Heartbeat {
        /// heartbeat calls commit block proposals and forms new blocks
        /// including all the recently executed transactions.
        /// The Flow protocol makes sure to call this function
        /// once per block as a system call.
        access(all)
        fun heartbeat() {
            InternalEVM.commitBlockProposal()
        }
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L1223-1236)
```text
    /// Returns whether EVM transactions have been paused, either for
    /// maintenance or any situation that requires special governance
    /// handling.
    ///
    /// Only the Governance Committee can pause the EVM transactions, with
    /// a multi-sig Cadence transaction. The EVM enters a read-only mode,
    /// where all EVM state is available for reading, but no state updates
    /// are executed.
    access(all)
    view fun isPaused(): Bool {
        return self.account.storage.copy<Bool>(
            from: /storage/evmOperationsPaused
        ) ?? false
    }
```

**File:** fvm/blueprints/scripts/systemChunkTransactionTemplate.cdc (L23-25)
```text
        let evmHeartbeat = serviceAccount.storage
            .borrow<&EVM.Heartbeat>(from: /storage/EVMHeartbeat)
        evmHeartbeat?.heartbeat()
```

**File:** fvm/evm/handler/handler.go (L416-462)
```go
func (h *ContractHandler) CommitBlockProposal() {
	panicOnError(h.commitBlockProposal())
}

func (h *ContractHandler) commitBlockProposal() (err error) {
	defer func() {
		if err == nil {
			// Invalidate drycall cache if EVM state is changed (commitBlockProposal is successful).
			h.invalidateDryCallCache()
		}
	}()

	// load latest block proposal
	bp, err := h.backend.BlockProposal()
	if err != nil {
		return err
	}

	// commit the proposal
	err = h.backend.CommitBlockProposal(bp)
	if err != nil {
		return err
	}

	// emit block executed event
	err = h.emitEvent(events.NewBlockEvent(&bp.Block))
	if err != nil {
		return err
	}

	// report metrics
	h.backend.EVMBlockExecuted(
		len(bp.TxHashes),
		bp.TotalGasUsed,
		types.UnsafeCastOfBalanceToFloat64(bp.TotalSupply),
	)

	// log evm block commitment
	logger := h.backend.Logger()
	logger.Info().
		Uint64("evm_height", bp.Height).
		Int("tx_count", len(bp.TxHashes)).
		Uint64("total_gas_used", bp.TotalGasUsed).
		Uint64("total_supply", bp.TotalSupply.Uint64()).
		Msg("EVM Block Committed")

	return nil
```
