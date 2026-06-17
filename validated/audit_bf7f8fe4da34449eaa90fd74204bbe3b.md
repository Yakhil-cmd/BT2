### Title
`notify_l2_asset_tracker` Revert Treated as Fatal Error Halts Entire Block Processing — (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

Any revert from `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` during L1→L2 deposit processing is unconditionally escalated to a fatal `InternalError` that terminates the entire block processing loop. This means a failure in the token-accounting subsystem (`L2AssetTracker`) halts the unrelated transaction-processing subsystem (the bootloader tx loop), blocking all subsequent L1 and L2 transactions in the block — a direct analog to the Reserve Protocol M-02 pattern where a GnosisTrade failure disabled the entire Broker.

---

### Finding Description

In `notify_l2_asset_tracker`, after calling `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` via `run_single_interaction`, the bootloader checks whether the call failed:

```rust
if failed {
    // A revert here means the chain's token accounting would be inconsistent.
    // Treated as a fatal system error — block processing cannot continue.
    return Err(internal_error!(
        "L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"
    )
    .into());
}
``` [1](#0-0) 

This `BootloaderSubsystemError` (an `InternalError`) propagates up through `mint_base_token` → `process_l1_transaction` → the ZK tx loop. In the tx loop, `TxError::Internal` is not handled per-transaction; it terminates the entire loop:

```rust
Err(TxError::Internal(err)) => {
    system.finish_global_frame(None)?;
    return Err(err);  // terminates the block loop
}
``` [2](#0-1) 

`notify_l2_asset_tracker` is invoked up to three times per L1 deposit transaction — once for the value mint, once for the operator fee, and once for the refund: [3](#0-2) 

Each invocation is a separate block-halting failure point. The call is made with `FORMAL_INFINITE` resources, so resource exhaustion cannot prevent it from executing — but a contract-level revert still propagates as fatal.

The design contrast with per-transaction validation errors is explicit: `TxError::Validation` is caught and the transaction is skipped while the block continues; `TxError::Internal` is not caught and kills the block. [4](#0-3) 

---

### Impact Explanation

If `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` reverts for any reason during an L1→L2 deposit transaction, the entire block processing halts. All remaining transactions in the block — both L1 and L2 — are not processed. The sequencer cannot seal the block until the root cause is resolved. This is a chain-wide denial-of-service: no state transitions can be committed, no withdrawals finalized, no L2 transactions executed, for the duration of the outage.

---

### Likelihood Explanation

The entry path is reachable by any unprivileged actor who can submit an L1→L2 priority transaction with `to_mint > 0` (i.e., any standard L1 deposit). The trigger condition — `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` reverting — depends on the contract's implementation (not in this repository). However:

1. The `L2AssetTracker` is a real deployed EVM contract whose state can be modified by L2 transactions. If any publicly callable function on it can be used to put it into a state where `handleFinalizeBaseTokenBridgingOnL2` reverts (e.g., by manipulating `isAssetRegistered`, `chainBalance`, or migration state), an attacker can exploit this.
2. The call is made as `L2_BASE_TOKEN_ADDRESS` (0x800a) to pass the `onlyBaseTokenHolderOrL2BaseToken` modifier — but the function body can still revert for internal reasons.
3. The `SIMULATION` mode path (`amount == 0 || Config::SIMULATION`) also calls the function unconditionally during simulation, widening the surface. [5](#0-4) 

---

### Recommendation

Decouple the `L2AssetTracker` notification failure from block-level liveness. Options:

1. **Treat the revert as a per-transaction failure**: If `handleFinalizeBaseTokenBridgingOnL2` reverts, revert the L1 transaction (returning it as a failed priority op) rather than propagating a fatal `InternalError`. This mirrors the Reserve Protocol mitigation: isolate the failing subsystem rather than disabling the broader system.

2. **Distinguish revert causes**: Differentiate between a transient contract revert (handle gracefully) and a true system invariant violation (fatal). A revert from a user-influenceable contract state should not be treated identically to an internal consistency failure.

3. **Emit a recoverable error variant**: Introduce a new `TxError` variant (e.g., `AssetTrackerFailure`) that the tx loop handles by skipping the transaction and emitting a system log, rather than terminating the loop.

---

### Proof of Concept

1. Attacker identifies a publicly callable function on `L2AssetTracker` (deployed at `L2_ASSET_TRACKER_ADDRESS`) that, when called, puts the contract into a state where `handleFinalizeBaseTokenBridgingOnL2` reverts (e.g., by manipulating `isAssetRegistered` or `chainBalance` mappings).
2. Attacker submits an L2 transaction to invoke that function.
3. Attacker (or any user) submits an L1→L2 priority transaction with `to_mint > 0`.
4. The bootloader calls `notify_l2_asset_tracker` with the deposit amount.
5. `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` reverts.
6. `notify_l2_asset_tracker` returns `Err(internal_error!(...).into())`.
7. This propagates as `TxError::Internal` in the tx loop, which calls `return Err(err)`, terminating block processing.
8. All remaining transactions in the block are not processed; the block cannot be sealed. [6](#0-5) [7](#0-6)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L836-855)
```rust
/// Notify L2AssetTracker about base token bridging from L1.
///
/// Calls handleFinalizeBaseTokenBridgingOnL2(uint256 _fromChainId, uint256 _amount)
/// as L2_BASE_TOKEN_ADDRESS (0x800a) to pass the onlyBaseTokenHolderOrL2BaseToken modifier.
///
/// This is called separately for each token movement (value mint, operator
/// payment, refund) so that the asset tracker's accounting stays correct even
/// if the main transaction body reverts.
///
/// Resource usage depends on the caller — value-mint tracks native against user resources;
/// operator-fee and refund use FORMAL_INFINITE.
///
/// Failure halts block processing — if the asset tracker reverts, the
/// chain's token accounting would be inconsistent, so we treat it as
/// fatal rather than silently continuing with incorrect bookkeeping.
///
/// If no contract is deployed at L2AssetTracker, the call succeeds silently
/// (a call to an empty address returns success with no returndata in EVM).
/// However, we are certain that L2AssetTracker is available after the upgrade.
fn notify_l2_asset_tracker<'a, S: EthereumLikeTypes + 'a, Config: BasicBootloaderExecutionConfig>(
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L870-876)
```rust
    if amount > U256::ZERO || Config::SIMULATION {
        // Encode calldata for handleFinalizeBaseTokenBridgingOnL2(uint256,uint256):
        // selector 0x03117c8c + abi-encoded (fromChainId, amount)
        let mut calldata = [0u8; 68];
        calldata[0..4].copy_from_slice(&[0x03, 0x11, 0x7c, 0x8c]);
        calldata[4..36].copy_from_slice(&l1_chain_id.to_be_bytes::<32>());
        calldata[36..68].copy_from_slice(&amount.to_be_bytes::<32>());
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L878-912)
```rust
        let failed = resources.with_infinite_ergs(|inf_ergs| {
            let CompletedExecution {
                resources_returned,
                result: asset_tracker_result,
            } = BasicBootloader::<S, ZkTransactionFlowOnlyEOA<S>>::run_single_interaction(
                system,
                system_functions,
                memories,
                &calldata,
                &L2_BASE_TOKEN_ADDRESS,
                &L2_ASSET_TRACKER_ADDRESS,
                inf_ergs.clone(),
                &U256::ZERO,
                true, // should_make_frame - isolate state changes
                tracer,
                validator,
            )?;
            // Overwrite resources inside the closure so that
            // with_infinite_ergs correctly restores ergs afterwards.
            *inf_ergs = resources_returned;
            Ok::<bool, BootloaderSubsystemError>(asset_tracker_result.failed())
        })?;

        if failed {
            system_log!(
                system,
                "L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 failed for amount {amount:?}\n"
            );
            // A revert here means the chain's token accounting would be inconsistent.
            // Treated as a fatal system error — block processing cannot continue.
            return Err(internal_error!(
                "L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"
            )
            .into());
        }
```

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L108-113)
```rust
                        Err(TxError::Internal(err)) => {
                            system_log!(system, "Tx execution result: Internal error = {err:?}\n",);
                            // Finish the frame opened before processing the tx
                            system.finish_global_frame(None)?; // TODO should we use pre_tx_rollback_handle here?
                            return Err(err);
                        }
```

**File:** basic_bootloader/src/bootloader/errors.rs (L132-145)
```rust
#[derive(Debug)]
pub enum TxError {
    /// Failed to validate the transaction,
    /// shouldn't terminate the block execution
    Validation(InvalidTransaction),
    /// Internal error.
    Internal(BootloaderSubsystemError),
}

impl From<BootloaderSubsystemError> for TxError {
    fn from(v: BootloaderSubsystemError) -> Self {
        Self::Internal(v)
    }
}
```
