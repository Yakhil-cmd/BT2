### Title
Fatal Block Halt via `L2AssetTracker` Revert Permanently Locks All Pending L1→L2 Deposits — (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

The ZKsync OS bootloader treats any revert from `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` as a **fatal system error** that halts block processing entirely. Because L1→L2 transactions reside in the L1 priority queue and **cannot be invalidated**, a single revert in `L2AssetTracker` permanently stalls the chain and locks all pending user deposits with no recovery path. This is the direct structural analog to the reported "funds stuck due to single point of failure with no withdrawal mechanism" vulnerability class.

---

### Finding Description

In `process_l1_transaction.rs`, the function `notify_l2_asset_tracker` (lines 855–915) is called for every L1→L2 transaction with `total_deposited > 0` — up to three times per deposit (value mint, operator fee, refund). It calls `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2(uint256,uint256)` at address `0x1000f` with:

- `fromChainId` = value read from `L2AssetTracker` storage slot 154 (the `L1_CHAIN_ID` field)
- `amount` = the deposit amount, derived from the user-controlled `total_deposited` field of the L1→L2 transaction

If this call reverts, the function unconditionally returns a fatal internal error:

```rust
if failed {
    // A revert here means the chain's token accounting would be inconsistent.
    // Treated as a fatal system error — block processing cannot continue.
    return Err(internal_error!(
        "L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"
    )
    .into());
}
```

This error propagates through `mint_base_token` → `process_l1_transaction` → the block runner, causing the entire block to fail. The L1→L2 transaction that triggered it remains in the priority queue and cannot be skipped or invalidated.

The bootloader's own documentation and resilience tests confirm the invariant: *"L1 transactions cannot be invalidated (doing so would halt the chain due to the priority queue)."* The codebase explicitly applies saturating arithmetic and graceful fallbacks for many other L1 transaction edge cases (gas limit below intrinsic, gas price overflow, native per pubdata overflow) to preserve this invariant — but `notify_l2_asset_tracker` failure is the one path that is **not** handled gracefully.

The `l1_chain_id` used in the call is read directly from `L2AssetTracker` storage slot 154 with no fallback:

```rust
let chain_id = system
    .io
    .storage_read::<false>(
        ExecutionEnvironmentType::NoEE,
        &mut inf_resources,
        &L2_ASSET_TRACKER_ADDRESS,
        &l1_chain_id_slot,
    )
    .expect("must read L2AssetTracker L1_CHAIN_ID");
```

If this slot is zero (uninitialized or reset), `fromChainId = 0` is passed to `handleFinalizeBaseTokenBridgingOnL2`. Whether this causes a revert depends on the `L2AssetTracker` contract's validation logic, which is outside the ZKsync OS repository — but the fatal halt path in ZKsync OS is unconditional.

---

### Impact Explanation

- **Chain halt**: block processing cannot be completed; no further transactions (L1 or L2) can be included.
- **Funds permanently locked**: all L1→L2 deposits queued in the priority queue are stuck. The deposited funds are locked on L1 with no mechanism to recover them on L2 or refund them on L1 from the ZKsync OS side.
- **No recovery path**: there is no mechanism in the bootloader to skip a failing L1 transaction, retry with different parameters, or bypass the `L2AssetTracker` call.
- This is the direct analog to the reported vulnerability: funds stuck due to a single point of failure (the `L2AssetTracker` contract) with no withdrawal or recovery mechanism.

---

### Likelihood Explanation

- Every L1→L2 transaction with `total_deposited > 0` triggers this code path.
- The `amount` parameter is user-controlled (via `total_deposited`). If `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` has any amount-dependent validation that can be triggered by specific values, an unprivileged attacker can craft an L1→L2 transaction to halt the chain.
- Even without a deliberate attacker, any bug in `L2AssetTracker` that causes it to revert on specific inputs (e.g., overflow in internal accounting, uninitialized state, access control edge case) would trigger this halt.
- The `l1_chain_id = 0` scenario (uninitialized storage slot) is a concrete, reachable trigger if the `L2AssetTracker` validates the chain ID.
- The design is fragile by construction: a single revert in a non-system-hook EVM contract halts the entire chain with no fallback.

---

### Recommendation

1. **Handle `L2AssetTracker` revert non-fatally**: Log the failure and continue block processing, consistent with how other L1 transaction edge cases are handled (saturating arithmetic, graceful fallbacks). The token accounting inconsistency concern can be addressed by a separate reconciliation mechanism.
2. **Add a circuit-breaker or skip mechanism**: Allow the operator to mark a specific L1 transaction as "skip asset tracker notification" in emergency scenarios, analogous to how other rollups handle stuck priority queue transactions.
3. **Validate `l1_chain_id` before use**: If `read_l1_chain_id` returns zero, treat it as a non-fatal condition rather than passing an invalid chain ID to the asset tracker.
4. **Decouple asset tracker accounting from block liveness**: The asset tracker is an accounting contract, not a consensus-critical system hook. Its failure should not be able to halt the chain.

---

### Proof of Concept

1. An L1→L2 transaction is submitted on L1 with `total_deposited > 0` and a specific `amount` value that causes `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` to revert (e.g., due to an uninitialized `L1_CHAIN_ID` slot returning 0, or an amount-dependent validation in the contract).
2. The bootloader calls `notify_l2_asset_tracker` with `amount = total_deposited` and `l1_chain_id` read from storage slot 154.
3. `run_single_interaction` returns `asset_tracker_result.failed() == true`.
4. `notify_l2_asset_tracker` returns `Err(internal_error!("L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"))` at line 908–911.
5. This error propagates through `mint_base_token` (line 290–309 or 338–359) via the `?` operator.
6. `process_l1_transaction` returns the fatal error; the block runner cannot seal the block.
7. The L1→L2 transaction remains in the priority queue. The chain is halted. All user deposits are locked with no recovery path.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L100-104)
```rust
    // Compute resource and fee information, making sure we handle
    // all possible validation errors carefully.
    // L1 transactions cannot be invalidated. Therefore, the following
    // function makes sure L1 transactions are processable even when
    // some checks that should be performed by the L1 don't hold.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L290-309)
```rust
    mint_base_token::<S, Config>(
        system,
        system_functions,
        memories.reborrow(),
        &pay_to_operator,
        &coinbase,
        l1_chain_id,
        &mut inf_resources,
        tracer,
        validator,
    )
    .map_err(|e| match e.root_cause() {
        RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
            internal_error!("Out of ergs on infinite ergs").into()
        }
        RootCause::Runtime(RuntimeError::FatalRuntimeError(_)) => {
            internal_error!("Out of native on infinite").into()
        }
        _ => e,
    })?;
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L901-911)
```rust
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L921-943)
```rust
fn read_l1_chain_id<S: EthereumLikeTypes>(system: &mut System<S>) -> U256
where
    S::IO: IOSubsystemExt,
{
    // L2AssetTracker storage layout (verified via `forge inspect`):
    //   slots 0-100:   Initializable + OwnableUpgradeable + Ownable2StepUpgradeable
    //   slots 101-150: Ownable2Step __gap
    //   slot 151:      mapping chainBalance
    //   slot 152:      mapping assetMigrationNumber
    //   slot 153:      mapping isAssetRegistered
    //   slot 154:      uint256 L1_CHAIN_ID
    let l1_chain_id_slot = Bytes32::from_u256_be(&U256::from(154));
    let mut inf_resources = S::Resources::FORMAL_INFINITE;
    let chain_id = system
        .io
        .storage_read::<false>(
            ExecutionEnvironmentType::NoEE,
            &mut inf_resources,
            &L2_ASSET_TRACKER_ADDRESS,
            &l1_chain_id_slot,
        )
        .expect("must read L2AssetTracker L1_CHAIN_ID");
    U256::from_be_bytes(chain_id.as_u8_array())
```
