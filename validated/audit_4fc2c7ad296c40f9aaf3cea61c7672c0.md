### Title
Fatal Block Halt via Reverting `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` Push Notification — (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

The bootloader uses a **push pattern** to notify the `L2AssetTracker` contract for every L1→L2 deposit. If `handleFinalizeBaseTokenBridgingOnL2` reverts for any reason, the bootloader explicitly treats this as a **fatal error that halts all block processing**, rather than handling it gracefully. Any L1→L2 priority transaction with a non-zero deposit that triggers a revert in the `L2AssetTracker` will permanently stall the chain.

---

### Finding Description

In `notify_l2_asset_tracker`, the bootloader pushes a call to `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` up to **three times** per L1→L2 deposit transaction (once for the value mint, once for the operator fee, once for the refund). The function's own documentation explicitly states the fatal consequence:

> "Failure halts block processing — if the asset tracker reverts, the chain's token accounting would be inconsistent, so we treat it as fatal rather than silently continuing with incorrect bookkeeping." [1](#0-0) 

The fatal error is returned as a `BootloaderSubsystemError` from `notify_l2_asset_tracker`: [2](#0-1) 

This error propagates through `mint_base_token` → `process_l1_transaction` → `process_transaction`. In the ZK transaction loop (`tx_loop.rs`), any `TxError::Internal` causes the entire loop to exit with a fatal error — no further transactions in the block can be processed: [3](#0-2) 

The `notify_l2_asset_tracker` call is triggered for every L1→L2 deposit with `total_deposited > 0` or during simulation: [4](#0-3) 

The `mint_base_token` function calls `notify_l2_asset_tracker` before `transfer_from_treasury`, meaning the push notification is the first thing that can fail: [5](#0-4) 

The `l1_chain_id` passed to the call is read directly from `L2AssetTracker` storage slot 154 at runtime: [6](#0-5) 

If this slot returns `0` (e.g., uninitialized state after an upgrade), the `handleFinalizeBaseTokenBridgingOnL2` call may revert inside the contract due to chain-ID mismatch checks, triggering the fatal path.

---

### Impact Explanation

If `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` reverts for any reason — a buggy upgrade, a deregistered asset, a chain-ID mismatch, or any other contract-level revert condition — **every subsequent L1→L2 deposit transaction will cause a fatal block processing error**. The chain cannot produce new blocks containing L1 transactions. Funds already locked in the L1 bridge cannot be finalized on L2. This is a complete chain halt for the L1→L2 deposit path, analogous to the original bug where a reverting recipient locks all payouts permanently.

---

### Likelihood Explanation

The `L2AssetTracker` is an upgradeable system contract. A buggy upgrade, a storage slot corruption, or a governance action that deregisters the base token asset can put the contract into a reverting state. The `handleFinalizeBaseTokenBridgingOnL2` function has multiple internal conditions (asset registration check, chain-ID matching, migration number checks) that can revert. Once the contract is in a reverting state, **any** L1→L2 deposit transaction — submitted by any unprivileged user — will trigger the fatal path. The user does not need to know the contract is broken; they only need to submit a standard L1→L2 deposit.

---

### Recommendation

Replace the fatal-error push pattern with a resilient design:

1. **Do not treat a revert from `L2AssetTracker` as a block-halting fatal error.** Instead, record the failed notification and allow block processing to continue. Emit a system log or event for observability.
2. **Implement a pull/retry mechanism**: store failed notification amounts in a queue that can be replayed by the operator or a subsequent block.
3. **Decouple accounting correctness from liveness**: the chain should not halt because a single system contract reverts. Token accounting inconsistency is a recoverable state; a chain halt is not.

---

### Proof of Concept

**Entry path:**
1. An unprivileged user submits an L1→L2 priority transaction with `total_deposited > 0` (standard bridge deposit).
2. The bootloader calls `process_l1_transaction`, which calls `execute_l1_transaction_and_notify_result`.
3. Inside, `mint_base_token` is called, which calls `notify_l2_asset_tracker`.
4. `notify_l2_asset_tracker` calls `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` via `run_single_interaction`.
5. If the `L2AssetTracker` contract reverts (e.g., asset not registered, chain-ID mismatch after upgrade), `asset_tracker_result.failed()` returns `true`.
6. The bootloader returns `Err(internal_error!("L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"))`.
7. This propagates as `TxError::Internal` to `tx_loop.rs`, which executes `return Err(err)` at line 112, terminating block processing entirely.
8. No further transactions — L1 or L2 — can be included in the block. The chain is halted. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L288-309)
```rust
    let coinbase = system.get_coinbase();
    // Mint operator fee portion of the deposit to coinbase.
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L757-768)
```rust
    notify_l2_asset_tracker::<S, Config>(
        system,
        system_functions,
        memories,
        *amount,
        l1_chain_id,
        resources,
        tracer,
        validator,
    )?;

    transfer_from_treasury::<S>(system, amount, to, resources, Config::SIMULATION)
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L855-914)
```rust
fn notify_l2_asset_tracker<'a, S: EthereumLikeTypes + 'a, Config: BasicBootloaderExecutionConfig>(
    system: &mut System<S>,
    system_functions: &mut HooksStorage<S, S::Allocator>,
    memories: RunnerMemoryBuffers<'a>,
    amount: U256,
    l1_chain_id: U256,
    resources: &mut S::Resources,
    tracer: &mut impl Tracer<S>,
    validator: &mut impl TxValidator<S>,
) -> Result<(), BootloaderSubsystemError>
where
    S::IO: IOSubsystemExt,
    S::Metadata: ZkSpecificPricingMetadata
        + BasicMetadata<S::IOTypes, TransactionMetadata = TxLevelMetadata<S::IOTypes>>,
{
    if amount > U256::ZERO || Config::SIMULATION {
        // Encode calldata for handleFinalizeBaseTokenBridgingOnL2(uint256,uint256):
        // selector 0x03117c8c + abi-encoded (fromChainId, amount)
        let mut calldata = [0u8; 68];
        calldata[0..4].copy_from_slice(&[0x03, 0x11, 0x7c, 0x8c]);
        calldata[4..36].copy_from_slice(&l1_chain_id.to_be_bytes::<32>());
        calldata[36..68].copy_from_slice(&amount.to_be_bytes::<32>());

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
    }
    Ok(())
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

**File:** basic_bootloader/src/bootloader/block_flow/zk/tx_loop.rs (L107-113)
```rust
                    match tx_result {
                        Err(TxError::Internal(err)) => {
                            system_log!(system, "Tx execution result: Internal error = {err:?}\n",);
                            // Finish the frame opened before processing the tx
                            system.finish_global_frame(None)?; // TODO should we use pre_tx_rollback_handle here?
                            return Err(err);
                        }
```
