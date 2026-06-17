### Title
Fatal Block-Halt via Push-Notification Pattern in L1→L2 Deposit Processing — (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

The bootloader's L1→L2 deposit flow uses a **push-payment pattern** to notify the `L2AssetTracker` contract of every token movement. If the `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` call reverts for any reason, the bootloader escalates the failure to a **fatal system error that permanently halts block processing**. This is the direct structural analog of the PromissoryToken `send`-in-a-loop vulnerability: one failing push recipient blocks all subsequent processing.

---

### Finding Description

During every L1→L2 deposit transaction, `process_l1_transaction` calls `mint_base_token` up to **three times** — once for the value mint, once for the operator fee, and once for the refund recipient. Each call internally invokes `notify_l2_asset_tracker`, which pushes a call to `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2(uint256 _fromChainId, uint256 _amount)`. [1](#0-0) 

The function explicitly documents that a revert is fatal: [2](#0-1) 

The three push calls are made sequentially at lines 290–309 (operator fee), 338–359 (refund), and inside `execute_l1_transaction_and_notify_result` (value mint): [3](#0-2) [4](#0-3) 

The `notify_l2_asset_tracker` function passes user-influenced amounts directly as ABI-encoded calldata to the `L2AssetTracker` EVM contract: [5](#0-4) 

The amounts passed are:
- `pay_to_operator = gas_used * gas_price` — partially user-controlled via `gas_price` and `gas_limit`
- `to_refund_recipient = total_deposited - pay_to_operator` — derived from user-supplied `to_mint`
- The value-mint amount — directly from user-supplied `to_mint`

The `L2AssetTracker` is a real EVM Solidity contract (compiled with 0.8.x checked arithmetic). Its `handleFinalizeBaseTokenBridgingOnL2` accumulates deposits into `interopInfo[assetId].totalSuccessfulDepositsFromL1 += _amount`. If this addition overflows (reachable once the cumulative deposit counter approaches `type(uint256).max`), or if any other revert path in the contract is triggered by the user-controlled `amount` or `_fromChainId` parameters, the bootloader propagates the failure as a fatal `internal_error`, halting the entire block.

The test suite itself confirms the three-call structure: [6](#0-5) 

---

### Impact Explanation

**Vulnerability class**: State-transition bug / DoS of block processing.

If an attacker can craft an L1→L2 transaction whose `to_mint`, `gas_price`, or `gas_limit` causes any of the three `handleFinalizeBaseTokenBridgingOnL2` calls to revert, the bootloader returns a fatal `BootloaderSubsystemError` from `process_l1_transaction`. This propagates up through the block execution loop and halts block production. No subsequent L1 transactions in the block can be processed. The operator must either skip the offending transaction (if the sequencer has that capability) or the chain stalls.

Unlike a normal transaction revert (which is isolated), this failure mode bypasses all per-transaction rollback logic because it occurs in the post-execution accounting phase, after the main transaction frame has already been committed or rolled back.

---

### Likelihood Explanation

The `L2AssetTracker` is a Solidity 0.8.x contract with checked arithmetic. The `totalSuccessfulDepositsFromL1` counter is a `uint256` that accumulates across all L1 deposits. An attacker who deposits a sufficiently large amount (or who can trigger any other revert path in `handleFinalizeBaseTokenBridgingOnL2`) can halt block processing. The structural risk is **medium**: the overflow requires an enormous cumulative deposit, but the design pattern itself — treating a push-notification revert as a fatal block error — means any future bug or edge case in `L2AssetTracker` immediately becomes a chain-halting event. The `l1_chain_id` parameter is also read from contract storage and passed through without sanitization, creating additional revert surface if the contract's internal state diverges from expectations. [7](#0-6) 

---

### Recommendation

Replace the push-notification pattern with a pull/lazy accounting model: instead of calling `handleFinalizeBaseTokenBridgingOnL2` synchronously inside block execution, record the deposit amounts in a queue or accumulator that the `L2AssetTracker` can read lazily. If synchronous notification is required, the bootloader should treat a revert from `L2AssetTracker` as a per-transaction failure (skip the notification, mark the transaction as failed) rather than a fatal block-level error. This mirrors the "favor pull payments over push payments" recommendation from the original report.

---

### Proof of Concept

1. Accumulate L1→L2 deposits until `totalSuccessfulDepositsFromL1` in `L2AssetTracker` is near `type(uint256).max`.
2. Submit an L1→L2 transaction with `to_mint` set to a value that causes `totalSuccessfulDepositsFromL1 += to_mint` to overflow (Solidity 0.8.x reverts on overflow).
3. The bootloader calls `notify_l2_asset_tracker` with this amount; `handleFinalizeBaseTokenBridgingOnL2` reverts.
4. `notify_l2_asset_tracker` returns `Err(internal_error!("L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"))`.
5. `process_l1_transaction` propagates this fatal error; the block execution loop halts.
6. All subsequent L1 transactions in the block are never processed.

The three-call structure means the same failure can be triggered by the operator-fee or refund amounts, not only the value-mint amount, giving the attacker multiple vectors with different `amount` values derived from `gas_price * gas_used` and `total_deposited - pay_to_operator`. [8](#0-7) [9](#0-8)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-360)
```rust
    if to_refund_recipient > U256::ZERO {
        let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
        mint_base_token::<S, Config>(
            system,
            system_functions,
            memories.reborrow(),
            &to_refund_recipient,
            &refund_recipient,
            l1_chain_id,
            &mut inf_resources,
            tracer,
            validator,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e.root_cause() {
                RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
                    internal_error!("Out of ergs on infinite ergs").into()
                }
                RootCause::Runtime(RuntimeError::FatalRuntimeError(_)) => {
                    internal_error!("Out of native on infinite").into()
                }
                _ => e,
            }
        })?;
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L741-769)
```rust
fn mint_base_token<'a, S: EthereumLikeTypes + 'a, Config: BasicBootloaderExecutionConfig>(
    system: &mut System<S>,
    system_functions: &mut HooksStorage<S, S::Allocator>,
    memories: RunnerMemoryBuffers<'a>,
    amount: &U256,
    to: &B160,
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
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L836-851)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L855-915)
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
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L917-943)
```rust
/// Reads L1 chain id from L2AssetTracker storage.
///
/// This is the chain tokens are bridged *from* during L1→L2 deposits,
/// passed as `_fromChainId` to `handleFinalizeBaseTokenBridgingOnL2`.
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

**File:** tests/instances/transactions/src/asset_tracker.rs (L1-13)
```rust
//!
//! Tests for the L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 calls
//! that the bootloader makes during L1 transaction processing.
//!
//! When an L1 transaction deposits base tokens (total_deposited > 0), the
//! bootloader calls handleFinalizeBaseTokenBridgingOnL2(uint256, uint256)
//! on the real L2AssetTracker contract up to three times — once for the
//! value mint, once for the operator fee, and once for the refund. If any
//! of these amounts is zero the corresponding call is skipped.
//!
//! When the source chain matches `L1_CHAIN_ID` and the current settlement
//! layer also matches `L1_CHAIN_ID`, the contract records the aggregate
//! bridged amount in `interopInfo[BASE_TOKEN_ASSET_ID].totalSuccessfulDepositsFromL1`.
```
