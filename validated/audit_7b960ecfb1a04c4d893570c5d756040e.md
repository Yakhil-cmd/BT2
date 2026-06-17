### Title
Blocking L1→L2 Priority Queue: Fatal `notify_l2_asset_tracker` Revert Halts Block Processing Without Recovery - (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

`notify_l2_asset_tracker` in `process_l1_transaction.rs` treats any revert from `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` as a fatal `BootloaderSubsystemError` that immediately halts block processing. Because L1→L2 priority-queue transactions cannot be skipped or invalidated, a single L1 deposit transaction whose amount triggers a revert in `L2AssetTracker` permanently blocks the chain with no recovery path — a direct structural analog to the LayerZero blocking-receiver DoS.

---

### Finding Description

In `process_l1_transaction.rs`, every L1→L2 transaction with a non-zero deposit calls `notify_l2_asset_tracker` up to three times (value mint, operator fee, refund). The function is documented as fatal on failure:

```
/// Failure halts block processing — if the asset tracker reverts, the
/// chain's token accounting would be inconsistent, so we treat it as
/// fatal rather than silently continuing with incorrect bookkeeping.
```

The implementation confirms this:

```rust
if failed {
    return Err(internal_error!(
        "L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"
    ).into());
}
```

This `BootloaderSubsystemError` propagates up through `mint_base_token` → `execute_l1_transaction_and_notify_result` → `process_l1_transaction` → the block tx loop, halting the entire block.

The `amount` passed to `handleFinalizeBaseTokenBridgingOnL2` is derived from `transaction.reserved[0]` (`total_deposited`), which is set by the user on L1. An attacker can craft an L1→L2 transaction with a specific `to_mint` value that causes `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` to revert (e.g., via overflow checks, state-dependent guards, or any revert path in the contract). Because the code explicitly acknowledges that L1 validation may not hold and uses saturating arithmetic elsewhere for resilience, but provides **no equivalent resilience** for the asset-tracker call, this is a structural gap.

The `l1_chain_id` used in the call is read directly from `L2AssetTracker` storage slot 154 with `FORMAL_INFINITE` resources and no error handling:

```rust
let chain_id = system.io.storage_read::<false>(...)
    .expect("must read L2AssetTracker L1_CHAIN_ID");
```

If this slot is zero (uninitialized or misconfigured), `l1_chain_id = 0` is passed to the contract, which may itself trigger a revert in the asset tracker's chain-ID validation logic. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

If `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` reverts for any reason during processing of an L1→L2 priority-queue transaction, the entire block processing halts with a fatal internal error. Since L1 transactions **cannot be invalidated or skipped** (as the codebase itself states: *"invalidating an L1 transaction can halt the chain due to the priority queue"*), the chain is permanently halted with no operator-level recovery mechanism. There is no `forceResumeReceive` equivalent, no skip-and-continue path, and no way to remove the offending transaction from the queue. [4](#0-3) 

---

### Likelihood Explanation

The `L2AssetTracker` is a real deployed contract with its own revert conditions. The `amount` parameter is directly attacker-controlled via `total_deposited` (`transaction.reserved[0]`). Any revert path in `handleFinalizeBaseTokenBridgingOnL2` reachable with a specific amount — including arithmetic overflow guards, state-dependent checks (e.g., `_needToForceSetAssetMigrationOnL2`), or an uninitialized `L1_CHAIN_ID` slot producing `chainId = 0` — is sufficient to trigger the halt. An attacker only needs to submit one L1→L2 transaction with the right parameters. [5](#0-4) 

---

### Recommendation

Apply the same resilience philosophy already used for other L1 transaction edge cases: instead of treating `L2AssetTracker` revert as a fatal block-halting error, implement a nonblocking pattern:

1. **Skip-and-log**: If `handleFinalizeBaseTokenBridgingOnL2` reverts, log the failure and continue processing (accepting that accounting may be imprecise) rather than halting the chain.
2. **Operator recovery hook**: Provide an operator-callable mechanism to re-run or skip a stuck asset-tracker notification, analogous to LayerZero's `forceResumeReceive`.
3. **Defensive `l1_chain_id` handling**: Replace the `.expect("must read L2AssetTracker L1_CHAIN_ID")` with a fallback default (e.g., `U256::ONE`) so an uninitialized slot cannot contribute to a revert. [6](#0-5) 

---

### Proof of Concept

1. Attacker submits an L1→L2 priority-queue transaction with `to_mint = X` where `X` is chosen to make `handleFinalizeBaseTokenBridgingOnL2(l1_chain_id, X - max_fee)` revert inside `L2AssetTracker` (e.g., `X = 0` with `gas_price = 0` so `to_transfer = 0` but `Config::SIMULATION` is true, or a value that triggers an overflow guard in the asset tracker).
2. The bootloader processes the block and reaches `execute_l1_transaction_and_notify_result`.
3. `mint_base_token` → `notify_l2_asset_tracker` is called; `run_single_interaction` returns `CompletedExecution { result: Revert }`.
4. `failed = true`; `notify_l2_asset_tracker` returns `Err(internal_error!("L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2 reverted"))`.
5. This propagates as `BootloaderSubsystemError` through the entire call stack.
6. Block processing halts. The L1 transaction remains at the head of the priority queue and cannot be removed.
7. All subsequent blocks also fail to process, permanently halting the chain. [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L100-104)
```rust
    // Compute resource and fee information, making sure we handle
    // all possible validation errors carefully.
    // L1 transactions cannot be invalidated. Therefore, the following
    // function makes sure L1 transactions are processable even when
    // some checks that should be performed by the L1 don't hold.
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L422-432)
```rust
///
/// Compute and perform some checks on fee/resource parameters.
/// This function handles cases that for L2 transactions would be
/// validation errors, as "invalidating" an L1 transaction can halt
/// the chain (due to the priority queue).
/// Note that the "validation errors" are practically unreachable, as
/// gas_limit, gas_price and gas_per_pubdata are either checked or set
/// by the L1 contracts. We decide to handle these cases as a fallback in
/// case the L1 contracts aren't properly updated to reflect a change in
/// ZKsync OS.
/// The approach is to use saturating arithmetic and emit a system
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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L848-912)
```rust
/// Failure halts block processing — if the asset tracker reverts, the
/// chain's token accounting would be inconsistent, so we treat it as
/// fatal rather than silently continuing with incorrect bookkeeping.
///
/// If no contract is deployed at L2AssetTracker, the call succeeds silently
/// (a call to an empty address returns success with no returndata in EVM).
/// However, we are certain that L2AssetTracker is available after the upgrade.
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
