### Title
L2AssetTracker Accounting Updated Before Treasury Transfer With No Rollback on Failure in Post-Execution L1 Mints — (`basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

In `mint_base_token`, `notify_l2_asset_tracker` is called **before** `transfer_from_treasury`. For post-execution L1 transaction operations (operator fee and refund mints), there is no enclosing global frame. If `transfer_from_treasury` fails after `notify_l2_asset_tracker` has already committed its state changes, the L2AssetTracker permanently records a deposit that never actually occurred, creating an irrecoverable accounting discrepancy between the asset tracker's view and the actual token balances.

---

### Finding Description

`mint_base_token` is called up to three times per L1 transaction: once for the value mint (inside a global frame), once for the operator fee, and once for the refund. The latter two are post-execution and run outside any enclosing global frame. [1](#0-0) 

Inside `mint_base_token`, the ordering is:

1. **`notify_l2_asset_tracker`** — calls `L2AssetTracker.handleFinalizeBaseTokenBridgingOnL2` in an isolated inner frame (`should_make_frame = true`). On success, the frame is committed and the L2AssetTracker state change is **permanent** in the current execution context. [2](#0-1) 

2. **`transfer_from_treasury`** — performs a two-step balance update: first debits the treasury, then credits the recipient. [3](#0-2) 

Within `transfer_from_treasury` itself there is a second non-atomic hazard: if the treasury debit (line 793–811) succeeds but the recipient credit (line 813–831) fails with `MintingBalanceOverflow`, the treasury is permanently debited without the recipient being credited — tokens are destroyed. [4](#0-3) 

For the **operator fee** and **refund** mints, these calls happen after the main transaction frame has already been committed or rolled back: [5](#0-4) [6](#0-5) 

There is no outer `start_global_frame` / `finish_global_frame` wrapping these post-execution calls. When `transfer_from_treasury` returns an error, the error propagates and block processing halts, but the L2AssetTracker state change from step 1 is already committed and cannot be undone.

The code comment acknowledges the one-sided concern (asset tracker failure) but does not address the reverse case: [7](#0-6) 

---

### Impact Explanation

Two distinct impacts:

**Impact A — L2AssetTracker over-counts deposits (accounting discrepancy):**  
If `transfer_from_treasury` fails for any reason after `notify_l2_asset_tracker` has committed, the L2AssetTracker's `totalSuccessfulDepositsFromL1` is permanently inflated. Any cross-chain logic, interoperability contracts, or migration checks that rely on this value will operate on incorrect data. This is a direct state-transition accounting bug.

**Impact B — Permanent token destruction (treasury debited, recipient not credited):**  
If the treasury debit in `transfer_from_treasury` succeeds but the recipient credit fails with `MintingBalanceOverflow`, tokens are permanently removed from the treasury without being credited anywhere. The total circulating supply decreases irreversibly.

In both cases, block processing halts, constituting a liveness failure for the entire block.

---

### Likelihood Explanation

**For Impact A (`TreasuryTransferFailed` path):** The treasury (`BASE_TOKEN_HOLDER_ADDRESS`) must have insufficient balance at the time of the operator fee or refund mint. This is a realistic system-level condition if the treasury is depleted by a sequence of large L1 deposits within a single block. An attacker who can submit many large-value L1 transactions could drain the treasury and trigger this condition on a subsequent transaction in the same block.

**For Impact B (`MintingBalanceOverflow` path):** The refund recipient is `transaction.reserved[1]`, which is set by the L1 transaction sender: [8](#0-7) 

An attacker who controls an address with balance near `U256::MAX` can set it as the refund recipient. While pre-funding an address to near `U256::MAX` is practically very difficult, it is not impossible in a chain where the base token has been minted extensively. The operator fee recipient (coinbase) is not attacker-controlled, reducing that vector's likelihood.

Overall likelihood: **Medium** for Impact A (treasury depletion is a realistic operational condition); **Low** for Impact B (requires near-max balance).

---

### Recommendation

1. **Wrap post-execution mints in a global frame.** The operator fee and refund `mint_base_token` calls should be enclosed in a `start_global_frame` / `finish_global_frame` pair so that if `transfer_from_treasury` fails, the L2AssetTracker state change is rolled back atomically.

2. **Make `transfer_from_treasury` atomic.** If the treasury debit succeeds but the recipient credit fails, the treasury debit must be reversed before returning the error. Either use a single atomic transfer primitive, or explicitly undo the debit on credit failure.

3. **Reorder operations.** Consider calling `transfer_from_treasury` first and only calling `notify_l2_asset_tracker` after the transfer has succeeded, matching the principle that accounting should only be updated after the underlying operation is confirmed.

---

### Proof of Concept

**Trigger path for Impact A (L2AssetTracker over-count):**

1. Submit a block containing many L1 transactions with large `total_deposited` values, each consuming treasury balance via `transfer_from_treasury`.
2. Arrange for the treasury balance to be exactly sufficient for the value mints but insufficient for the final transaction's operator fee mint.
3. For that final transaction:
   - `execute_l1_transaction_and_notify_result` completes (value mint inside global frame succeeds or is rolled back cleanly).
   - `mint_base_token` is called for the operator fee (post-execution, no outer frame).
   - `notify_l2_asset_tracker` succeeds → L2AssetTracker records `pay_to_operator` as a successful deposit.
   - `transfer_from_treasury` fails with `TreasuryTransferFailed` → error propagates.
   - Block processing halts.
   - **Result:** L2AssetTracker has permanently recorded a deposit of `pay_to_operator` that never occurred. Treasury balance is unchanged (debit failed), but the asset tracker's accounting is inflated. [9](#0-8) [10](#0-9)

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L793-831)
```rust
    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            treasury_address,
            nominal_token_value,
            true, // true = subtract from balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Treasury transfer failed: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::TreasuryTransferFailed)
                }
                _ => wrap_error!(e),
            }
        })?;

    let _ = system
        .io
        .update_account_nominal_token_balance(
            zk_ee::execution_environment_type::ExecutionEnvironmentType::EVM,
            resources,
            to,
            nominal_token_value,
            false, // false = add to balance
            fee_payment_in_simulation,
        )
        .map_err(|e| -> BootloaderSubsystemError {
            match e {
                SubsystemError::LeafUsage(balance_error) => {
                    system_log!(system, "Error while minting: {balance_error:?}");
                    interface_error!(BootloaderInterfaceError::MintingBalanceOverflow)
                }
                _ => wrap_error!(e),
            }
        })?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L848-854)
```rust
/// Failure halts block processing — if the asset tracker reverts, the
/// chain's token accounting would be inconsistent, so we treat it as
/// fatal rather than silently continuing with incorrect bookkeeping.
///
/// If no contract is deployed at L2AssetTracker, the call succeeds silently
/// (a call to an empty address returns success with no returndata in EVM).
/// However, we are certain that L2AssetTracker is available after the upgrade.
```
