### Title
Treasury Self-Transfer Causes Incorrect L2AssetTracker Accounting When Refund Recipient Is Treasury Address - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

### Summary
In the L1→L2 transaction processing flow, `transfer_from_treasury` performs a two-step balance update: subtract from the treasury (`BASE_TOKEN_HOLDER_ADDRESS`) then add to the recipient `to`. When `to == BASE_TOKEN_HOLDER_ADDRESS`, the net effect on the treasury balance is zero (self-transfer). However, `notify_l2_asset_tracker` is called **before** the balance update and unconditionally records that `amount` tokens were bridged. This creates a permanent accounting divergence in the L2AssetTracker: it believes tokens were distributed, but the treasury's balance is unchanged.

### Finding Description

In `mint_base_token`, the L2AssetTracker is notified first, then `transfer_from_treasury` is called:

```rust
fn mint_base_token(..., amount: &U256, to: &B160, ...) {
    notify_l2_asset_tracker::<S, Config>(system, ..., *amount, ...)?;  // (1) records amount as bridged
    transfer_from_treasury::<S>(system, amount, to, ...)               // (2) subtract treasury, add to `to`
}
```

Inside `transfer_from_treasury`:

```rust
let treasury_address = &system_hooks::addresses_constants::BASE_TOKEN_HOLDER_ADDRESS;

// Step A: subtract from treasury
system.io.update_account_nominal_token_balance(..., treasury_address, nominal_token_value, true, ...)?;

// Step B: add to `to`
system.io.update_account_nominal_token_balance(..., to, nominal_token_value, false, ...)?;
```

When `to == BASE_TOKEN_HOLDER_ADDRESS`:
- Step A: treasury balance goes from `B` → `B - amount`
- Step B: treasury balance goes from `B - amount` → `B` (same account, net zero)
- But step (1) already told the L2AssetTracker that `amount` tokens were bridged

The refund recipient is read directly from the user-controlled `transaction.reserved[1]` field with no validation:

```rust
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
mint_base_token::<S, Config>(
    system, system_functions, memories.reborrow(),
    &to_refund_recipient,
    &refund_recipient,   // ← user-controlled, no check against BASE_TOKEN_HOLDER_ADDRESS
    ...
)?;
```

### Impact Explanation

The L2AssetTracker (`0x1000f`) accumulates incorrect bridging records. Each such transaction inflates the L2AssetTracker's view of how many tokens have been distributed from the treasury without any corresponding actual balance change. The system's own comments confirm this is critical:

> "Failure halts block processing — if the asset tracker reverts, the chain's token accounting would be inconsistent"

Incorrect L2AssetTracker accounting can:
1. Allow more tokens to be claimed/withdrawn to L1 than the treasury actually disbursed
2. Corrupt total supply tracking used by cross-chain asset migration logic (`_needToForceSetAssetMigrationOnL2`)
3. Cause permanent, irreversible state divergence between on-chain balances and the asset tracker's records

### Likelihood Explanation

Any user who can submit an L1→L2 transaction (a standard, permissionless operation) can trigger this by setting `reserved[1] = 0x0000000000000000000000000000000000010011` (`BASE_TOKEN_HOLDER_ADDRESS`). The attacker maximizes the corrupted amount by using a high `gas_limit` with minimal actual gas consumption, making the refund (`gas_price * (gas_limit - gas_used)`) as large as possible. No privileged access, leaked keys, or external oracle manipulation is required.

### Recommendation

Add a guard in `transfer_from_treasury` (or in the caller before invoking `mint_base_token`) to reject or skip the operation when `to == treasury_address`:

```rust
if to == treasury_address {
    // No-op: self-transfer; do not notify L2AssetTracker either
    return Ok(());
}
```

Alternatively, move the `notify_l2_asset_tracker` call to **after** the balance update and only invoke it when `to != treasury_address`, mirroring the fix pattern from the referenced report.

### Proof of Concept

1. Attacker submits an L1→L2 priority transaction with:
   - `gas_limit = 1_000_000`, `gas_price = 1_000`
   - `reserved[1] = 0x0000000000000000000000000000000000010011` (treasury address as refund recipient)
   - Minimal calldata so `gas_used ≈ 21_000`

2. System executes the transaction. Refund amount = `1_000 * (1_000_000 - 21_000) = 979_000_000` tokens.

3. `mint_base_token` is called with `to = BASE_TOKEN_HOLDER_ADDRESS`, `amount = 979_000_000`:
   - `notify_l2_asset_tracker(979_000_000)` → L2AssetTracker records 979M tokens bridged ✓
   - `transfer_from_treasury(979_000_000, BASE_TOKEN_HOLDER_ADDRESS)`:
     - Treasury: `B - 979_000_000` then `B - 979_000_000 + 979_000_000 = B` (net zero) ✓

4. Result: Treasury balance unchanged, but L2AssetTracker permanently records 979M extra tokens as having been distributed. Repeating this across multiple transactions inflates the discrepancy unboundedly. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L776-834)
```rust
pub fn transfer_from_treasury<'a, S: EthereumLikeTypes + 'a>(
    system: &mut System<S>,
    nominal_token_value: &U256,
    to: &B160,
    resources: &mut S::Resources,
    fee_payment_in_simulation: bool,
) -> Result<(), BootloaderSubsystemError>
where
    S::IO: IOSubsystemExt,
{
    system_log!(
        system,
        "Transferring {nominal_token_value:?} tokens from treasury to {to:?}\n"
    );

    let treasury_address = &system_hooks::addresses_constants::BASE_TOKEN_HOLDER_ADDRESS;

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

    Ok(())
}
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

**File:** system_hooks/src/addresses_constants.rs (L49-52)
```rust
// Treasury contract used for "minting" base tokens on L2
pub const BASE_TOKEN_HOLDER_ADDRESS_LOW: u32 = 0x10011;
pub const BASE_TOKEN_HOLDER_ADDRESS: B160 =
    B160::from_limbs([BASE_TOKEN_HOLDER_ADDRESS_LOW as u64, 0, 0]);
```
