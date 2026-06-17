### Title
Missing Zero-Address Validation for `refund_recipient` in L1→L2 Transaction Processing Causes Permanent Loss of Refund Funds - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

The `process_l1_transaction` function in ZKsync OS does not validate that the `refund_recipient` field (`reserved[1]`) of an L1→L2 transaction is non-zero before transferring the refund amount to it. When `refund_recipient = address(0)` and a non-zero refund exists, the bootloader silently transfers the refund tokens from the treasury to `address(0)`, permanently destroying them. The `validate_structure` function even contains an explicit `// TODO: validate address?` comment acknowledging this gap.

---

### Finding Description

In `process_l1_transaction.rs`, after computing the refund amount `to_refund_recipient`, the code unconditionally reads `reserved[1]` as the refund recipient and calls `mint_base_token` with it:

```rust
if to_refund_recipient > U256::ZERO {
    let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
    mint_base_token::<S, Config>(
        system,
        system_functions,
        memories.reborrow(),
        &to_refund_recipient,
        &refund_recipient,   // ← can be B160::ZERO
        ...
    )?;
}
```

`mint_base_token` calls `transfer_from_treasury`, which calls `update_account_nominal_token_balance` on the `to` address with no zero-address guard. The treasury balance is decremented and the zero address balance is incremented — the tokens are permanently lost.

The structural validation function `validate_structure` in `abi_encoded/mod.rs` explicitly skips this check:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
    ...
}
```

The `refund_recipient` field defaults to `Address::default()` (i.e., `address(0)`) in the `L1TxBuilder` helper, meaning any L1→L2 transaction that omits this field will silently route its refund to the zero address.

---

### Impact Explanation

**Permanent loss of user funds.** Two concrete loss scenarios:

1. **Unused gas refund lost**: A user submits an L1→L2 transaction with `refund_recipient = address(0)` and a `gas_limit` larger than consumed. The unused gas refund `(gas_limit - gas_used) * gas_price` is transferred from the treasury to `address(0)` and permanently destroyed.

2. **Full deposit lost on revert**: If the L2 transaction body reverts, `to_refund_recipient = total_deposited - pay_to_operator`. With `refund_recipient = address(0)`, the entire deposit minus the operator fee is sent to `address(0)` and permanently lost. This can be a large amount.

In both cases, the treasury is correctly debited but the funds are irrecoverably credited to `address(0)` rather than returned to the user.

---

### Likelihood Explanation

**Medium.** The `L1TxBuilder` defaults `refund_recipient` to `address(0)` when not explicitly set. Any L1→L2 transaction submitted without an explicit refund recipient — whether through a buggy bridge integration, a user mistake, or a contract that omits the field — will silently lose its refund. The `// TODO: validate address?` comment confirms the developers are aware this validation is absent.

---

### Recommendation

1. In `validate_structure` (or in `process_l1_transaction` before the refund transfer), reject any L1→L2 or upgrade transaction where `reserved[1]` decodes to `B160::ZERO` when `reserved[0]` (total deposit) is non-zero.
2. Remove the `// TODO: validate address?` placeholder and replace it with an explicit check: `if self.reserved[1].read() == U256::ZERO { return Err(()); }` for L1/upgrade transaction types with a non-zero deposit.
3. Update `L1TxBuilder::build()` to require an explicit `refund_recipient` rather than defaulting to `address(0)`.

---

### Proof of Concept

**Entry path**: Submit an L1→L2 transaction (type `0x7F`) with:
- `reserved[0]` (to_mint) = `gas_limit * gas_price + 1_000_000` (non-zero deposit)
- `reserved[1]` (refund_recipient) = `0x0000000000000000000000000000000000000000`
- `gas_limit` = 100,000 (much more than needed)
- `gas_price` = 1,000

**Execution trace**:

1. `process_l1_transaction` is called. `total_deposited = reserved[0]`.
2. The L2 body executes and succeeds (or reverts — both paths lead to a non-zero `to_refund_recipient`).
3. `to_refund_recipient = (gas_limit - gas_used) * gas_price` (success case) or `total_deposited - pay_to_operator` (revert case).
4. Since `to_refund_recipient > U256::ZERO`, the code reads `refund_recipient = u256_to_b160_checked(reserved[1]) = B160::ZERO`.
5. `mint_base_token` → `transfer_from_treasury` is called with `to = B160::ZERO`.
6. `update_account_nominal_token_balance` subtracts from treasury and adds to `address(0)` — no revert, no error.
7. The refund amount is permanently lost.

This is directly confirmed by the existing test `test_treasury_based_token_distribution_regression` which uses `refund_recipient = address(0)` and asserts the refund is credited to `address(0)`, demonstrating the path is live and unguarded. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-359)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L741-768)
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
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L776-831)
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
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L267-273)
```rust
        // reserved[1] = refund recipient for l1 to l2 and upgrade txs
        match tx_type {
            Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
                // TODO: validate address?
            }
            _ => unreachable!(),
        }
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```

**File:** tests/rig/src/utils/mod.rs (L409-409)
```rust
            refund_recipient: self.refund_recipient.unwrap_or_default(),
```
