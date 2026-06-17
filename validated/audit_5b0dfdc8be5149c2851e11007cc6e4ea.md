### Title
Blob Gas Fees Are Permanently Lost — Not Paid to Operator in ZK Transaction Flow (`basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs`)

---

### Summary

In the ZK transaction flow (`ZkTransactionFlowOnlyEOA`), EIP-4844 blob gas fees are fully deducted from the sender's balance during `precharge_fee`, but are never credited to the operator/coinbase during `refund_and_commit_fee`. The blob gas fee component of `fee_to_prepay` is silently destroyed — it leaves the sender's account and arrives nowhere. This is a direct analog to the Tapioca H-15 pattern: one fee type (blob gas fee) is collected through the same precharge path as execution gas fees, but the distribution step only handles execution gas fees, leaving the blob gas fee permanently unaccounted.

---

### Finding Description

**Step 1 — Precharge collects both fee types together.**

In `validate_and_compute_fee_for_transaction` (ZK path), `fee_to_prepay` is computed as the sum of execution gas fee and blob gas fee: [1](#0-0) 

Both components are bundled into a single `fee_to_prepay` value stored in `TxContextForPreAndPostProcessing`: [2](#0-1) 

**Step 2 — `precharge_fee` deducts the full combined amount from the sender.** [3](#0-2) 

The sender's balance is reduced by `gas_fee_amount + fee_for_blob_gas`.

**Step 3 — `refund_and_commit_fee` only handles execution gas — blob gas fee is never paid out.**

The refund to sender covers only unused execution gas: [4](#0-3) 

The operator payment covers only `gas_used * gas_price_for_operator` (execution gas): [5](#0-4) 

There is no step that pays `fee_for_blob_gas` to the coinbase, to a burn address, or back to the sender. The blob gas fee is simply destroyed.

**Token accounting imbalance per blob transaction:**

| Party | Change |
|---|---|
| Sender | −(`gas_price × gas_limit` + `blob_base_fee × blob_gas_used`) |
| Sender refund | +`gas_price × (gas_limit − gas_used)` |
| Operator | +`gas_used × gas_price_for_operator` |
| **Unaccounted** | **`blob_base_fee × blob_gas_used`** |

The `blob_base_fee × blob_gas_used` amount is permanently lost from the system's token accounting.

**Contrast with the `burn_base_fee` feature flag:** The codebase explicitly models the choice of whether to burn or pay base fees to the operator via a compile-time feature flag: [6](#0-5) 

No equivalent mechanism exists for blob gas fees — they are neither conditionally burned nor paid to the operator. The omission is structural, not a deliberate design choice.

---

### Impact Explanation

For every EIP-4844 blob transaction processed by the ZK bootloader, the blob gas fee paid by the sender is permanently destroyed. The operator receives no compensation for blob data availability costs. This is a protocol-wide loss of funds: the operator's coinbase balance is systematically underpaid relative to what users are charged, and the deficit grows with every blob transaction. The magnitude is `blob_base_fee × GAS_PER_BLOB × num_blobs` per transaction.

---

### Likelihood Explanation

EIP-4844 blob transactions are a standard Ethereum transaction type (type 0x03). Any unprivileged user can submit one. The bug is triggered unconditionally on every blob transaction — no special conditions, no governance, no privileged access required. The entry path is the normal transaction submission flow.

---

### Recommendation

In `refund_and_commit_fee` for the ZK transaction flow, after paying the operator for execution gas, also credit the blob gas fee to the coinbase (or explicitly burn it to a designated burn address if that is the intended design):

```rust
// After paying execution gas to operator:
if context.blob_gas_used > 0 {
    let blob_fee = system.get_blob_base_fee_per_gas()
        .checked_mul(U256::from(context.blob_gas_used))
        .ok_or(internal_error!("blob_base_fee * blob_gas_used"))?;
    // Pay blob fee to coinbase (or burn address)
    system.io.update_account_nominal_token_balance(
        ExecutionEnvironmentType::NoEE,
        resources,
        &coinbase,
        &blob_fee,
        false,
        Config::SIMULATION,
    )?;
}
```

The same fix should be applied to `EthereumTransactionFlow::refund_and_commit_fee` for consistency.

---

### Proof of Concept

1. Submit an EIP-4844 blob transaction with `num_blobs = 1`, `blob_base_fee = 100`, `gas_limit = 21000`, `gas_price = 1000`.
2. `fee_to_prepay = 1000 × 21000 + 100 × 131072 = 21_000_000 + 13_107_200 = 34_107_200`.
3. Sender balance decreases by `34_107_200`.
4. After execution (say `gas_used = 21000`): refund = `1000 × 0 = 0`; operator receives `21000 × 1000 = 21_000_000`.
5. `13_107_200` tokens (the blob gas fee) are unaccounted — not in sender, not in operator, not in any burn address.
6. Verify: `sender_balance_before − sender_balance_after − operator_balance_increase = 13_107_200 ≠ 0`. [7](#0-6) [8](#0-7)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L464-495)
```rust
    // Note: no need to feature gate this part, as for non-EIP4844 transactions
    // num_blobs will be 0.
    let num_blobs = system.metadata.num_blobs();
    // NOTE: it's a special resource - not transaction gas. Will be used to charge fee only
    let blob_gas_used = num_blobs as u64 * GAS_PER_BLOB;
    let fee_for_blob_gas = if blob_gas_used > 0 {
        system_log!(
            system,
            "Blob gas price = {}\n",
            &system.get_blob_base_fee_per_gas()
        );

        let Some(value) = system
            .get_blob_base_fee_per_gas()
            .checked_mul(U256::from(blob_gas_used))
        else {
            return Err(TxError::Validation(
                InvalidTransaction::OverflowPaymentInTransaction,
            ));
        };

        value
    } else {
        U256::ZERO
    };
    let fee_to_prepay = gas_fee_amount
        .checked_add(fee_for_blob_gas)
        .ok_or(internal_error!("gfa+ffbg"))?;

    Ok(TxContextForPreAndPostProcessing {
        resources: tx_resources,
        fee_to_prepay,
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L233-283)
```rust
    fn precharge_fee<Config: BasicBootloaderExecutionConfig>(
        system: &mut System<S>,
        transaction: &Transaction<<S as SystemTypes>::Allocator>,
        context: &mut Self::TransactionContext,
        _tracer: &mut impl Tracer<S>,
    ) -> Result<(), TxError> {
        let from = transaction.from();
        let fee = context.fee_to_prepay;

        system_log!(
            system,
            "Will precharge {:?} native tokens for transaction\n",
            &fee
        );

        // ARCHITECTURE NOTE: Fee payment is split into two phases:
        // 1. Deduct full fee from sender at transaction start (here)
        // 2. Transfer actual payment to operator after execution (in refund_transaction_and_pay_operator)
        // This ensures sender has sufficient funds before execution begins
        context
            .intrinsic_resources
            .with_infinite_ergs(|resources| {
                system.io.update_account_nominal_token_balance(
                    ExecutionEnvironmentType::NoEE,
                    resources,
                    &from,
                    &fee,
                    true,
                    Config::SIMULATION,
                )
            })
            .map_err(|e| match e {
                SubsystemError::LeafUsage(interface_error) => {
                    unreachable!(
                        "balance should be pre-verified, but received error {:?}",
                        interface_error
                    );
                }
                SubsystemError::LeafDefect(internal_error) => internal_error.into(),
                // shouldn't be reachable as we are using infinite resources
                SubsystemError::LeafRuntime(runtime_error) => match runtime_error {
                    RuntimeError::FatalRuntimeError(_) => {
                        TxError::oon_as_validation(out_of_native_resources!().into())
                    }
                    RuntimeError::OutOfErgs(_) => {
                        TxError::Validation(InvalidTransaction::OutOfGasDuringValidation)
                    }
                },
                SubsystemError::Cascaded(cascaded_error) => match cascaded_error {},
            })?;
        Ok(())
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L444-547)
```rust
    fn refund_and_commit_fee<Config: BasicBootloaderExecutionConfig>(
        system: &mut System<S>,
        transaction: &Transaction<<S as SystemTypes>::Allocator>,
        context: &mut Self::TransactionContext,
        _tracer: &mut impl Tracer<S>,
    ) -> Result<(), BootloaderSubsystemError> {
        // here we refund the user, then we will transfer fee to the operator

        if context.tx_gas_limit > context.gas_used {
            system_log!(system, "Gas price for refund is {:?}\n", &context.gas_price);

            // refund
            let refund_recipient = transaction.from();
            let token_to_refund =
                context.gas_price * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow

            // First refund the sender. Routed through `intrinsic_resources` so
            // the native charge (precharged by the intrinsic formula) can be
            // verified under `verify_intrinsic_native`.
            context
                .intrinsic_resources
                .with_infinite_ergs(|resources| {
                    system.io.update_account_nominal_token_balance(
                        ExecutionEnvironmentType::NoEE,
                        resources,
                        &refund_recipient,
                        &token_to_refund,
                        false,
                        Config::SIMULATION,
                    )
                })
                .map_err(|e| match e {
                    // Balance errors can not be cascaded
                    SubsystemError::Cascaded(CascadedError(inner, _)) => match inner {},
                    SubsystemError::LeafUsage(InterfaceError(ie, _)) => match ie {
                        BalanceError::InsufficientBalance => {
                            unreachable!("Cannot be insufficient when incrementing balance")
                        }
                        BalanceError::Overflow => {
                            interface_error!(BootloaderInterfaceError::CantPayRefundOverflow)
                        }
                    },
                    other => wrap_error!(other),
                })?;
        }

        // Next we pay the operator
        // ARCHITECTURE NOTE: Fee payment is split into two phases:
        // 1. Deduct full fee from sender at transaction start (in pay_for_transaction)
        // 2. Transfer actual payment to operator after execution (here)
        // This ensures sender has sufficient funds before execution begins

        // EIP-1559 compatibility: When burn_base_fee is enabled, only priority fees
        // go to the operator. Base fees are effectively "burned" (not transferred anywhere).
        let gas_price_for_operator = if cfg!(feature = "burn_base_fee") {
            let base_fee = system.get_eip1559_basefee();
            // We use saturating arithmetic to allow the caller of this method to
            // allow gas_price < base_fee. This can be used, for example, for
            // transaction simulation
            context.gas_price.saturating_sub(base_fee)
        } else {
            context.gas_price
        };

        system_log!(
            system,
            "Gas price for coinbase fee is {:?}\n",
            &gas_price_for_operator
        );

        let token_to_pay_operator = U256::from(context.gas_used)
            .checked_mul(gas_price_for_operator)
            .ok_or(internal_error!("gu*gpfo"))?;

        let coinbase = system.get_coinbase();
        // Operator payment native is precharged by the intrinsic formula too.
        context
            .intrinsic_resources
            .with_infinite_ergs(|resources| {
                system.io.update_account_nominal_token_balance(
                    ExecutionEnvironmentType::NoEE,
                    resources,
                    &coinbase,
                    &token_to_pay_operator,
                    false,
                    Config::SIMULATION,
                )
            })
            .map_err(|e| match e {
                // Balance errors can not be cascaded
                SubsystemError::Cascaded(CascadedError(inner, _)) => match inner {},
                SubsystemError::LeafUsage(InterfaceError(ie, _)) => match ie {
                    BalanceError::InsufficientBalance => {
                        unreachable!("Cannot be insufficient when incrementing balance")
                    }
                    BalanceError::Overflow => {
                        interface_error!(BootloaderInterfaceError::CantPayOperatorOverflow)
                    }
                },
                other => wrap_error!(other),
            })?;

        Ok(())
    }
```
