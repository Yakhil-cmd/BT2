### Title
EIP-4844 Blob Gas Fees Collected from Sender but Never Distributed to Operator/Coinbase — (`basic_bootloader/src/bootloader/transaction_flow/`)

### Summary

In both the Ethereum STF (`EthereumTransactionFlow`) and ZK STF (`ZkTransactionFlowOnlyEOA`), EIP-4844 blob gas fees are charged to the transaction sender as part of `fee_to_prepay` during validation, but are never paid to the coinbase/operator in `refund_and_commit_fee`. The blob gas fee is permanently removed from the sender's balance without being credited to any recipient.

### Finding Description

**Step 1 — Fee is charged to sender (includes blob gas fee):**

In the Ethereum STF validation (`validation_impl.rs`), `fee_for_blob_gas` is computed and added to `fee_to_prepay`:

```rust
let fee_for_blob_gas = ... blob_base_fee_per_gas * blob_gas_used ...;
let total_fee = fee_amount_execution_gas.checked_add(fee_for_blob_gas)?;
// ...
let context = EthereumTxContext { fee_to_prepay: total_fee, ... };
``` [1](#0-0) 

In `precharge_fee`, the full `fee_to_prepay` (including blob gas fee) is deducted from the sender: [2](#0-1) 

The same pattern exists in the ZK STF validation: [3](#0-2) 

**Step 2 — Blob gas fee is never distributed in `refund_and_commit_fee`:**

In the Ethereum STF `refund_and_commit_fee`, only execution gas is handled:
- Refund to sender: `tx_gas_price * (tx_gas_limit - gas_used)` — execution gas only
- Coinbase payment: `priority_fee_per_gas * gas_used` — execution gas only [4](#0-3) 

In the ZK STF `refund_and_commit_fee`, the same omission exists:
- Refund: `gas_price * (tx_gas_limit - gas_used)` — execution gas only
- Coinbase: `gas_used * gas_price_for_operator` — execution gas only [5](#0-4) 

Neither function contains any handling of `blob_gas_used` or `fee_for_blob_gas`. The `EthereumTxContext` stores `blob_gas_used` as a field but it is only used for reporting in `after_execution`, never for fee distribution: [6](#0-5) 

**Token accounting imbalance per blob transaction:**

| Party | Change |
|---|---|
| Sender | `-gas_price * gas_limit - fee_for_blob_gas` |
| Sender refund | `+gas_price * (gas_limit - gas_used)` |
| Net sender cost | `gas_price * gas_used + fee_for_blob_gas` |
| Operator receives | `gas_price_for_operator * gas_used` |
| **Blob gas fee** | **permanently lost** |

### Impact Explanation

Every EIP-4844 transaction with blobs causes `fee_for_blob_gas = blob_base_fee_per_gas * num_blobs * GAS_PER_BLOB` tokens to be permanently removed from the sender's balance without being credited to the operator or any other address. The operator is never compensated for blob processing costs. Over time, this causes a deflationary drain on the token supply proportional to blob transaction volume. Unlike Ethereum mainnet where blob fee burning is an explicit protocol mechanism, ZKsync OS has no designated burn address — the tokens simply vanish.

### Likelihood Explanation

Any user submitting an EIP-4844 transaction (type 0x03) with one or more blob versioned hashes triggers this path. The `eip-4844` feature is present in the codebase and blob transactions are validated and accepted. The likelihood is high whenever blob transactions are enabled and used. [7](#0-6) 

### Recommendation

In `refund_and_commit_fee` for both `EthereumTransactionFlow` and `ZkTransactionFlowOnlyEOA`, add explicit handling for the blob gas fee. Either:

1. **Pay blob gas fees to the coinbase/operator** (consistent with how ZKsync OS handles execution gas fees without `burn_base_fee`):
   ```rust
   if context.blob_gas_used > 0 {
       let blob_fee = blob_base_fee * U256::from(context.blob_gas_used);
       // credit coinbase with blob_fee
   }
   ```

2. **Explicitly burn blob gas fees** to a designated zero/burn address, making the intent clear and auditable, consistent with EIP-4844 semantics.

### Proof of Concept

1. Submit an EIP-4844 transaction with `blob_versioned_hashes = [hash]` (1 blob), `blob_base_fee = 1`, `GAS_PER_BLOB = 131072`.
2. `fee_for_blob_gas = 131072` tokens are deducted from sender in `precharge_fee`.
3. After execution, `refund_and_commit_fee` pays only `gas_price * gas_used` to coinbase.
4. The 131072 tokens are never credited anywhere — sender balance decreased, coinbase balance unchanged, total supply decreased by 131072. [8](#0-7) [9](#0-8)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L344-346)
```rust
    // NOTE: it's a special resource - not transaction gas. Will be used to charge fee only
    let blob_gas_used = (blobs.len() as u64) * GAS_PER_BLOB;

```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/validation_impl.rs (L364-413)
```rust
    let fee_for_blob_gas = if blob_gas_used > 0 {
        system_log!(
            system,
            "Blob gas price = {}\n",
            &system.metadata.blob_base_fee_per_gas()
        );

        let (value, of) = u256_mul_by_word(&system.metadata.blob_base_fee_per_gas(), blob_gas_used);
        if of > 0 {
            return Err(internal_error!("blob gas price by blob gas used").into());
        }

        value
    } else {
        U256::ZERO
    };

    debug_assert!(transaction.max_fee_per_gas() >= &effective_gas_price);

    // Balance check - originator must cover fee prepayment plus whatever "value" it would like to send along
    let tx_value = transaction.value();

    let mut total_required_balance = tx_value
        .checked_add(worst_case_fee_amount)
        .ok_or(internal_error!("transaction amount + fee"))?;
    total_required_balance = total_required_balance
        .checked_add(fee_for_blob_gas)
        .ok_or(internal_error!("transaction amount + fee + blob gas"))?;
    if total_required_balance > originator_account_data.nominal_token_balance.0 {
        return Err(TxError::Validation(
            InvalidTransaction::LackOfFundForMaxFee {
                fee: total_required_balance,
                balance: originator_account_data.nominal_token_balance.0,
            },
        ));
    }

    // But the fee to charge is based on current block context, and not worst case of max fee (backward-compatible manner)
    let fee_amount_execution_gas = {
        let (value, of) = u256_mul_by_word(&effective_gas_price, tx_gas_limit);
        if of > 0 {
            return Err(internal_error!("effective gas price by tx gas limit").into());
        }

        value
    };

    let total_fee = fee_amount_execution_gas
        .checked_add(fee_for_blob_gas)
        .ok_or(internal_error!("transaction fee + blob gas"))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L179-190)
```rust
pub struct EthereumTxContext<S: EthereumLikeTypes> {
    pub resources: ResourcesForEthereumTx<S>,
    // pub tx_hash: Bytes32,
    pub fee_to_prepay: U256,
    pub priority_fee_per_gas: U256,
    pub minimal_gas_to_charge: u64,
    pub originator_nonce_to_use: u64,
    pub tx_gas_limit: u64,
    pub gas_used: u64,
    pub blob_gas_used: u64,
    pub tx_level_metadata: EthereumTransactionMetadata<{ MAX_BLOBS_PER_BLOCK }>,
}
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L303-345)
```rust
    fn precharge_fee<Config: BasicBootloaderExecutionConfig>(
        system: &mut System<S>,
        transaction: &Transaction<S::Allocator>,
        context: &mut Self::TransactionContext,
        _tracer: &mut impl Tracer<S>,
    ) -> Result<(), TxError> {
        let from = transaction.from();
        let value = context.fee_to_prepay;

        system_log!(
            system,
            "Will precharge 0x{:040x} with {:?} native tokens for transaction\n",
            from.as_uint(),
            &value
        );

        // let _ = system.get_logger().write_fmt(format_args!(
        //     "Balance of 0x{:040x} before transaction is {}\n",
        //     from.as_uint(),
        //     context
        //     .resources
        //     .main_resources
        //     .with_infinite_ergs(|resources| {
        //         system.io.get_nominal_token_balance(
        //             ExecutionEnvironmentType::NoEE, // out of scope of other interactions
        //             resources,
        //             from,
        //         ).unwrap()
        //     })
        // ));

        context
            .resources
            .main_resources
            .with_infinite_ergs(|resources| {
                system.io.update_account_nominal_token_balance(
                    ExecutionEnvironmentType::NoEE, // out of scope of other interactions
                    resources,
                    from,
                    &value,
                    true,
                    false,
                )
```

**File:** basic_bootloader/src/bootloader/transaction_flow/ethereum/mod.rs (L508-654)
```rust
        if context.tx_gas_limit > context.gas_used {
            system_log!(
                system,
                "Gas price for refund is {:?}\n",
                &context.tx_level_metadata.tx_gas_price
            );

            // refund
            let receiver = transaction.from();
            let refund = context.tx_level_metadata.tx_gas_price
                * U256::from(context.tx_gas_limit - context.gas_used); // can not overflow

            system_log!(
                system,
                "Will refund 0x{:040x} with {:?} native tokens\n",
                receiver.as_uint(),
                &refund
            );

            // let _ = system.get_logger().write_fmt(format_args!(
            //     "Balance of 0x{:040x} before refund is {}\n",
            //     receiver.as_uint(),
            //     context
            //     .resources
            //     .main_resources
            //     .with_infinite_ergs(|resources| {
            //         system.io.get_nominal_token_balance(
            //             ExecutionEnvironmentType::NoEE, // out of scope of other interactions
            //             resources,
            //             receiver,
            //         ).unwrap()
            //     })
            // ));

            let mut inf_resources = S::Resources::FORMAL_INFINITE;
            // First refund the sender
            system
                .io
                .update_account_nominal_token_balance(
                    ExecutionEnvironmentType::NoEE,
                    &mut inf_resources,
                    &receiver,
                    &refund,
                    false,
                    Config::SIMULATION,
                )
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

            // let _ = system.get_logger().write_fmt(format_args!(
            //     "Balance of 0x{:040x} after refund is {}\n",
            //     receiver.as_uint(),
            //     context
            //     .resources
            //     .main_resources
            //     .with_infinite_ergs(|resources| {
            //         system.io.get_nominal_token_balance(
            //             ExecutionEnvironmentType::NoEE, // out of scope of other interactions
            //             resources,
            //             receiver,
            //         ).unwrap()
            //     })
            // ));
        }

        assert!(context.gas_used > 0);

        if context.priority_fee_per_gas.is_zero() == false {
            system_log!(
                system,
                "Gas price for coinbase fee is {:?}\n",
                &context.priority_fee_per_gas
            );

            let fee = context.priority_fee_per_gas * U256::from(context.gas_used); // can not overflow
            let coinbase = system.get_coinbase();

            system_log!(system, "Coinbase's share of fee is {:?}\n", &fee);

            // let _ = system.get_logger().write_fmt(format_args!(
            //     "Balance of coinbase 0x{:040x} before fee collection is {}\n",
            //     coinbase.as_uint(),
            //     context
            //     .resources
            //     .main_resources
            //     .with_infinite_ergs(|resources| {
            //         system.io.get_nominal_token_balance(
            //             ExecutionEnvironmentType::NoEE, // out of scope of other interactions
            //             resources,
            //             &coinbase,
            //         ).unwrap()
            //     })
            // ));

            let mut inf_resources = S::Resources::FORMAL_INFINITE;
            system
                .io
                .update_account_nominal_token_balance(
                    ExecutionEnvironmentType::NoEE,
                    &mut inf_resources,
                    &coinbase,
                    &fee,
                    false,
                    Config::SIMULATION,
                )
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

            // let _ = system.get_logger().write_fmt(format_args!(
            //     "Balance of coinbase 0x{:040x} after fee collection is {}\n",
            //     coinbase.as_uint(),
            //     context
            //     .resources
            //     .main_resources
            //     .with_infinite_ergs(|resources| {
            //         system.io.get_nominal_token_balance(
            //             ExecutionEnvironmentType::NoEE, // out of scope of other interactions
            //             resources,
            //             &coinbase,
            //         ).unwrap()
            //     })
            // ));
        }

        Ok(())
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L400-416)
```rust
    let blobs = if let Some(blobs_list) = transaction.blobs() {
        let tx_max_fee_per_blob_gas = transaction.max_fee_per_blob_gas().ok_or(internal_error!(
            "Tx with blobs must define max_fee_per_blob_gas"
        ))?;

        if &block_base_fee_per_blob_gas > tx_max_fee_per_blob_gas && !Config::SIMULATION {
            return Err(TxError::Validation(
                InvalidTransaction::BlobBaseFeeGreaterThanMaxFeePerBlobGas,
            ));
        }

        match parse_blobs_list::<MAX_BLOBS_PER_BLOCK>(blobs_list) {
            Ok(blobs) => blobs,
            Err(e) => {
                return Err(e);
            }
        }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/validation_impl.rs (L466-491)
```rust
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
