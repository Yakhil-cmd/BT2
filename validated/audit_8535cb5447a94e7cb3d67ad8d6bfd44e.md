### Title
Gateway Admits Transactions with Zero L1/L1-Data Gas Price That Fail at Blockifier Execution - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs, crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

Both the stateless and stateful gateway validators check only the `l2_gas.max_price_per_unit` against a market-price threshold, while the blockifier's `check_fee_bounds` enforces minimum prices for **all three** resource types (L1 gas, L2 gas, L1 data gas). A transaction with a valid L2 gas price but zero L1 gas or L1 data gas price passes every gateway admission check and enters the mempool, then fails at blockifier pre-validation during block building — without the sender ever paying fees.

### Finding Description

**Stateless validator** (`StatelessTransactionValidator::validate_resource_bounds`):

```rust
// Only l2_gas price is checked against min_gas_price
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
```

`l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` are never compared to any floor. [1](#0-0) 

**Stateful validator** (`validate_tx_l2_gas_price_within_threshold`):

```rust
// TODO(Arni): Consider running this validation for all gas prices.
fn validate_tx_l2_gas_price_within_threshold(...) {
    match tx_resource_bounds {
        ValidResourceBounds::AllResources(tx_resource_bounds) => {
            let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
            // threshold derived from previous block L2 gas price only
            if tx_l2_gas_price.0 < threshold { return Err(...) }
        }
        ValidResourceBounds::L1Gas(_) => { /* No validation required */ }
    }
}
```

The developer TODO explicitly acknowledges the gap. [2](#0-1) 

**Blockifier `check_fee_bounds`** (called during block building, not gateway):

```rust
ValidResourceBounds::AllResources(...) => {
    vec![
        (L1Gas,     l1_gas_resource_bounds,     ..., *l1_gas_price),
        (L1DataGas, l1_data_gas_resource_bounds, ..., *l1_data_gas_price),
        (L2Gas,     l2_gas_resource_bounds,      ..., *l2_gas_price),
    ]
}
// For each resource:
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
```

All three prices are enforced here, but only when `charge_fee = true` (i.e., `max_possible_fee > 0`). [3](#0-2) 

`check_fee_bounds` is only reached during `perform_pre_validation_stage`, which is called by the batcher during block building — not during gateway admission. [4](#0-3) 

### Impact Explanation

An attacker crafts a transaction:
- `l2_gas = { max_amount: 1, max_price_per_unit: min_gas_price }` — satisfies both stateless and stateful L2 price checks; `max_possible_fee > 0` so `enforce_fee = true`
- `l1_gas = { max_amount: 1, max_price_per_unit: 0 }` — zero price, never checked by gateway
- `l1_data_gas = { max_amount: 0, max_price_per_unit: 0 }`

**Gateway path**: passes `ZeroResourceBounds` (total fee = `min_gas_price > 0`), passes `MaxGasPriceTooLow` (l2 price ≥ floor), passes stateful l2 threshold check → **admitted to mempool**. [5](#0-4) [6](#0-5) 

**Blockifier path**: `l1_gas.max_price_per_unit = 0 < actual_l1_gas_price` (which is `NonzeroGasPrice`, always > 0) → `InsufficientResourceBounds` → **pre-validation failure, no fee charged, transaction discarded**.

The attacker can continuously refill the mempool with such transactions at zero cost, displacing legitimate transactions and degrading block-building throughput.

### Likelihood Explanation

The attack requires no privileged access, no special account, and no on-chain state. Any user can submit a well-formed V3 invoke transaction with zero L1 gas price. The gap is structural and present in every production deployment.

### Recommendation

Extend `validate_resource_bounds` in both the stateless and stateful validators to check `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against their respective market prices, mirroring the existing L2 gas price check. The stateless validator should use a configured floor for L1 and L1-data gas prices; the stateful validator should compare against the previous block's `strk_gas_prices.l1_gas_price` and `strk_gas_prices.l1_data_gas_price`, consistent with how `check_fee_bounds` operates in the blockifier. [7](#0-6) [8](#0-7) 

### Proof of Concept

```
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "version": "0x3",
  "sender_address": "<valid_deployed_account>",
  "calldata": [...],
  "signature": [...],
  "nonce": "<current_nonce>",
  "resource_bounds": {
    "l1_gas":      { "max_amount": "0x1",       "max_price_per_unit": "0x0" },
    "l2_gas":      { "max_amount": "0x1",       "max_price_per_unit": "0x1DCD6500" },  // >= min_gas_price (8e9)
    "l1_data_gas": { "max_amount": "0x0",       "max_price_per_unit": "0x0" }
  },
  "tip": "0x0",
  "paymaster_data": [],
  "account_deployment_data": [],
  "nonce_data_availability_mode": "L1",
  "fee_data_availability_mode": "L1"
}
```

**Expected (broken) result**: Gateway returns `200 OK` with a transaction hash; transaction enters the mempool.

**Actual blockifier result**: When the batcher picks this transaction, `check_fee_bounds` fires `MaxGasPriceTooLow { resource: L1Gas, max_gas_price: 0, actual_gas_price: <block_l1_gas_price> }` → transaction is dropped without fee payment.

Repeat indefinitely to maintain mempool saturation at zero cost.

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L56-88)
```rust
    fn validate_resource_bounds(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        if !self.config.validate_resource_bounds {
            return Ok(());
        }

        let resource_bounds = *tx.resource_bounds();
        // The resource bounds should be positive even without the tip.
        if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
        {
            return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
        }

        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }

        // TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
        if let RpcTransaction::Declare(_) = tx {
        } else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
            return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
                gas_amount: resource_bounds.l2_gas.max_amount,
                max_gas_amount: self.config.max_l2_gas_amount,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L223-243)
```rust
    async fn validate_resource_bounds(
        &self,
        executable_tx: &ExecutableTransaction,
    ) -> StatefulTransactionValidatorResult<()> {
        // Skip this validation during the systems bootstrap phase.
        if self.config.validate_resource_bounds {
            // TODO(Arni): getnext_l2_gas_price from the block header.
            let previous_block_l2_gas_price = self
                .gateway_fixed_block_state_reader
                .get_block_info()
                .await?
                .gas_prices
                .strk_gas_prices
                .l2_gas_price;
            self.validate_tx_l2_gas_price_within_threshold(
                executable_tx.resource_bounds(),
                previous_block_l2_gas_price,
            )?;
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
    fn validate_tx_l2_gas_price_within_threshold(
        &self,
        tx_resource_bounds: ValidResourceBounds,
        previous_block_l2_gas_price: NonzeroGasPrice,
    ) -> StatefulTransactionValidatorResult<()> {
        match tx_resource_bounds {
            ValidResourceBounds::AllResources(tx_resource_bounds) => {
                let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
                    return Err(StarknetError {
                        // We didn't have this kind of an error.
                        code: StarknetErrorCode::UnknownErrorCode(
                            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
                        ),
                        message: format!(
                            "Transaction L2 gas price {tx_l2_gas_price} is below the required \
                             threshold {threshold}.",
                        ),
                    });
                }
            }
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
        }
        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-458)
```rust
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
                    }
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
```

**File:** crates/apollo_gateway_config/src/config.rs (L166-204)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
pub struct StatelessTransactionValidatorConfig {
    // If true, ensures that at least one resource bound (L1, L2, or L1 data) is greater than zero.
    pub validate_resource_bounds: bool,
    // TODO(AlonH): Remove the `min_gas_price` field from this struct and use the one from the
    // versioned constants.
    pub min_gas_price: u128,
    pub max_l2_gas_amount: u64,
    pub max_calldata_length: usize,
    pub max_signature_length: usize,
    pub max_proof_size: usize,

    // Declare txs specific config.
    pub max_contract_bytecode_size: usize,
    pub max_contract_class_object_size: usize,
    pub min_sierra_version: VersionId,
    pub max_sierra_version: VersionId,

    // If true, allows transactions with non-empty proof_facts or proof fields.
    pub allow_client_side_proving: bool,
}

impl Default for StatelessTransactionValidatorConfig {
    fn default() -> Self {
        StatelessTransactionValidatorConfig {
            validate_resource_bounds: true,
            min_gas_price: 8_000_000_000,
            max_l2_gas_amount: 1_210_000_000,
            max_calldata_length: 5000,
            max_signature_length: 4000,
            max_contract_bytecode_size: 81920,
            max_contract_class_object_size: 4089446,
            min_sierra_version: VersionId::new(1, 1, 0),
            max_sierra_version: VersionId::new(1, 9, usize::MAX),
            allow_client_side_proving: true,
            max_proof_size: 480000,
        }
    }
}
```

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
}
```
