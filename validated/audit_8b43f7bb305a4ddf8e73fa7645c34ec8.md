### Title
Gateway Stateful Validator Checks Only L2 Gas Price Against Previous Block, Admitting Transactions With Unviable L1/L1-Data Gas Prices - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful resource-bounds validation (`validate_tx_l2_gas_price_within_threshold`) compares only the transaction's `l2_gas.max_price_per_unit` against the previous block's L2 gas price. It performs no equivalent check for `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit`. A transaction whose L1 or L1-data gas price is zero (or below the current market rate) passes gateway admission, enters the mempool, and is only rejected later by the blockifier's `check_fee_bounds` during pre-validation — after sequencer resources have been consumed.

### Finding Description

`StatefulTransactionValidator::validate_resource_bounds` reads only `strk_gas_prices.l2_gas_price` from the previous block and delegates to `validate_tx_l2_gas_price_within_threshold`: [1](#0-0) 

That function explicitly skips L1 and L1-data gas price checks, with a developer TODO acknowledging the gap: [2](#0-1) 

The stateless validator similarly only enforces a floor on `l2_gas.max_price_per_unit`: [3](#0-2) 

Neither validator touches `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit`.

The blockifier's `check_fee_bounds` — called only during execution — does check all three prices: [4](#0-3) 

This check is gated on `charge_fee`: [5](#0-4) 

So the blockifier is the only guard, and it fires after the transaction has already been admitted and queued.

### Impact Explanation

Any unprivileged user can submit a V3 (`AllResources`) transaction with:
- `l2_gas.max_price_per_unit` ≥ `min_gas_price` (8 000 000 000 fri, the static floor)
- `l1_gas.max_price_per_unit = 0`
- `l1_data_gas.max_price_per_unit = 0`

This transaction passes both stateless and stateful gateway validation, is accepted into the mempool, and is only rejected at blockifier pre-validation with `ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas, .. }`. The admission invariant — that the gateway rejects transactions that cannot pay for execution — is broken for L1 and L1-data gas dimensions.

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

Trivially reachable. Any caller of the gateway's `add_transaction` RPC endpoint can craft such a transaction. No special privilege, no prior state, no race condition required. The `l1_gas.max_price_per_unit` field defaults to zero in many SDK helpers, making accidental triggering plausible as well.

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or add a parallel function) to also compare `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the previous block's `strk_gas_prices.l1_gas_price` and `strk_gas_prices.l1_data_gas_price`, applying the same `min_gas_price_percentage` multiplier. The existing TODO comment at line 358 already flags this gap: [6](#0-5) 

The `StatefulTransactionValidatorConfig` already carries `min_gas_price_percentage`; the fix is to read all three gas prices from `get_block_info()` and apply the threshold check uniformly. [7](#0-6) 

### Proof of Concept

1. Obtain the current L2 gas price floor (e.g., 8 000 000 000 fri from `StatelessTransactionValidatorConfig::default`).
2. Construct a V3 invoke transaction with:
   ```
   resource_bounds = AllResourceBounds {
       l2_gas: { max_price_per_unit: 8_000_000_000, max_amount: 1_000_000 },
       l1_gas: { max_price_per_unit: 0, max_amount: 1_000_000 },
       l1_data_gas: { max_price_per_unit: 0, max_amount: 1_000_000 },
   }
   ```
3. Submit via the gateway's `add_transaction` endpoint.
4. Observe: stateless validation passes (L2 price ≥ floor, total fee > 0); stateful validation passes (L2 price ≥ previous-block threshold); transaction enters the mempool.
5. At blockifier execution, `check_fee_bounds` fires `ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas }` and the transaction is dropped — after having consumed gateway and mempool resources.

The test at `crates/apollo_gateway/src/stateful_transaction_validator_test.rs` confirms only L2 gas price is exercised in the `validate_resource_bounds` test suite: [8](#0-7)

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L363-367)
```rust
        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L288-328)
```rust
async fn validate_resource_bounds(
    #[case] prev_l2_gas_price: NonzeroGasPrice,
    #[case] min_gas_price_percentage: u8,
    #[case] tx_gas_price_per_unit: GasPrice,
    #[case] expected_result: Result<(), StarknetError>,
) {
    let resource_bounds = ValidResourceBounds::AllResources(AllResourceBounds {
        l2_gas: ResourceBounds { max_price_per_unit: tx_gas_price_per_unit, ..Default::default() },
        ..Default::default()
    });
    let executable_tx = executable_invoke_tx(invoke_tx_args!(resource_bounds));

    let mut mock_gateway_fixed_block = MockGatewayFixedBlockStateReader::new();
    mock_gateway_fixed_block.expect_get_block_info().return_once(move || {
        Ok(BlockInfo {
            gas_prices: GasPrices {
                strk_gas_prices: GasPriceVector {
                    l2_gas_price: prev_l2_gas_price,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
    });

    let stateful_validator: StatefulTransactionValidator<TestStateReader, _> =
        StatefulTransactionValidator {
            config: StatefulTransactionValidatorConfig {
                validate_resource_bounds: true,
                min_gas_price_percentage,
                ..Default::default()
            },
            chain_info: ChainInfo::create_for_testing(),
            state_reader_and_contract_manager: None,
            gateway_fixed_block_state_reader: mock_gateway_fixed_block,
        };

    let result = stateful_validator.validate_resource_bounds(&executable_tx).await;
    assert_eq!(result, expected_result);
}
```
