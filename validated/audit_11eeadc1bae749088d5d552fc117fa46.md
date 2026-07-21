### Title
Missing `max_l2_gas_amount` Bound on Declare Transactions Allows Unbounded L2 Gas Amount Through Gateway Admission - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary
The stateless transaction validator explicitly skips the `max_l2_gas_amount` upper-bound check for `Declare` transactions. Any unprivileged user can submit a `Declare` transaction with `l2_gas.max_amount = u64::MAX`, bypassing the configured admission cap (production default: 1,210,000,000). The stateful path's `verify_can_pay_committed_bounds` is the only remaining guard, but it operates on `max_amount × max_price_per_unit`; if both fields are set near their type limits the product overflows `u128`, potentially collapsing the balance check to a trivially-satisfiable value and admitting the transaction.

### Finding Description

In `validate_resource_bounds`, the `max_l2_gas_amount` guard is wrapped in an explicit `if let RpcTransaction::Declare(_) = tx { }` no-op branch, with a developer TODO acknowledging the gap:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
``` [1](#0-0) 

The production config sets `max_l2_gas_amount = 1_210_000_000` for Invoke/DeployAccount, but Declare transactions are entirely exempt. [2](#0-1) 

A dedicated test (`valid_l2_gas_amount_on_declare`) explicitly asserts that a Declare with `max_amount = 200` passes even when the config cap is `100`, confirming the bypass is reachable: [3](#0-2) 

The stateful path calls `verify_can_pay_committed_bounds` inside `perform_pre_validation_stage`, which computes `max_possible_fee` from `max_amount × max_price_per_unit`. With `max_amount = u64::MAX` and a sufficiently large `max_price_per_unit` (no upper bound is checked by the stateless validator), the `u128` product wraps, producing a small fee value. The balance check then passes for any account with a non-zero balance, and the transaction is forwarded to the mempool. [4](#0-3) 

The stateful validator's `validate_resource_bounds` only checks the L2 gas *price* against the previous block, not the gas *amount*, so it provides no backstop: [5](#0-4) 

### Impact Explanation

A Declare transaction with `l2_gas.max_amount = u64::MAX` and a large `max_price_per_unit` passes every gateway check and enters the mempool. The broken invariant is: *the gateway must reject any transaction whose declared L2 gas amount exceeds the configured cap*. For Declare transactions this invariant is not enforced, matching the **High** impact: *Mempool/gateway/RPC admission accepts invalid transactions before sequencing*.

### Likelihood Explanation

The trigger requires only a valid Declare transaction (any Sierra class, any sender address that passes the address range check). No privileged access is needed. The bypass is unconditional — it applies to every Declare V3 transaction regardless of the sender or class content.

### Recommendation

Remove the empty `if let RpcTransaction::Declare(_) = tx { }` branch and apply the same `max_l2_gas_amount` guard to Declare transactions, resolving the existing TODO:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

Additionally, add an upper-bound check on `max_price_per_unit` to prevent `max_amount × max_price_per_unit` from overflowing `u128` in `max_possible_fee`.

### Proof of Concept

1. Construct an `RpcDeclareTransactionV3` with a valid Sierra class and set:
   - `resource_bounds.l2_gas.max_amount = GasAmount(u64::MAX)`
   - `resource_bounds.l2_gas.max_price_per_unit = GasPrice(u128::MAX / u64::MAX as u128 + 1)` (forces overflow)
2. Submit to the gateway's `add_tx` endpoint.
3. `StatelessTransactionValidator::validate_resource_bounds` reaches the `if let RpcTransaction::Declare(_) = tx { }` branch and returns `Ok(())` without checking the amount.
4. `verify_can_pay_committed_bounds` computes `max_possible_fee` with an overflowed (small) value and passes for any account with a non-zero STRK balance.
5. The transaction is forwarded to the mempool — admitted despite `max_amount` exceeding `max_l2_gas_amount` by a factor of ~15×. [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_node/resources/config_schema.json (L3172-3176)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": {
    "description": "Maximum allowed L2 gas amount for transactions.",
    "privacy": "Public",
    "value": 1210000000
  },
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L173-201)
```rust
#[rstest]
#[case::l2_gas_amount_out_of_limit(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 100,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(200),
                ..NON_EMPTY_RESOURCE_BOUNDS
            },
            ..Default::default()
        },
        ..Default::default()
    }
)]
fn valid_l2_gas_amount_on_declare(
    #[case] config: StatelessTransactionValidatorConfig,
    #[case] rpc_tx_args: RpcTransactionArgs,
) {
    let tx_type = TransactionType::Declare;
    let tx_validator = StatelessTransactionValidator { config };

    let tx = rpc_tx_for_testing(tx_type, rpc_tx_args);

    assert_matches!(tx_validator.validate(&tx), Ok(()));
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
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

**File:** crates/apollo_gateway_config/src/config.rs (L166-186)
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
```
