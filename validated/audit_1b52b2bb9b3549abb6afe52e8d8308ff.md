### Title
Gateway Omits Minimum L1 Gas Price and L1 Data Gas Price Checks, Admitting Transactions That Will Always Fail Execution - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

---

### Summary

The gateway's resource-bounds validation enforces a minimum price floor only for `l2_gas.max_price_per_unit`. The fields `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` are never checked against any minimum in either the stateless or stateful validator. An unprivileged user can submit a transaction with a zero (or sub-threshold) L1 gas price that clears all gateway checks and is admitted to the mempool, yet will always be rejected by the blockifier's `check_fee_bounds` during execution with `MaxGasPriceTooLow`. This is the direct sequencer analog of the CurveSwapper `min_amount = 0` pattern: a missing lower-bound guard on a fee field that the protocol later enforces, causing the admission layer to accept inputs that the execution layer will always reject.

---

### Finding Description

**Stateless validator — only L2 gas price has a floor**

`StatelessTransactionValidator::validate_resource_bounds` applies a `min_gas_price` floor exclusively to `l2_gas.max_price_per_unit`:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { … });
}
``` [1](#0-0) 

No equivalent check exists for `l1_gas.max_price_per_unit` or `l1_data_gas.max_price_per_unit`. The only other guard is the aggregate `max_possible_fee(Tip::ZERO) != Fee(0)` check, which passes as long as any single resource has a non-zero product — so a transaction with `l1_gas.max_price_per_unit = 0`, `l1_data_gas.max_price_per_unit = 0`, but a valid L2 gas bound clears it. [2](#0-1) 

**Stateful validator — L1 gas price threshold check is explicitly absent**

`validate_tx_l2_gas_price_within_threshold` checks only the L2 gas price against the previous block's price. The `L1Gas` arm is a no-op with the comment *"No validation required for legacy transactions"*, and even for `AllResources` transactions only `l2_gas.max_price_per_unit` is tested:

```rust
ValidResourceBounds::L1Gas(_) => {
    // No validation required for legacy transactions.
}
``` [3](#0-2) 

A developer TODO acknowledges the gap: `// TODO(Arni): Consider running this validation for all gas prices.` [4](#0-3) 

**Blockifier enforces the check — but only after admission**

`AccountTransaction::check_fee_bounds` does validate all three gas prices against actual block prices for `AllResources` transactions:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { … });
}
``` [5](#0-4) 

This check runs inside `perform_pre_validation_stage`, which is called during execution — after the transaction has already been admitted to the mempool. The gateway never reaches this code path. [6](#0-5) 

---

### Impact Explanation

Any unprivileged user can submit an `AllResources` invoke transaction with `l1_gas.max_price_per_unit = 0` (or any value below the actual L1 gas price). The transaction:

1. Passes `StatelessTransactionValidator::validate_resource_bounds` — `max_possible_fee > 0` because L2 gas bounds are non-zero; L2 gas price meets `min_gas_price`; no L1 gas price floor exists.
2. Passes `StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` — only L2 gas price is compared to the block threshold.
3. Is admitted to the mempool.
4. Fails during blockifier execution with `TransactionFeeError::InsufficientResourceBounds { MaxGasPriceTooLow { resource: L1Gas } }`.

The gateway's admission decision is wrong: it accepts a transaction that is guaranteed to fail. This matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing**.

---

### Likelihood Explanation

The attack requires no privileges. Any user with a valid account and nonce can craft such a transaction through the standard JSON-RPC `add_transaction` endpoint. The `min_gas_price` config value (default `8_000_000_000`) is public, making it trivial to set L2 gas price just above the floor while setting L1 gas price to zero. [7](#0-6) 

---

### Recommendation

1. **Stateless validator**: Add minimum price checks for `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` analogous to the existing L2 check. A configurable `min_l1_gas_price` and `min_l1_data_gas_price` field (or reuse `min_gas_price`) should be added to `StatelessTransactionValidatorConfig`.

2. **Stateful validator**: Extend `validate_tx_l2_gas_price_within_threshold` to also compare `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the corresponding previous-block prices, resolving the existing TODO comment. This mirrors the blockifier's `check_fee_bounds` logic but at the admission layer. [8](#0-7) 

---

### Proof of Concept

Submit the following `AllResources` invoke transaction via the gateway RPC:

```json
{
  "type": "INVOKE",
  "version": "0x3",
  "sender_address": "<valid_deployed_account>",
  "nonce": "<current_nonce>",
  "resource_bounds": {
    "l1_gas":      { "max_amount": "0x100", "max_price_per_unit": "0x0" },
    "l2_gas":      { "max_amount": "0xF4240", "max_price_per_unit": "0x1DCD65000" },
    "l1_data_gas": { "max_amount": "0x100", "max_price_per_unit": "0x0" }
  },
  "calldata": [...],
  "signature": [...]
}
```

**Expected (correct) behavior**: Gateway rejects with `MaxGasPriceTooLow` for L1 gas.

**Actual behavior**:
- `StatelessTransactionValidator::validate_resource_bounds`: `max_possible_fee > 0` (L2 gas contributes), `l2_gas.max_price_per_unit = 8_000_000_000 >= min_gas_price` → **passes**.
- `StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold`: only L2 gas price checked → **passes**.
- Transaction is **admitted to the mempool**.
- During blockifier execution, `check_fee_bounds` fires `ResourceBoundsError::MaxGasPriceTooLow { resource: L1Gas }` → transaction fails. [9](#0-8) [10](#0-9)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-449)
```rust
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
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

**File:** crates/apollo_gateway_config/src/config.rs (L188-204)
```rust
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
