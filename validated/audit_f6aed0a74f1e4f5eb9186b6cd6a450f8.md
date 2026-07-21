### Title
Gateway Stateless Validator Unconditionally Applies `min_gas_price` to L2 Gas Price, Rejecting Valid L1-Only and Client-Side Proving Transactions - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` checks `resource_bounds.l2_gas.max_price_per_unit` against the production `min_gas_price` of 8 Gwei unconditionally — even when `l2_gas.max_amount == 0` (L1-only transactions) or when the protocol explicitly requires `l2_gas.max_price_per_unit == 0` (client-side proving transactions). This causes the gateway to reject every such transaction with `MaxGasPriceTooLow` before it reaches the mempool.

### Finding Description

In `validate_resource_bounds`:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
``` [1](#0-0) 

The production default and the deployed `gateway_config.json` both set `min_gas_price = 8_000_000_000` (8 Gwei): [2](#0-1) [3](#0-2) 

Two classes of fully-valid transactions carry `l2_gas.max_price_per_unit == 0`:

**1. L1-only / L1-data-only transactions.** The `AllResourceBounds` struct defaults unused resource fields to zero. A transaction that only specifies L1 gas bounds has `l2_gas = ResourceBounds::default()` (amount = 0, price = 0). The check `0 < 8_000_000_000` is `true`, so the transaction is rejected. The test suite marks this pattern as valid (`valid_l1_gas`, `valid_l1_data_gas`) but uses `min_gas_price: 0` in the test config, masking the production failure: [4](#0-3) [5](#0-4) 

**2. Client-side proving transactions.** The `validate_zero_fee_resource_bounds` function in the virtual SNOS prover explicitly *requires* all `max_price_per_unit` fields — including `l2_gas.max_price_per_unit` — to be zero, while `l2_gas.max_amount` is non-zero (it is the OS gas limit): [6](#0-5) 

Real on-chain data confirms this pattern (`max_price_per_unit: "0x0"` with non-zero `max_amount`): [7](#0-6) 

The stateless validator runs `validate_resource_bounds` *before* `validate_client_side_proving_allowed`, so client-side proving transactions are rejected at the price check before the proving-specific path is ever reached: [8](#0-7) 

The stateful validator correctly guards its analogous check with a match arm that skips L2 gas price validation when the L2 gas amount is zero (it only fires for `AllResources` and checks the price against the previous block's price, but the stateless check fires first): [9](#0-8) 

### Impact Explanation

Every transaction whose `l2_gas.max_price_per_unit` is zero — including all L1-only, L1-data-only, and client-side proving transactions — is permanently rejected at the stateless gateway with `MaxGasPriceTooLow`. No such transaction can enter the mempool or be sequenced. This is a gateway admission bug that rejects valid transactions before sequencing, matching the **High** impact tier: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The bug is triggered by any unprivileged user submitting a transaction with zero L2 gas price. Client-side proving is an explicitly supported and documented feature (`allow_client_side_proving: true` in production config). The test suite does not catch the issue because all positive-flow tests that exercise L1-only bounds use `min_gas_price: 0` rather than the production value of 8 Gwei. [10](#0-9) 

### Recommendation

Guard the `min_gas_price` check with a condition that skips it when `l2_gas.max_amount == 0`, since a zero-amount resource bound carries no economic meaning for the L2 gas price:

```rust
if resource_bounds.l2_gas.max_amount.0 > 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price
{
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
```

Add a test case that uses the production `min_gas_price` value with L1-only and client-side proving resource bounds to prevent regression.

### Proof of Concept

1. Deploy the sequencer with the production config (`min_gas_price = 8_000_000_000`, `validate_resource_bounds = true`, `allow_client_side_proving = true`).
2. Submit an invoke V3 transaction with:
   ```json
   "resource_bounds": {
     "L1_GAS": { "max_amount": "0x100", "max_price_per_unit": "0x77359400" },
     "L2_GAS": { "max_amount": "0x0",   "max_price_per_unit": "0x0" },
     "L1_DATA_GAS": { "max_amount": "0x0", "max_price_per_unit": "0x0" }
   }
   ```
3. The gateway returns `MaxGasPriceTooLow { gas_price: 0, min_gas_price: 8000000000 }` and rejects the transaction, even though the L1 gas bounds are non-zero and the transaction is economically valid.
4. Repeat with a client-side proving transaction (`proof_facts` and `proof` non-empty, `l2_gas.max_price_per_unit = 0`, `l2_gas.max_amount = 0x5f5e100`): same rejection. [11](#0-10)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L40-48)
```rust
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
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

**File:** crates/apollo_gateway_config/src/config.rs (L188-203)
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
```

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L31-31)
```json
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": 8000000000,
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L54-67)
```rust
static DEFAULT_VALIDATOR_CONFIG_FOR_TESTING: LazyLock<StatelessTransactionValidatorConfig> =
    LazyLock::new(|| StatelessTransactionValidatorConfig {
        validate_resource_bounds: false,
        min_gas_price: 0,
        max_l2_gas_amount: 1_000_000_000,
        max_calldata_length: 10,
        max_signature_length: 1,
        max_proof_size: 10,
        max_contract_bytecode_size: 100_000,
        max_contract_class_object_size: 100_000,
        min_sierra_version: *MIN_SIERRA_VERSION,
        max_sierra_version: *MAX_SIERRA_VERSION,
        allow_client_side_proving: true,
    });
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L70-82)
```rust
#[case::valid_l1_gas(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l1_gas: NON_EMPTY_RESOURCE_BOUNDS,
            ..Default::default()
        },
        ..Default::default()
    }
)]
```

**File:** crates/starknet_transaction_prover/src/proving/virtual_snos_prover.rs (L401-443)
```rust
fn validate_zero_fee_resource_bounds(
    tx: &RpcInvokeTransactionV3,
) -> Result<(), VirtualSnosProverError> {
    let bounds = &tx.resource_bounds;
    let mut violations = Vec::new();

    if bounds.l1_gas.max_price_per_unit != GasPrice(0) {
        violations
            .push(format!("l1_gas.max_price_per_unit = {}", bounds.l1_gas.max_price_per_unit.0));
    }
    if bounds.l2_gas.max_price_per_unit != GasPrice(0) {
        violations
            .push(format!("l2_gas.max_price_per_unit = {}", bounds.l2_gas.max_price_per_unit.0));
    }
    if bounds.l1_data_gas.max_price_per_unit != GasPrice(0) {
        violations.push(format!(
            "l1_data_gas.max_price_per_unit = {}",
            bounds.l1_data_gas.max_price_per_unit.0
        ));
    }
    if tx.tip != Tip(0) {
        violations.push(format!("tip = {}", tx.tip.0));
    }

    if !violations.is_empty() {
        return Err(VirtualSnosProverError::InvalidTransactionInput(format!(
            "Proving is client-side — no fees are charged. The following fields must be zero but \
             were not: [{}]. Set all max_price_per_unit fields and tip to 0x0. Note: max_amount \
             fields are fine to set — l2_gas.max_amount controls the gas limit enforced by the OS \
             (use the value from starknet_estimateFee, or 100000000 as a safe upper bound). \
             l1_gas.max_amount and l1_data_gas.max_amount do not affect OS execution.",
            violations.join(", ")
        )));
    }

    if bounds.l2_gas.max_amount == GasAmount(0) {
        return Err(VirtualSnosProverError::InvalidTransactionInput(
            "l2_gas.max_amount must be non-zero — it is the gas limit enforced by the OS on the \
             transaction. Set this to the value returned by starknet_estimateFee, or use \
             100000000 (0x5f5e100) as a safe upper bound (sufficient for ~1 million Cairo steps)."
                .to_string(),
        ));
    }
```

**File:** crates/apollo_starknet_client/resources/reader/block_post_0_14_3.json (L481-490)
```json
                },
                "L2_GAS": {
                    "max_amount": "0x5f5e100",
                    "max_price_per_unit": "0x0"
                },
                "L1_DATA_GAS": {
                    "max_amount": "0x0",
                    "max_price_per_unit": "0x0"
                }
            },
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
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

**File:** crates/apollo_node/resources/config_schema.json (L3202-3206)
```json
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": {
    "description": "Minimum gas price for transactions.",
    "privacy": "Public",
    "value": 8000000000
  },
```
