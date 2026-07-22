### Title
`StatelessTransactionValidator::validate_resource_bounds` Applies L2 Gas Price Floor to L1-Gas-Only Transactions, Causing Incorrect Gateway Rejection - (`File: crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` unconditionally checks `resource_bounds.l2_gas.max_price_per_unit` against `config.min_gas_price` (production default: `8_000_000_000`) for every V3 transaction, regardless of whether the transaction uses L2 gas at all. A transaction that legitimately allocates only L1 gas (with `l2_gas.max_price_per_unit = 0`) passes the zero-fee guard but is then rejected with `MaxGasPriceTooLow` because `0 < 8_000_000_000`. This is the direct analog of H-06: the wrong resource type's value is checked during admission, causing valid transactions to be incorrectly blocked at the gateway.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`:

```rust
let resource_bounds = *tx.resource_bounds();
// The resource bounds should be positive even without the tip.
if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0) {
    return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
}

if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
``` [1](#0-0) 

The zero-fee guard at line 66 correctly accepts a transaction with only L1 gas (non-zero `l1_gas` fields, zero `l2_gas` fields), because `max_possible_fee > 0`. However, the immediately following check at line 71 then reads `resource_bounds.l2_gas.max_price_per_unit` — which is `0` for an L1-only transaction — and compares it against `min_gas_price`. Since `0 < 8_000_000_000` is true, the transaction is rejected with `MaxGasPriceTooLow`.

The production default for `min_gas_price` is `8_000_000_000`: [2](#0-1) 

The test suite masks this entirely by using `min_gas_price: 0` in `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING`: [3](#0-2) 

The test case `valid_l1_gas` explicitly documents that a transaction with only L1 gas is a valid input: [4](#0-3) 

But this test only passes because `min_gas_price = 0`. Under the production config (`min_gas_price = 8_000_000_000`), the same transaction would be rejected.

The structural parallel to H-06 is exact:

| DYAD H-06 | Sequencer analog |
|---|---|
| Withdrawing Kerosene checks `getNonKeroseneValue - value` | Submitting L1-only tx checks `l2_gas.max_price_per_unit` |
| Wrong collateral type's value is subtracted | Wrong resource type's price is compared |
| Valid Kerosene withdrawal reverts | Valid L1-gas-only tx rejected at gateway |

### Impact Explanation

Any user submitting a V3 transaction with `l2_gas.max_price_per_unit = 0` and non-zero `l1_gas` bounds will have their transaction rejected at the stateless gateway validation stage with `MaxGasPriceTooLow`, even though the transaction is economically valid and would execute correctly in the blockifier. This is a **High** impact: the gateway/mempool admission path rejects valid transactions before sequencing. [5](#0-4) 

### Likelihood Explanation

The trigger is unprivileged and requires no special access: any user can submit a V3 transaction with only L1 gas bounds. The production config has `validate_resource_bounds: true` and `min_gas_price: 8_000_000_000`, so the bug is active in every production deployment. [6](#0-5) 

The test suite does not catch this because the testing config sets `min_gas_price: 0`, which makes the comparison `0 < 0` false and the check always passes.

### Recommendation

The L2 gas price floor should only be enforced when the transaction actually allocates L2 gas. The fix is to guard the check:

```rust
// Only enforce the L2 gas price floor if the transaction uses L2 gas.
if resource_bounds.l2_gas.max_amount.0 > 0
    && resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price
{
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
```

Alternatively, if the intent is that all V3 transactions must carry L2 gas (making L1-only V3 transactions invalid by protocol design), that invariant should be enforced explicitly and documented, and the test case `valid_l1_gas` should be updated to reflect the expected rejection. The test config should also use the production `min_gas_price` value to prevent future regressions.

### Proof of Concept

```rust
#[test]
fn test_l1_only_tx_rejected_with_production_min_gas_price() {
    let config = StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        min_gas_price: 8_000_000_000, // production default
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    };
    let validator = StatelessTransactionValidator { config };

    // Transaction with only L1 gas, zero L2 gas price — valid by protocol.
    let tx = rpc_tx_for_testing(
        TransactionType::Invoke,
        RpcTransactionArgs {
            resource_bounds: AllResourceBounds {
                l1_gas: NON_EMPTY_RESOURCE_BOUNDS, // non-zero l1 gas
                l2_gas: ResourceBounds::default(), // zero l2 gas price
                l1_data_gas: ResourceBounds::default(),
            },
            ..Default::default()
        },
    );

    // Passes zero-fee guard (l1_gas is non-zero), but fails L2 price check.
    // Expected: Ok(()), Actual: Err(MaxGasPriceTooLow { gas_price: 0, min_gas_price: 8000000000 })
    assert_eq!(validator.validate(&tx), Ok(()));
}
``` [1](#0-0) [7](#0-6)

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

**File:** crates/apollo_gateway_config/src/config.rs (L167-204)
```rust
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

**File:** crates/apollo_node/resources/config_schema.json (L3202-3226)
```json
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": {
    "description": "Minimum gas price for transactions.",
    "privacy": "Public",
    "value": 8000000000
  },
  "gateway_config.static_config.stateless_tx_validator_config.min_sierra_version.major": {
    "description": "The major version of the configuration.",
    "privacy": "Public",
    "value": 1
  },
  "gateway_config.static_config.stateless_tx_validator_config.min_sierra_version.minor": {
    "description": "The minor version of the configuration.",
    "privacy": "Public",
    "value": 1
  },
  "gateway_config.static_config.stateless_tx_validator_config.min_sierra_version.patch": {
    "description": "The patch version of the configuration.",
    "privacy": "Public",
    "value": 0
  },
  "gateway_config.static_config.stateless_tx_validator_config.validate_resource_bounds": {
    "description": "If true, ensures that at least one resource bound (L1, L2, or L1 data) is greater than zero.",
    "pointer_target": "validate_resource_bounds",
    "privacy": "Public"
  },
```
