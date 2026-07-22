### Title
Gateway `ZeroResourceBounds` check unconditionally rejects valid client-side proving transactions — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` evaluates whether a transaction's fee is zero by calling `max_possible_fee(Tip::ZERO)`. Client-side proving transactions are **required** to set all `max_price_per_unit` fields to zero (enforced by `validate_zero_fee_resource_bounds`). With all prices zero and tip zero, `max_possible_fee(Tip::ZERO)` always equals `Fee(0)`, so the `ZeroResourceBounds` guard fires and rejects the transaction — before the `allow_client_side_proving` check is ever reached. The `allow_client_side_proving = true` production default is therefore rendered inoperative.

### Finding Description

`validate_resource_bounds` in `StatelessTransactionValidator` performs this check:

```rust
// crates/apollo_gateway/src/stateless_transaction_validator.rs L66-69
if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
{
    return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
}
``` [1](#0-0) 

`max_possible_fee` for `AllResources` is:

```
l1_gas.amount * l1_gas.price
+ l2_gas.amount * (l2_gas.price + tip)
+ l1_data_gas.amount * l1_data_gas.price
``` [2](#0-1) 

For a client-side proving transaction, `validate_zero_fee_resource_bounds` **requires** all three `max_price_per_unit` fields and `tip` to be zero: [3](#0-2) 

With all prices and tip zero, `max_possible_fee(Tip::ZERO)` is always `0` regardless of `max_amount`. The `ZeroResourceBounds` error is therefore always raised for any client-side proving transaction.

The `validate` function calls `validate_resource_bounds` **before** `validate_client_side_proving_allowed`: [4](#0-3) 

So the `allow_client_side_proving` guard is never reached. The test suite confirms this: the client-side proving positive-flow test is forced to use `validate_resource_bounds: false`: [5](#0-4) [6](#0-5) 

The production default has both flags enabled: [7](#0-6) 

Real on-chain client-side proving transactions (from `block_post_0_14_2.json`) confirm the zero-price pattern: [8](#0-7) 

### Impact Explanation

With the production default (`validate_resource_bounds: true`, `allow_client_side_proving: true`), every client-side proving transaction submitted to the gateway is rejected with `ZeroResourceBounds` at the stateless validation stage. The feature is completely non-functional despite being enabled. This matches: **High — Mempool/gateway/RPC admission rejects valid transactions before sequencing.**

### Likelihood Explanation

Any user or integration that submits a client-side proving (INVOKE V3, all prices zero) transaction to a node running the default configuration will receive a rejection. The `allow_client_side_proving` flag is `true` by default and documented as the mechanism to permit these transactions, so operators who enable it have a reasonable expectation it works. The conflict is invisible from configuration alone.

### Recommendation

Move the `ZeroResourceBounds` check **after** the client-side proving detection, or add an explicit exemption: skip the zero-bounds check when the transaction carries non-empty `proof_facts` or `proof` fields (i.e., when it is a client-side proving transaction). Alternatively, the `validate_resource_bounds` guard should be aware of the proving path and evaluate fee-enforcement using the same logic as `enforce_fee` in blockifier — which correctly returns `false` for zero-price transactions.

### Proof of Concept

1. Configure the gateway with defaults: `validate_resource_bounds: true`, `allow_client_side_proving: true`.
2. Submit an INVOKE V3 transaction with `l2_gas.max_amount = 0x5f5e100`, all `max_price_per_unit = 0x0`, `tip = 0x0`, and non-empty `proof_facts`.
3. Observe: the gateway returns `ZeroResourceBounds` error from `validate_resource_bounds` — the `validate_client_side_proving_allowed` check is never reached.
4. Confirm: setting `validate_resource_bounds: false` allows the same transaction through, proving the conflict is between these two flags.

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L64-69)
```rust
        let resource_bounds = *tx.resource_bounds();
        // The resource bounds should be positive even without the tip.
        if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
        {
            return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
        }
```

**File:** crates/starknet_api/src/transaction/fields.rs (L398-413)
```rust
            ValidResourceBounds::AllResources(AllResourceBounds {
                l1_gas,
                l2_gas,
                l1_data_gas,
            }) => l1_gas
                .max_amount
                .saturating_mul(l1_gas.max_price_per_unit)
                .saturating_add(
                    l2_gas
                        .max_amount
                        .saturating_mul(l2_gas.max_price_per_unit.saturating_add(tip.into())),
                )
                .saturating_add(
                    l1_data_gas.max_amount.saturating_mul(l1_data_gas.max_price_per_unit),
                ),
        }
```

**File:** crates/starknet_transaction_prover/src/proving/virtual_snos_prover.rs (L407-423)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L148-159)
```rust
#[case::client_side_proving(
    DEFAULT_VALIDATOR_CONFIG_FOR_TESTING.clone(),
    RpcTransactionArgs { proof_facts: create_valid_proof_facts_for_testing(), proof: Proof::proof_for_testing(), ..Default::default()}
)]
#[case::client_side_proving_disabled(
    StatelessTransactionValidatorConfig {
        allow_client_side_proving: false,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs::default()
)]
#[case::valid_tx(DEFAULT_VALIDATOR_CONFIG_FOR_TESTING.clone(), RpcTransactionArgs::default())]
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

**File:** crates/apollo_starknet_client/resources/reader/block_post_0_14_2.json (L281-295)
```json
            "resource_bounds": {
                "L1_GAS": {
                    "max_amount": "0x0",
                    "max_price_per_unit": "0x0"
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
            "tip": "0x0",
```
