### Title
`StatelessTransactionValidator` skips `max_l2_gas_amount` check for `Declare` transactions, allowing gateway admission bypass — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` enforces the `max_l2_gas_amount` ceiling for `Invoke` and `DeployAccount` transactions but deliberately skips it for `Declare` transactions via an empty `if`-branch with a `TODO` comment. Any unprivileged user can submit a `Declare` transaction whose `l2_gas.max_amount` exceeds the configured gateway limit and have it admitted to the mempool, violating the gateway's own admission invariant.

### Finding Description

In `validate_resource_bounds`, the check reads:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ❌ no check — Declare bypasses max_l2_gas_amount entirely
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
```

The empty `if`-arm for `Declare` is structurally identical to the `isPair = true` pattern in the external report: one transaction type is validated, the other is silently accepted. The `TODO` comment confirms developer awareness of the gap.

The production configuration sets `max_l2_gas_amount = 1_210_000_000`. An attacker submits a `DeclareV3` with `l2_gas.max_amount = 1_210_000_001` (or any value above the limit). The stateless validator passes it. The stateful validator then checks `verify_can_pay_committed_bounds`, which computes `max_possible_fee = max_l2_gas_amount × max_price_per_unit`. As long as the sender's balance covers this product, the transaction clears stateful validation and enters the mempool — despite violating the gateway's explicit admission ceiling.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

A `Declare` transaction with `l2_gas.max_amount` above the configured limit is admitted to the mempool when it should be rejected at the stateless gateway boundary. This:

- Breaks the gateway's admission invariant for resource bounds, which exists to bound per-transaction gas consumption and protect the sequencer from oversized transactions.
- Allows an attacker with sufficient STRK balance to flood the mempool with Declare transactions carrying arbitrarily large (within balance constraints) `max_l2_gas_amount` values, bypassing the operator-configured ceiling entirely.
- Produces an authoritative-looking admission decision (`Ok`) for a transaction that the gateway's own policy marks as invalid.

### Likelihood Explanation

Any unprivileged user can trigger this. No special role, governance access, or privileged key is required — only a valid Sierra class and enough STRK to cover `max_l2_gas_amount × max_price_per_unit`. The `TODO` comment confirms the gap is known and unaddressed.

### Recommendation

Remove the empty `if`-arm and apply the same `max_l2_gas_amount` ceiling to `Declare` transactions:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If `Declare` transactions legitimately require a higher ceiling (e.g., because large Sierra programs consume more L2 gas), introduce a separate `max_l2_gas_amount_declare` config parameter and enforce it explicitly rather than skipping the check entirely.

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = config.max_l2_gas_amount + 1` (e.g., `1_210_000_001`)
   - `l2_gas.max_price_per_unit = min_gas_price` (minimum allowed)
   - A valid Sierra class and sufficient sender balance to cover `max_possible_fee`
2. Submit to the gateway's `add_tx` endpoint.
3. Observe: `StatelessTransactionValidator::validate` returns `Ok(())` — the `max_l2_gas_amount` check is skipped for `Declare`.
4. The transaction proceeds to stateful validation and, if balance is sufficient, enters the mempool.
5. For comparison, submit an identical `RpcInvokeTransactionV3` with the same `l2_gas.max_amount`; it is rejected with `MaxGasAmountTooHigh`.

**Relevant code locations:** [1](#0-0) [2](#0-1) 

The test `valid_l2_gas_amount_on_declare` in the test file explicitly documents and asserts this bypass as expected behavior: [3](#0-2) 

The production config ceiling being bypassed: [4](#0-3)

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

**File:** crates/apollo_node/resources/config_schema.json (L3172-3176)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": {
    "description": "Maximum allowed L2 gas amount for transactions.",
    "privacy": "Public",
    "value": 1210000000
  },
```
