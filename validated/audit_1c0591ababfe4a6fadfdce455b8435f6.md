### Title
Gateway Stateless Validator Unconditionally Rejects Transactions With Zero L2 Gas Price, Blocking Valid L1-Only-Bounded Transactions - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies the `min_gas_price` floor check unconditionally to `l2_gas.max_price_per_unit`, even when a transaction carries only L1 or L1-data gas bounds and legitimately sets `l2_gas.max_price_per_unit = 0`. In production the default `min_gas_price` is `8_000_000_000`; any such transaction is permanently rejected at the gateway with `MaxGasPriceTooLow`. The unit test that is supposed to prove the opposite (`valid_l1_gas`) silently masks the defect by running against a test-only config that sets `min_gas_price: 0`.

### Finding Description

`validate_resource_bounds` in `stateless_transaction_validator.rs` performs two sequential checks:

1. Reject if the total max-possible fee across all three resources is zero.
2. Reject if `resource_bounds.l2_gas.max_price_per_unit < self.config.min_gas_price`.

Check 2 is unconditional — it fires regardless of whether the transaction actually allocates any L2 gas. A transaction that sets only `l1_gas` (or only `l1_data_gas`) with a non-zero amount and price will have `l2_gas.max_price_per_unit = 0` (the `Default` value). In production the config default is `min_gas_price: 8_000_000_000`, so `0 < 8_000_000_000` is always true and the transaction is always rejected.

```rust
// crates/apollo_gateway/src/stateless_transaction_validator.rs  lines 71-76
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
        gas_price: resource_bounds.l2_gas.max_price_per_unit,
        min_gas_price: self.config.min_gas_price,
    });
}
```

The production default:

```rust
// crates/apollo_gateway_config/src/config.rs  lines 191-192
min_gas_price: 8_000_000_000,
```

The test that is supposed to cover this case uses `min_gas_price: 0`, so it never exercises the production path:

```rust
// crates/apollo_gateway/src/stateless_transaction_validator_test.rs  lines 54-57
static DEFAULT_VALIDATOR_CONFIG_FOR_TESTING: LazyLock<StatelessTransactionValidatorConfig> =
    LazyLock::new(|| StatelessTransactionValidatorConfig {
        validate_resource_bounds: false,
        min_gas_price: 0,   // ← masks the production defect
```

The `valid_l1_gas` positive-flow test case overrides only `validate_resource_bounds: true` while inheriting `min_gas_price: 0`, so it passes even though the same transaction would be rejected in production.

### Impact Explanation

Any `AllResourceBounds` V3 transaction that legitimately omits L2 gas (sets `l2_gas.max_price_per_unit = 0`) is permanently blocked at the stateless gateway before it can reach the stateful validator, the mempool, or the blockifier. This includes:

- Transactions that pay only in L1 gas (valid under the Starknet V3 spec).
- Client-side proving transactions, which the prover explicitly requires to have all `max_price_per_unit` fields set to zero (`validate_zero_fee_resource_bounds` in `virtual_snos_prover.rs` lines 401–445).

The gateway claims to support such transactions (the positive-flow test `valid_l1_gas` exists and passes), but in production they are always rejected. This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

The defect is triggered by any user or wallet that submits a V3 transaction with only L1 gas bounds, which is a documented valid transaction shape. The production config is the default and is deployed as-is. The masking test config (`min_gas_price: 0`) means the defect has never been caught by CI.

### Recommendation

Guard the L2 gas price floor check so it only fires when the transaction actually allocates L2 gas:

```rust
if resource_bounds.l2_gas.max_amount.0 > 0 || resource_bounds.l2_gas.max_price_per_unit.0 > 0 {
    if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
        return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
    }
}
```

Additionally, add a positive-flow test that uses the production-default `min_gas_price` value with a transaction that carries only L1 gas bounds, to prevent regression.

### Proof of Concept

1. Deploy the sequencer with the default `StatelessTransactionValidatorConfig` (`min_gas_price = 8_000_000_000`, `validate_resource_bounds = true`).
2. Submit a V3 Invoke transaction with:
   ```
   resource_bounds = AllResourceBounds {
       l1_gas: { max_amount: 1000, max_price_per_unit: 10_000_000_000 },
       l2_gas