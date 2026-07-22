### Title
Gateway Stateless Validator Missing `max_l2_gas_amount` Enforcement for Declare Transactions Allows Admission Policy Bypass - (File: crates/apollo_gateway/src/stateless_transaction_validator.rs)

### Summary
The `StatelessTransactionValidator::validate_resource_bounds` function enforces a `max_l2_gas_amount` cap on `l2_gas.max_amount` for Invoke and DeployAccount transactions but explicitly skips this check for Declare transactions. This asymmetry — directly analogous to the external report's "check present in one code path, absent in the parallel path" pattern — allows a Declare transaction with an arbitrarily large `l2_gas.max_amount` to pass the stateless gateway and be admitted to the mempool, while an identical Invoke transaction would be rejected at the stateless stage.

### Finding Description

In `crates/apollo_gateway/src/stateless_transaction_validator.rs` lines 78–85, the `max_l2_gas_amount` guard is explicitly skipped for Declare transactions:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

The production configuration sets `max_l2_gas_amount = 1_210_000_000` for Invoke and DeployAccount. For Declare, no upper bound on `l2_gas.max_amount` is enforced at the stateless stage.

The stateful validator's `validate_resource_bounds` (lines 223–243) only checks the L2 gas *price* threshold against the previous block price — it does not check the gas *amount* at all:

```rust
self.validate_tx_l2_gas_price_within_threshold(
    executable_tx.resource_bounds(),
    previous_block_l2_gas_price,
)?;
```

`validate_tx_l2_gas_price_within_threshold` (lines 359–390) matches only on `AllResources` to check the price ratio; it never inspects `max_amount`. Therefore a Declare transaction with `l2_gas.max_amount = max_l2_gas_amount + N` for any `N ≥ 1` passes both the stateless and stateful gateway checks, provided the account balance covers `max_amount × max_price_per_unit` (the `verify_can_pay_committed_bounds` backstop in the blockifier).

The asymmetry is exact:

| Transaction type | `max_l2_gas_amount` enforced at stateless stage? |
|---|---|
| Invoke | Yes — rejected if `max_amount > 1_210_000_000` |
| DeployAccount | Yes — rejected if `max_amount > 1_210_000_000` |
| **Declare** | **No — any `max_amount` passes** |

### Impact Explanation

A Declare transaction with `l2_gas.max_amount = 1_210_000_001` (one unit above the enforced limit) and `l2_gas.max_price_per_unit = min_gas_price` passes the stateless validator, passes the stateful validator's price-only check, and is admitted to the mempool — violating the gateway's own admission policy. The gateway's `max_l2_gas_amount` control is a DoS-protection boundary; bypassing it for Declare transactions means the boundary is not uniformly enforced across all transaction types. An equivalent Invoke transaction with the same parameters is rejected at the stateless stage before any state is read.

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

Any unprivileged user who holds enough STRK to satisfy `verify_can_pay_committed_bounds` for the chosen `max_amount × max_price_per_unit` can trigger this. No special role, key, or privileged access is required. The TODO comment in the source confirms the developers are aware the check is absent.

### Recommendation

Apply the same `max_l2_gas_amount` guard to Declare transactions, removing the empty `if let RpcTransaction::Declare(_) = tx {}` branch:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

This aligns Declare with the uniform policy already applied to Invoke and DeployAccount.

### Proof of Concept

1. Construct an `RpcDeclareTransactionV3` with:
   - `resource_bounds.l2_gas.max_amount = GasAmount(1_210_000_001)` (one above the production limit)
   - `resource_bounds.l2_gas.max_price_per_unit = GasPrice(8_000_000_000)` (at `min_gas_price`)
   - A valid Sierra contract class and all other required fields.
2. Fund the sender account with at least `1_210_000_001 × 8_000_000_000 ≈ 9.68 × 10^18` STRK (or use a smaller `max_amount` overage with a proportionally smaller balance).
3. Submit via the gateway's `add_transaction` RPC endpoint.
4. Observe: the stateless validator accepts the transaction (the `MaxGasAmountTooHigh` error is never raised for Declare). An identical Invoke with the same `max_amount` is rejected at step 3 with `MaxGasAmountTooHigh`.

The root cause is at: [1](#0-0) 

The missing stateful-side amount check is confirmed at: [2](#0-1) 

The production `max_l2_gas_amount` value that is bypassed: [3](#0-2)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L78-85)
```rust
        // TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
        if let RpcTransaction::Declare(_) = tx {
        } else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
            return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
                gas_amount: resource_bounds.l2_gas.max_amount,
                max_gas_amount: self.config.max_l2_gas_amount,
            });
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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L25-25)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": 1210000000,
```
