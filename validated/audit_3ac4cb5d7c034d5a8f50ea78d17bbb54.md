### Title
Declare Transactions Bypass `max_l2_gas_amount` Admission Control in `StatelessTransactionValidator::validate_resource_bounds` - (File: `crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary

`StatelessTransactionValidator::validate_resource_bounds` explicitly skips the `l2_gas.max_amount` upper-bound check for `Declare` transactions while enforcing it for `Invoke` and `DeployAccount`. Any user can submit a `Declare` transaction with an arbitrarily large `l2_gas.max_amount`, bypassing the gateway's intended admission-control limit. The downstream `verify_can_pay_committed_bounds` check only guards against insufficient balance, not against the declared amount exceeding the protocol-configured ceiling, so a sufficiently funded account can get such a transaction admitted and executed.

### Finding Description

In `StatelessTransactionValidator::validate_resource_bounds`, the `max_l2_gas_amount` ceiling is enforced for every transaction type **except** `Declare`:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
    // ← no check at all
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { … });
}
```

The test `valid_l2_gas_amount_on_declare` (lines 191–201 of `stateless_transaction_validator_test.rs`) explicitly asserts that a `Declare` with `max_amount: GasAmount(200)` passes when `max_l2_gas_amount = 100`, confirming the bypass is intentional at the code level but unguarded at the security level.

The full gateway admission path for a `Declare` is:

1. **Stateless** (`StatelessTransactionValidator::validate`): skips `max_l2_gas_amount` check.
2. **Stateful** (`StatefulTransactionValidator::validate_resource_bounds`): only checks `l2_gas.max_price_per_unit` against the previous-block threshold; never checks `max_amount`.
3. **Blockifier pre-validation** (`perform_pre_validation_stage` → `check_fee_bounds`): checks `minimal_gas_amount ≤ resource_bounds.max_amount` — passes trivially when `max_amount` is huge.
4. **Balance check** (`verify_can_pay_committed_bounds`): checks `account_balance ≥ max_amount × max_price_per_unit`. This is the only downstream guard, and it is satisfied by any account whose balance covers the declared maximum fee.

No guard ever rejects a `Declare` whose `max_amount` exceeds `max_l2_gas_amount`.

### Impact Explanation

The `max_l2_gas_amount` limit (default `1_210_000_000`) is the gateway's per-transaction L2-gas ceiling. Its purpose is to prevent any single transaction from claiming more gas than the protocol intends to allow through the admission gate, independent of the sender's balance. For `Invoke` and `DeployAccount` this invariant is enforced; for `Declare` it is not.

A `Declare` transaction with `l2_gas.max_amount = max_l2_gas_amount + 1` (e.g., `1_210_000_001`) and `max_price_per_unit = min_gas_price` (e.g., `8_000_000_000`) produces a `max_possible_fee ≈ 9.68 × 10¹⁸` (smallest STRK units, ≈ 9.68 STRK at 18 decimals). Any account with that balance will have the transaction admitted through the full gateway pipeline and placed in the mempool, violating the admission invariant that `max_l2_gas_amount` is meant to enforce uniformly.

This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."**

### Likelihood Explanation

The bypass requires no privilege. Any user who can submit a `Declare` transaction (i.e., any account with a modest STRK balance) can set `l2_gas.max_amount` to any value above the configured ceiling. The code path is unconditional and confirmed by an existing positive-flow test.

### Recommendation

Remove the `Declare`-specific exemption and apply the same `max_l2_gas_amount` ceiling uniformly:

```rust
// Remove the special-case branch:
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

If `Declare` transactions legitimately require a higher ceiling (e.g., because compilation is more gas-intensive), introduce a separate `max_l2_gas_amount_declare` configuration parameter rather than removing the check entirely.

### Proof of Concept

1. Construct a valid `RpcDeclareTransactionV3` with:
   - `l2_gas.max_amount = StatelessTransactionValidatorConfig::default().max_l2_gas_amount + 1` (i.e., `1_210_000_001`)
   - `l2_gas.max_price_per_unit = StatelessTransactionValidatorConfig::default().min_gas_price` (i.e., `8_000_000_000`)
   - All other fields valid (correct Sierra class, sorted entry points, etc.)
2. Call `StatelessTransactionValidator { config: StatelessTransactionValidatorConfig::default() }.validate(&tx)`.
3. Observe `Ok(())` — the transaction passes stateless validation despite `max_amount` exceeding the configured ceiling.
4. For comparison, construct an identical `RpcInvokeTransactionV3` with the same `max_amount`; `validate` returns `Err(MaxGasAmountTooHigh { … })`.

The existing test `valid_l2_gas_amount_on_declare` (lines 191–201 of `stateless_transaction_validator_test.rs`) already encodes exactly this scenario and asserts `Ok(())`.

---

**Root cause**: [1](#0-0) 

**Confirmed bypass test**: [2](#0-1) 

**Config ceiling that is bypassed**: [3](#0-2) 

**Downstream balance guard (only remaining check)**: [4](#0-3) 

**Blockifier `check_fee_bounds` (passes for large `max_amount`)**: [5](#0-4)

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L191-201)
```rust
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

**File:** crates/apollo_gateway_config/src/config.rs (L173-193)
```rust
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
```

**File:** crates/blockifier/src/fee/fee_utils.rs (L173-202)
```rust
pub fn verify_can_pay_committed_bounds(
    state: &mut dyn StateReader,
    tx_context: &TransactionContext,
) -> TransactionFeeResult<()> {
    let tx_info = &tx_context.tx_info;
    let committed_fee = tx_context.max_possible_fee();
    let (balance_low, balance_high, can_pay) =
        get_balance_and_if_covers_fee(state, tx_context, committed_fee)?;
    if can_pay {
        Ok(())
    } else {
        Err(match tx_info {
            TransactionInfo::Current(context) => match &context.resource_bounds {
                L1Gas(l1_gas) => TransactionFeeError::GasBoundsExceedBalance {
                    resource: Resource::L1Gas,
                    max_amount: l1_gas.max_amount,
                    max_price: l1_gas.max_price_per_unit,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
                AllResources(bounds) => TransactionFeeError::ResourcesBoundsExceedBalance {
                    bounds: *bounds,
                    balance: balance_to_big_uint(&balance_low, &balance_high),
                },
            },
            TransactionInfo::Deprecated(context) => TransactionFeeError::MaxFeeExceedsBalance {
                max_fee: context.max_fee,
                balance: balance_to_big_uint(&balance_low, &balance_high),
            },
        })
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
