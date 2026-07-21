Let me look at the exact flow and confirm the interaction between the resource bounds check and client-side proving transactions.

### Title
`StatelessTransactionValidator::validate_resource_bounds` unconditionally rejects valid client-side proving transactions whose prices are mandatorily zero — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

---

### Summary

`StatelessTransactionValidator::validate_resource_bounds` applies two fee-positivity checks to every incoming `RpcTransaction` before any client-side-proving-specific logic runs. Client-side proving transactions are protocol-required to carry all-zero `max_price_per_unit` fields (enforced by the prover's own `validate_zero_fee_resource_bounds`). The gateway therefore rejects every such transaction with `ZeroResourceBounds` or `MaxGasPriceTooLow` before it ever reaches `validate_client_side_proving_allowed`, even though the gateway is explicitly configured to accept client-side proving transactions (`allow_client_side_proving: true` in production).

---

### Finding Description

**Root cause — wrong check ordering and missing special-case guard**

`StatelessTransactionValidator::validate` calls checks in this order:

```
validate_resource_bounds(tx)?;          // line 40 — runs for ALL tx types
...
validate_client_side_proving_allowed()? // line 46 — only reached if line 40 passes
validate_proof_facts_and_proof_consistency()?
```

Inside `validate_resource_bounds` (lines 56–88):

```rust
// Check 1 — rejects if max_possible_fee == 0
if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0) {
    return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
}

// Check 2 — rejects if l2_gas price < min_gas_price (default 8_000_000_000)
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
```

**The invariant that breaks it**

The prover's `validate_zero_fee_resource_bounds` (lines 401–445 of `crates/starknet_transaction_prover/src/proving/virtual_snos_prover.rs`) mandates that every client-side proving transaction has:

```
l1_gas.max_price_per_unit  = 0
l2_gas.max_price_per_unit  = 0
l1_data_gas.max_price_per_unit = 0
tip = 0
```

A canonical client-side proving transaction therefore has:

```
max_possible_fee = 0×0 + 0x5f5e100×0 + 0×0 = 0
l2_gas.max_price_per_unit = 0 < 8_000_000_000
```

Both checks fire and the transaction is rejected at the gateway's stateless stage.

**Production configuration confirms the collision**

`StatelessTransactionValidatorConfig::default()` sets `validate_resource_bounds: true` and `min_gas_price: 8_000_000_000`. The production replacer config (`crates/apollo_deployments/resources/app_configs/replacer_gateway_config.json`) sets `allow_client_side_proving: true` but does **not** override `validate_resource_bounds`, so it remains `true`. The `min_gas_price` is a non-zero template variable.

**Test coverage gap confirms the bug**

The only test that exercises client-side proving through the full `validate()` path (`test_positive_flow` case `client_side_proving`, line 148) uses `DEFAULT_VALIDATOR_CONFIG_FOR_TESTING` which explicitly sets `validate_resource_bounds: false` to avoid the collision. No test exercises client-side proving with `validate_resource_bounds: true`.

---

### Impact Explanation

Every valid client-side proving Invoke V3 transaction submitted to the production gateway is rejected at the stateless validation stage with `ZeroResourceBounds` or `MaxGasPriceTooLow`. The gateway returns a `ValidationFailure` error to the caller. The transaction never reaches the mempool or blockifier. This is a complete denial of the client-side proving feature for all users submitting through the gateway.

**Impact category**: High — Mempool/gateway admission rejects valid transactions before sequencing.

---

### Likelihood Explanation

The collision is deterministic: any client-side proving transaction (which must have zero prices by protocol) submitted to a gateway with the default or production configuration will be rejected 100% of the time. No special attacker capability is required; any user attempting to use the feature triggers it.

---

### Recommendation

`validate_resource_bounds` must skip the fee-positivity checks when the transaction is a client-side proving transaction (i.e., an Invoke V3 with non-empty `proof_facts` or `proof`). The check ordering should either be reversed (detect client-side proving first) or the guard should be inlined:

```diff
 fn validate_resource_bounds(
     &self,
     tx: &RpcTransaction,
 ) -> StatelessTransactionValidatorResult<()> {
     if !self.config.validate_resource_bounds {
         return Ok(());
     }

+    // Client-side proving transactions carry zero prices by protocol design;
+    // fee-positivity checks do not apply to them.
+    if let RpcTransaction::Invoke(RpcInvokeTransaction::V3(invoke_tx)) = tx {
+        if !invoke_tx.proof_facts.is_empty() || !invoke_tx.proof.is_empty() {
+            return Ok(());
+        }
+    }

     let resource_bounds = *tx.resource_bounds();
     if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0) {
         return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
     }
     if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
         return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
     }
     ...
 }
```

A corresponding test should be added that runs `validate()` with `validate_resource_bounds: true`, `min_gas_price > 0`, and a client-side proving transaction with zero prices, asserting `Ok(())`.

---

### Proof of Concept

1. Configure the gateway with defaults (`validate_resource_bounds: true`, `min_gas_price: 8_000_000_000`, `allow_client_side_proving: true`).
2. Construct a valid Invoke V3 transaction with:
   - `l1_gas / l2_gas / l1_data_gas`: all `max_price_per_unit = 0`, `l2_gas.max_amount = 0x5f5e100`
   - `tip = 0`
   - Non-empty `proof_facts` and `proof` (as returned by the prover)
3. Submit to `StatelessTransactionValidator::validate`.
4. Execution reaches line 66 of `stateless_transaction_validator.rs`: `max_possible_fee(Tip::ZERO) == Fee(0)` evaluates to `true` → returns `Err(ZeroResourceBounds)`.
5. The transaction is rejected before `validate_client_side_proving_allowed` is ever called (line 46).

The test `test_positive_flow / client_side_proving` (line 148 of `stateless_transaction_validator_test.rs`) silently masks this by using `validate_resource_bounds: false`; switching it to `true` with a non-zero `min_gas_price` reproduces the failure deterministically. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** crates/starknet_transaction_prover/src/proving/virtual_snos_prover.rs (L401-445)
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

    Ok(())
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

**File:** crates/apollo_deployments/resources/app_configs/replacer_gateway_config.json (L21-31)
```json
  "gateway_config.static_config.stateless_tx_validator_config.allow_client_side_proving": true,
  "gateway_config.static_config.stateless_tx_validator_config.max_calldata_length": 5000,
  "gateway_config.static_config.stateless_tx_validator_config.max_contract_bytecode_size": "$$$_GATEWAY_CONFIG-STATIC_CONFIG-STATELESS_TX_VALIDATOR_CONFIG-MAX_CONTRACT_BYTECODE_SIZE_$$$",
  "gateway_config.static_config.stateless_tx_validator_config.max_contract_class_object_size": 4089446,
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": 1210000000,
  "gateway_config.static_config.stateless_tx_validator_config.max_proof_size": 480000,
  "gateway_config.static_config.stateless_tx_validator_config.max_sierra_version.major": 1,
  "gateway_config.static_config.stateless_tx_validator_config.max_sierra_version.minor": 9,
  "gateway_config.static_config.stateless_tx_validator_config.max_sierra_version.patch": 0,
  "gateway_config.static_config.stateless_tx_validator_config.max_signature_length": 4000,
  "gateway_config.static_config.stateless_tx_validator_config.min_gas_price": "$$$_GATEWAY_CONFIG-STATIC_CONFIG-STATELESS_TX_VALIDATOR_CONFIG-MIN_GAS_PRICE_$$$",
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L148-151)
```rust
#[case::client_side_proving(
    DEFAULT_VALIDATOR_CONFIG_FOR_TESTING.clone(),
    RpcTransactionArgs { proof_facts: create_valid_proof_facts_for_testing(), proof: Proof::proof_for_testing(), ..Default::default()}
)]
```
