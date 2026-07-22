### Title
`skip_stateful_validations` Ignores Configurable `max_nonce_for_validation_skip`, Hardcodes `Nonce(Felt::ONE)` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` free function hardcodes `Nonce(Felt::ONE)` as the threshold for bypassing the `__validate__` entry-point check, instead of reading `config.max_nonce_for_validation_skip`. The config field exists, is documented, is serialized into the node config schema, and is correctly consumed in the `native_blockifier` path — but is silently ignored in the production gateway path. This is a direct structural analog of the external report's "hardcoded constant instead of configurable stored value" pattern.

---

### Finding Description

`StatefulTransactionValidatorConfig` declares a configurable field:

```rust
pub max_nonce_for_validation_skip: Nonce,   // default: Nonce(Felt::ONE)
``` [1](#0-0) 

The field is described as *"Maximum nonce for which the validation is skipped"* and is exposed in the node config schema. [2](#0-1) 

The method `run_pre_validation_checks` — a method on `StatefulTransactionValidator` that has full access to `self.config` — calls the free function `skip_stateful_validations` without forwarding the config:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [3](#0-2) 

Inside `skip_stateful_validations`, the threshold is hardcoded:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [4](#0-3) 

By contrast, the `native_blockifier` path correctly reads the stored value:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [5](#0-4) 

The two paths are therefore inconsistent: `native_blockifier` honours the operator-supplied threshold; the gateway ignores it.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions or rejects valid transactions before sequencing.**

Two concrete mis-admission scenarios arise from the hardcoded value:

1. **Operator disables the skip (`max_nonce_for_validation_skip = Nonce(Felt::ZERO)`).**
   The gateway still skips `__validate__` for any invoke transaction whose nonce is exactly `1` and whose account nonce is `0` (undeployed account with a deploy-account in the mempool). An attacker can craft an invoke with nonce=1 and an arbitrary, invalid signature. The gateway admits it to the mempool without signature verification, because the hardcoded `Nonce(Felt::ONE)` condition fires regardless of the operator's intent to disable the feature.

2. **Operator raises the threshold (`max_nonce_for_validation_skip = Nonce(Felt::from(N))` for N > 1).**
   The gateway only skips for nonce=1 (exact equality), so transactions with nonces 2…N that the operator intended to skip are instead rejected, breaking the UX guarantee for multi-step deploy flows.

In scenario 1, the gateway's role as a signature-verification gate is bypassed for a targeted class of transactions. The blockifier will reject the transaction during execution, but the invalid transaction has already been admitted to the mempool, consuming sequencer resources and potentially displacing valid transactions.

---

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which matches the hardcoded value, so the bug is invisible under the default configuration. It is triggered only when an operator explicitly changes the field — a plausible operational action (e.g., disabling the skip for a stricter security posture, or raising it for a multi-step deploy UX). The config field is publicly documented and serialized, so operators are expected to tune it.

---

### Recommendation

Convert `skip_stateful_validations` from a free function into a method on `StatefulTransactionValidator` (or pass `max_nonce_for_validation_skip` as a parameter), and replace the hardcoded literal with the config value, mirroring the `native_blockifier` logic:

```rust
// Replace:
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {

// With (matching native_blockifier semantics):
let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx.nonce();
let nonce_small_enough = tx.nonce() <= self.config.max_nonce_for_validation_skip;
if is_post_deploy_nonce && nonce_small_enough && account_nonce == Nonce(Felt::ZERO) {
``` [6](#0-5) 

---

### Proof of Concept

1. Deploy a sequencer node with `max_nonce_for_validation_skip = 0x0` (disable the skip).
2. Submit a `deploy_account` transaction for address `A` — it enters the mempool.
3. Submit an `invoke` transaction from address `A` with `nonce = 1` and a **garbage signature** (e.g., all-zero felts).
4. Observe: the gateway calls `skip_stateful_validations`, which evaluates `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` → `true`, finds the deploy-account in the mempool, and returns `skip_validate = true`.
5. `run_validate_entry_point` is called with `validate = false`, so `__validate__` is never invoked at the gateway.
6. The invoke transaction with the invalid signature is forwarded to the mempool and accepted, despite the operator having set `max_nonce_for_validation_skip = 0` to prevent exactly this bypass. [7](#0-6)

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
```

**File:** crates/apollo_node/resources/config_schema.json (L3107-3111)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
  },
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-437)
```rust
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-118)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
