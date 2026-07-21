### Title
`max_nonce_for_validation_skip` config field is silently ignored in `skip_stateful_validations`; hardcoded `Nonce(Felt::ONE)` used instead — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field that is documented as "Maximum nonce for which the validation is skipped." The field is serialized, deserialized, and shipped in the production config schema. However, the free function `skip_stateful_validations` — which decides whether to bypass the `__validate__` entry-point call for the deploy-account + invoke UX flow — never reads this field. It hardcodes `Nonce(Felt::ONE)` instead. The config value is therefore a dead parameter in the gateway: any operator-supplied value is silently discarded.

---

### Finding Description

`skip_stateful_validations` is a free function (not a method) and therefore has no access to `self.config`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  line 437
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [1](#0-0) 

Its caller, `run_pre_validation_checks`, holds `self` and therefore has access to `self.config.max_nonce_for_validation_skip`, but passes neither the config nor the threshold to the callee:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [2](#0-1) 

The config field is defined and serialized:

```rust
pub max_nonce_for_validation_skip: Nonce,   // default Nonce(Felt::ONE)
``` [3](#0-2) 

And it is present in the production config schema with value `"0x1"`: [4](#0-3) 

By contrast, the Python-facing `PyValidator` correctly uses the field in a range check:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [5](#0-4) 

The gateway's `skip_stateful_validations` is therefore inconsistent with both the config contract and the Python validator's semantics.

When `skip_validate` is `true`, `run_validate_entry_point` sets `validate: false` in the execution flags, causing the blockifier to skip the `__validate__` entry point (i.e., signature verification) for that transaction:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [6](#0-5) 

---

### Impact Explanation

**Case 1 — operator sets `max_nonce_for_validation_skip = 0` to disable the skip feature entirely:**  
The gateway still returns `skip_validate = true` for any Invoke transaction whose nonce is exactly `1` and whose account nonce is `0` with a deploy-account in the mempool. The `__validate__` entry point is not called, so a transaction carrying an invalid or forged signature is admitted to the mempool without signature verification. This satisfies: *"High. Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

**Case 2 — operator sets `max_nonce_for_validation_skip > 1` (e.g., `5`) to extend the UX window:**  
The gateway only skips for nonce `== 1`; invoke transactions with nonces `2`–`5` from a newly deploying account are subjected to full `__validate__` execution, which fails because the account contract does not yet exist on-chain. These valid transactions are incorrectly rejected. This satisfies: *"High. Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which coincidentally matches the hardcoded constant, so the bug is latent with default configuration. It becomes active the moment an operator changes the field — a change that is explicitly supported by the config schema and documented as meaningful. Because the field is present in the production schema and deployment configs, operators have a reasonable expectation that it controls gateway behavior.

---

### Recommendation

Convert `skip_stateful_validations` from a free function into a method of `StatefulTransactionValidator` (or pass `max_nonce_for_validation_skip` as an explicit parameter), and replace the hardcoded equality check with the range check used by `PyValidator`:

```rust
// Proposed fix inside run_pre_validation_checks (has access to self.config)
let max_nonce = self.config.max_nonce_for_validation_skip;
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, max_nonce, mempool_client.clone()).await?;

// Inside skip_stateful_validations:
let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx.nonce();
let nonce_within_skip_range = tx.nonce() <= max_nonce_for_validation_skip;
if is_post_deploy_nonce && nonce_within_skip_range && account_nonce == Nonce(Felt::ZERO) { … }
```

---

### Proof of Concept

1. Deploy the gateway with `stateful_tx_validator_config.max_nonce_for_validation_skip = 0x0` (operator intent: disable the skip feature).
2. Submit a `DeployAccount` transaction for a fresh account `A` (valid signature required — passes normally).
3. Submit an `Invoke` transaction from `A` with `nonce = 1` and a **deliberately invalid signature**.
4. Observe: `skip_stateful_validations` returns `true` (hardcoded `Nonce(Felt::ONE)` check fires), `run_validate_entry_point` is called with `validate = false`, the `__validate__` entry point is never executed, and the transaction is forwarded to the mempool — bypassing the operator's configured policy of requiring signature verification for all transactions.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L407-409)
```rust
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-438)
```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        // check if the transaction nonce is 1, meaning it is post deploy_account, and the
        // account nonce is zero, meaning the account was not deployed yet.
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            let account_address = tx.sender_address();
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-286)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
```

**File:** crates/apollo_node/resources/config_schema.json (L3107-3111)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": {
    "description": "Maximum nonce for which the validation is skipped.",
    "privacy": "Public",
    "value": "0x1"
  },
```

**File:** crates/native_blockifier/src/py_validator.rs (L112-118)
```rust
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
