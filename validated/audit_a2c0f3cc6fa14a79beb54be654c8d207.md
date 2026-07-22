### Title
`skip_stateful_validations` Ignores `max_nonce_for_validation_skip` Config — Hardcoded `Nonce(Felt::ONE)` Bypasses Operator-Configured Validation Gate - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidatorConfig` exposes a public, documented field `max_nonce_for_validation_skip` that is supposed to control the upper nonce bound below which the `__validate__` entry-point call is skipped for the deploy-account + invoke UX flow. The free function `skip_stateful_validations` — called from `run_pre_validation_checks` — never reads that field; it hardcodes `Nonce(Felt::ONE)` directly. The config field is therefore dead code in the Rust gateway path. When an operator sets `max_nonce_for_validation_skip = 0` to disable the skip entirely, the gateway still silently skips `__validate__` for every invoke transaction whose nonce is exactly 1 and whose account is not yet deployed, admitting transactions that should have been rejected.

---

### Finding Description

`StatefulTransactionValidatorConfig` declares:

```rust
pub max_nonce_for_validation_skip: Nonce,
```

with a default of `Nonce(Felt::ONE)` and a public config-schema entry `"gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1"`. [1](#0-0) 

`run_pre_validation_checks` is a method on `StatefulTransactionValidator` and therefore has full access to `self.config.max_nonce_for_validation_skip`. It calls the free function `skip_stateful_validations` but passes **none** of the config:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [2](#0-1) 

`skip_stateful_validations` then hardcodes the nonce threshold:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [3](#0-2) 

The Python-bindings path (`PyValidator`) implements the same logic correctly, reading `self.max_nonce_for_validation_skip`:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
``` [4](#0-3) 

The two implementations diverge: the Rust gateway path ignores the configured bound entirely.

When `skip_validate` is `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags` and the blockifier's `StatefulValidator::perform_validations` skips the `__validate__` call for the invoke transaction:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [5](#0-4) 

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [6](#0-5) 

---

### Impact Explanation

**Case 1 — operator disables the skip (`max_nonce_for_validation_skip = 0`):**  
The gateway still skips `__validate__` for any invoke with `nonce == 1` from an undeployed account that has a deploy-account tx in the mempool. Transactions carrying an invalid signature or failing account logic bypass the signature/validation check and are admitted to the mempool. This matches: *"High. Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

**Case 2 — operator raises the bound (`max_nonce_for_validation_skip > 1`):**  
Invoke transactions with nonces 2 … N from undeployed accounts are rejected even though the operator intended them to be admitted without `__validate__`. This matches: *"High. Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The default value of `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)`, which coincidentally matches the hardcoded constant, so the bug is invisible in default deployments. It surfaces only when an operator explicitly changes the config. Because the field is public, documented, and present in the production config schema, an operator tuning security posture (setting it to 0) or UX (setting it higher) will silently get the wrong behavior. The trigger is unprivileged: any user can submit an invoke with nonce 1 from an account that has a pending deploy-account.

---

### Recommendation

Convert `skip_stateful_validations` from a free function into a method on `StatefulTransactionValidator`, or pass `self.config.max_nonce_for_validation_skip` as an explicit parameter, and replace the hardcoded `Nonce(Felt::ONE)` with the configured value:

```rust
// In run_pre_validation_checks:
let skip_validate = skip_stateful_validations(
    executable_tx,
    account_nonce,
    mempool_client.clone(),
    self.config.max_nonce_for_validation_skip,  // ← pass config
).await?;

// In skip_stateful_validations:
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
    max_nonce_for_validation_skip: Nonce,       // ← new param
) -> ... {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() >= Nonce(Felt::ONE)
            && tx.nonce() <= max_nonce_for_validation_skip  // ← use config
            && account_nonce == Nonce(Felt::ZERO)
        { ... }
    }
}
```

Also add a test that sets `max_nonce_for_validation_skip = Nonce(Felt::ZERO)` and verifies that `skip_stateful_validations` returns `false` for a nonce-1 invoke.

---

### Proof of Concept

1. Deploy a sequencer node with `max_nonce_for_validation_skip = 0x0` in the gateway config.
2. Submit a `DeployAccount` transaction for address `A`; it enters the mempool (account nonce in state remains 0).
3. Craft an `Invoke` transaction from address `A` with `nonce = 1` and a **deliberately invalid signature**.
4. Submit the invoke to the gateway.
5. **Expected (with correct config use):** gateway calls `__validate__`, signature check fails, transaction rejected.
6. **Actual (with hardcoded `Nonce(Felt::ONE)`):** `skip_stateful_validations` returns `true` because `tx.nonce() == Nonce(Felt::ONE)` and `account_nonce == Nonce(Felt::ZERO)` and the deploy-account is in the mempool; `__validate__` is never called; the invalid-signature invoke is admitted to the mempool.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-437)
```rust
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        // check if the transaction nonce is 1, meaning it is post deploy_account, and the
        // account nonce is zero, meaning the account was not deployed yet.
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
