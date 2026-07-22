### Title
`max_nonce_for_validation_skip` Config Guard Is Configured But Never Applied in Gateway Admission — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidatorConfig` declares `max_nonce_for_validation_skip` to bound the nonce range for which the `__validate__` entry-point call is skipped at the gateway. The field is serialized, documented, and stored inside `StatefulTransactionValidator.config`, but the free function `skip_stateful_validations` that makes the skip decision is never given access to it. The function hardcodes the nonce check to exactly `Nonce(Felt::ONE)`. As a result, the configured guard has zero effect on the gateway's admission decision, and an operator who sets `max_nonce_for_validation_skip = 0` to disable the skip entirely cannot do so — the gateway continues to admit invoke transactions with nonce 1 and arbitrary/invalid signatures without running `__validate__`.

---

### Finding Description

`StatefulTransactionValidatorConfig` declares the field:

```rust
pub max_nonce_for_validation_skip: Nonce,   // default Nonce(Felt::ONE)
``` [1](#0-0) 

The config is stored in `StatefulTransactionValidator.config` and is available to every method on the struct. [2](#0-1) 

`run_pre_validation_checks` calls the free function `skip_stateful_validations` but passes only `(executable_tx, account_nonce, mempool_client)` — the config is never forwarded: [3](#0-2) 

Inside `skip_stateful_validations`, the nonce ceiling is hardcoded to `Nonce(Felt::ONE)`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
``` [4](#0-3) 

The `native_blockifier` equivalent correctly reads the configured ceiling:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
``` [5](#0-4) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`: [6](#0-5) 

`StatefulValidator::perform_validations` then short-circuits immediately for Invoke transactions without ever calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [7](#0-6) 

The transaction is admitted to the mempool with its signature completely unverified at the gateway level.

---

### Impact Explanation

**Matches: High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

An invoke transaction with nonce 1 and a wholly invalid (or empty) signature bypasses the `__validate__` entry-point check at the gateway and is admitted to the mempool. The batcher will later attempt to execute it, call `__validate__`, and reject it — but by then the mempool slot has been consumed and batcher CPU has been spent. Because the config guard is dead, an operator cannot close this path by setting `max_nonce_for_validation_skip = 0`.

---

### Likelihood Explanation

The precondition is that the attacker's account address has a deploy-account transaction in the mempool or a recent block (`account_tx_in_pool_or_recent_block` returns `true`). The attacker controls the account (they submitted the deploy-account tx), so they can trivially craft an invoke tx with nonce 1 and a garbage signature. The nonce check (`0 <= 1 <= 200`) and the mempool fee check do not inspect the signature. No privileged access is required.

---

### Recommendation

Pass `self.config.max_nonce_for_validation_skip` into `skip_stateful_validations` and replace the hardcoded equality check with the bounded range check used in `native_blockifier`:

```diff
-async fn skip_stateful_validations(
+async fn skip_stateful_validations(
     tx: &ExecutableTransaction,
     account_nonce: Nonce,
     mempool_client: SharedMempoolClient,
+    max_nonce_for_validation_skip: Nonce,
 ) -> StatefulTransactionValidatorResult<bool> {
     if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
-        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
+        let tx_nonce = tx.nonce();
+        if tx_nonce >= Nonce(Felt::ONE)
+            && tx_nonce <= max_nonce_for_validation_skip
+            && account_nonce == Nonce(Felt::ZERO)
+        {
```

And update the call site in `run_pre_validation_checks`:

```diff
-skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
+skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone(),
+    self.config.max_nonce_for_validation_skip).await?;
```

---

### Proof of Concept

1. Attacker generates a fresh key pair and computes the corresponding Starknet account address `A`.
2. Attacker submits a valid `DeployAccount` transaction for `A` (valid signature, nonce 0). Gateway validates it fully; it enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker submits an `Invoke` transaction from `A` with nonce 1 and a **garbage signature** (e.g., all zeros).
4. Gateway `validate_nonce`: `0 <= 1 <= 200` → passes.
5. Gateway `validate_by_mempool`: checks nonce ordering and fee, not the signature → passes.
6. Gateway `skip_stateful_validations`: `tx.nonce() == 1 && account_nonce == 0 && account_tx_in_pool == true` → returns `true`.
7. Gateway `run_validate_entry_point`: `ExecutionFlags { validate: false, … }` → `perform_validations` returns `Ok(())` without calling `__validate__`.
8. Invalid invoke transaction is admitted to the mempool. Repeat from step 3 to exhaust mempool capacity.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L136-136)
```rust
    config: StatefulTransactionValidatorConfig,
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/native_blockifier/src/py_validator.rs (L113-114)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
