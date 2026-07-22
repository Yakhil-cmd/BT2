### Title
Gateway `skip_stateful_validations` admits Invoke transactions with invalid signatures when any prior transaction from the account is in the mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (the account's signature-verification step) for any Invoke transaction with `nonce=1` when the account's on-chain nonce is `0` and **any** transaction from that account exists in the mempool or a recent block. The check `account_tx_in_pool_or_recent_block` is not restricted to `deploy_account` transactions. An attacker who controls an account with on-chain nonce `0` can first submit a valid `nonce=0` Invoke, then submit a `nonce=1` Invoke with an **invalid signature**; the gateway will admit the second transaction to the mempool without running `__validate__`.

---

### Finding Description

`skip_stateful_validations` is designed to improve UX for the `deploy_account + invoke` flow: when a user submits both transactions simultaneously, the account does not yet exist on-chain, so `__validate__` would fail. The function skips validation when:

1. The transaction is an Invoke with `tx.nonce() == Nonce(Felt::ONE)` and `account_nonce == Nonce(Felt::ZERO)`, **and**
2. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

The comment justifies the check as sufficient because it "means that either it has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from the account — including a regular Invoke — not exclusively a `deploy_account`: [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`, meaning the blockifier's `__validate__` entry point (which performs signature verification) is **not executed** during gateway admission: [3](#0-2) 

The full gateway stateful path is:

1. `extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `skip_stateful_validations` → returns `true`
2. `run_validate_entry_point(executable_tx, skip_validate=true)` → `validate: false` → no `__validate__` call [4](#0-3) 

The mempool's `validate_tx` (called via `validate_by_mempool`) checks nonce ordering but does **not** verify signatures: [5](#0-4) 

**Attack path:**

1. Attacker controls account `A` with on-chain nonce `0` (deployed, never transacted).
2. Attacker submits a valid `Invoke(nonce=0, valid_signature)` for account `A`. This passes all checks including `__validate__` and enters the mempool.
3. Attacker submits `Invoke(nonce=1, INVALID_SIGNATURE)` for account `A`.
4. Gateway: `validate_nonce` passes (nonce `1` is within `[0, 200]`); `validate_by_mempool` passes (nonce `1` is a valid future nonce); `skip_stateful_validations` returns `true` because `account_tx_in_pool_or_recent_block` finds the nonce=0 Invoke in the pool.
5. `run_validate_entry_point` is called with `validate=false` — `__validate__` is **not** called.
6. The invalid-signature Invoke is admitted to the mempool.

The same trigger fires if the account has any transaction in a **recently committed block** (the `state.contains_account` branch of `account_tx_in_pool_or_recent_block`), broadening the attack surface to any account that has ever transacted. [6](#0-5) 

---

### Impact Explanation

The gateway's invariant is that every transaction admitted to the mempool has passed signature verification via `__validate__`. This invariant is broken: an attacker can admit Invoke transactions with arbitrary (invalid) signatures for any account that has a prior transaction in the mempool or a recent block, as long as the account's on-chain nonce is `0` and the submitted transaction carries nonce `1`. The admitted transactions will fail at execution time (the batcher always runs `__validate__`), but the mempool is polluted with invalid transactions. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The preconditions are realistic:
- An account with on-chain nonce `0` is common (any newly deployed account that has not yet sent a transaction).
- The attacker only needs to submit one valid `nonce=0` transaction (or wait for the victim to do so) to unlock the skip for `nonce=1`.
- The `max_nonce_for_validation_skip` config defaults to `Nonce(Felt::ONE)`, so the skip is active in production. [7](#0-6) 

---

### Recommendation

Change `skip_stateful_validations` to verify that the account specifically has a **pending `deploy_account` transaction** in the mempool, not just any transaction. The mempool should expose a dedicated query such as `has_pending_deploy_account(address)` rather than the generic `account_tx_in_pool_or_recent_block`. Alternatively, restrict the skip to cases where the account contract does not yet exist on-chain (class hash is zero), which is the only scenario where skipping `__validate__` is semantically justified. [8](#0-7) 

---

### Proof of Concept

```
// Setup: account A is deployed on-chain, on-chain nonce = 0.

// Step 1: submit a valid nonce=0 Invoke for account A (signed correctly).
gateway.add_tx(Invoke { sender: A, nonce: 0, signature: valid_sig_0, ... })
// → passes __validate__, enters mempool.

// Step 2: submit a nonce=1 Invoke for account A with an INVALID signature.
gateway.add_tx(Invoke { sender: A, nonce: 1, signature: [0xff, 0xff, ...], ... })
// → validate_nonce: 1 ∈ [0, 200] ✓
// → validate_by_mempool: nonce 1 is a valid future nonce ✓
// → skip_stateful_validations:
//     tx.nonce() == 1 && account_nonce == 0 → check mempool
//     account_tx_in_pool_or_recent_block(A) == true (nonce=0 Invoke is in pool)
//     → returns true (skip __validate__)
// → run_validate_entry_point(validate=false) → __validate__ NOT called
// → ADMITTED TO MEMPOOL with invalid signature.

// Step 3: batcher picks up both transactions.
// nonce=0 Invoke executes successfully.
// nonce=1 Invoke: batcher runs __validate__ → fails (invalid signature) → reverted.
// Mempool was polluted with an invalid transaction.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
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

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
}
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-461)
```rust
/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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
            debug!("Checking if deploy_account transaction exists for account {account_address}.");
            // We verify that a deploy_account transaction exists for this account. It is sufficient
            // to check if the account exists in the mempool since it means that either it has a
            // deploy_account transaction or transactions with future nonces that passed
            // validations.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
                .inspect(|exists| {
                    if *exists {
                        debug!("Found deploy_account transaction for account {account_address}.");
                    } else {
                        debug!(
                            "No deploy_account transaction found for account {account_address}."
                        );
                    }
                });
        }
    }

    Ok(false)
}
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
