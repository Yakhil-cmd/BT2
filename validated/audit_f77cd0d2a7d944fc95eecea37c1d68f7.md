### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke for Any Undeployed Account with a Pending Deploy-Account - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (and therefore signature verification) for any invoke transaction whose sender has nonce=1 and whose on-chain account nonce is 0, provided `account_tx_in_pool_or_recent_block` returns `true` for that sender. The check does not verify that the existing mempool entry is specifically a `deploy_account` transaction. An attacker who observes a victim's `deploy_account` in the mempool can immediately submit an invoke with nonce=1 for the victim's address carrying an arbitrary (invalid) signature, have it admitted without signature verification, and thereby block the victim's legitimate invoke from entering the mempool.

### Finding Description

`skip_stateful_validations` is the gateway-side analog of the "permissionless action that bypasses intended processing logic" described in the seed report. The function is documented as a UX feature: when a user sends `deploy_account` + `invoke` together, the gateway cannot call `__validate__` on the invoke because the account contract does not yet exist on-chain. The intended guard is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    // We verify that a deploy_account transaction exists for this account.
    // It is sufficient to check if the account exists in the mempool since it means
    // that either it has a deploy_account transaction or transactions with future
    // nonces that passed validations.
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The comment's assumption is wrong. `account_tx_in_pool_or_recent_block` returns `true` whenever the address appears in the mempool pool **or** in the mempool's committed-account state, regardless of transaction type:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

Because the check is not restricted to `deploy_account` transactions, any attacker who sees a victim's `deploy_account` in the mempool can submit an invoke with nonce=1 for the victim's address. The three conditions are satisfied:

1. `tx.nonce() == Nonce(Felt::ONE)` — attacker sets nonce=1.
2. `account_nonce == Nonce(Felt::ZERO)` — victim's account is not yet deployed.
3. `account_tx_in_pool_or_recent_block(victim)` — victim's `deploy_account` is in the pool.

`skip_validate` is set to `true`, and `run_validate_entry_point` is called with `execution_flags.validate = false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 308-312
let only_query = false;
let charge_fee = enforce_fee(executable_tx, only_query);
let strict_nonce_check = false;
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

The `__validate__` entry point is never called, so the attacker's arbitrary signature is never verified. The transaction passes `validate_by_mempool` (no duplicate nonce=1 exists yet) and is inserted into the mempool. When the victim subsequently submits their legitimate invoke with nonce=1, the mempool rejects it as `DuplicateNonce`.

### Impact Explanation

**Mempool/gateway admission accepts an invalid transaction (invalid signature) and rejects a valid transaction before sequencing.** This is a High-severity impact under the allowed scope.

Concrete consequences:
- The victim's legitimate invoke is permanently blocked from the mempool for nonce=1 (the attacker's entry occupies that slot).
- When the attacker's invalid invoke is eventually executed in a block, the `__validate__` entry point is called with execution flags set by the batcher (not the gateway), the signature check fails, the transaction reverts, and the victim's deployed account is charged fees for the failed validation.
- The victim must wait for the attacker's transaction to be evicted (TTL expiry) or replaced via fee escalation before their own invoke can be admitted.

### Likelihood Explanation

The attack requires only:
1. Observing the victim's `deploy_account` transaction in the public mempool (trivially possible via the RPC or P2P layer).
2. Submitting an invoke with nonce=1 for the victim's address before the victim submits their own invoke.

No privileged access, no special account, and no on-chain funds are required. The attacker's transaction carries an arbitrary signature (e.g., all zeros) and still passes all gateway checks. The window is the time between the victim's `deploy_account` appearing in the mempool and the victim submitting their invoke — a race condition that is straightforward to win.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the sender address. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool` that inspects the transaction type, not merely the address presence. Alternatively, the gateway can inspect the `InternalRpcTransaction` type of the pending transaction for the address before granting the skip.

### Proof of Concept

1. Victim calls `add_tx` with a `deploy_account` for address `V`. The gateway admits it; the mempool now contains `deploy_account(V, nonce=0)`.
2. Attacker calls `add_tx` with `invoke(sender=V, nonce=1, signature=[0,0])`.
3. Gateway stateless validator passes (signature length ≤ max, resource bounds non-zero).
4. `extract_state_nonce_and_run_validations` reads on-chain nonce for `V` → `0`.
5. `run_pre_validation_checks` calls `validate_by_mempool` → no duplicate nonce=1 → passes.
6. `skip_stateful_validations`: nonce=1 ✓, account_nonce=0 ✓, `account_tx_in_pool_or_recent_block(V)` = `true` (deploy_account is in pool) → returns `true`.
7. `run_validate_entry_point` is called with `validate=false` → `__validate__` is never executed → invalid signature is never checked.
8. Attacker's invoke is admitted to the mempool.
9. Victim calls `add_tx` with their legitimate `invoke(sender=V, nonce=1, signature=<valid>)`.
10. `validate_by_mempool` → `MempoolError::DuplicateNonce` → victim's transaction is rejected. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-461)
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
