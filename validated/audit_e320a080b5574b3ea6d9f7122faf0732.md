### Title
Unauthorized Invoke Transaction Admitted Without Signature Verification via `skip_stateful_validations` When Victim's `deploy_account` Is in Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point (signature verification) for any invoke transaction with `nonce = 1` when the account's on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. That check returns `true` for **any** transaction in the pool for that address — not specifically a `deploy_account` submitted by the same signer. An unprivileged attacker who observes a victim's pending `deploy_account` in the mempool can immediately submit a competing invoke with `nonce = 1` and arbitrary calldata; the gateway accepts it without ever calling `__validate__`, admitting an unauthorized transaction into the mempool.

### Finding Description

**Broken invariant**: Every invoke transaction admitted to the mempool must have passed `__validate__` (i.e., the account's signature over the transaction hash must have been verified), or the account must not yet exist and the skip must be provably safe.

**Root cause — `skip_stateful_validations`**: [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
1. The incoming tx is an `Invoke` with `nonce == 1`, and
2. The account's on-chain nonce is `0` (not yet deployed), and
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

The third check is implemented as: [2](#0-1) 

This returns `true` if **any** transaction for the address is in the pool or has appeared in a committed block — it does **not** verify that the existing pool entry is a `deploy_account` submitted by the same key-holder. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but that reasoning is circular: the skip itself is what allows nonce-1 invokes to bypass `__validate__`.

**How `__validate__` is suppressed**: [3](#0-2) 

When `skip_validate = true`, `execution_flags.validate` is set to `false`. The blockifier's `StatefulValidator::perform_validations` then returns `Ok(())` immediately after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point: [4](#0-3) 

**Attack path**:

1. Victim broadcasts a `deploy_account` for address `X` (nonce 0). It enters the mempool pool.
2. Attacker observes the pending `deploy_account` and immediately submits an `Invoke` for address `X` with `nonce = 1` and malicious calldata (e.g., transfer all funds to attacker).
3. Gateway stateless validation passes (no signature check at this layer).
4. `validate_nonce`: `0 ≤ 1 ≤ 200` — passes.
5. `validate_by_mempool`: nonce-gap check passes.
6. `skip_stateful_validations`: `tx_pool.contains_account(X)` is `true` (victim's `deploy_account` is there) → returns `true`.
7. `run_validate_entry_point` is called with `skip_validate = true` → `__validate__` is **never called**.
8. Attacker's invoke is admitted to the mempool without any signature verification.

**Batcher behavior**: The batcher creates transactions with `validate: true` via `BlockifierTransaction::new_for_sequencing`, so `__validate__` **is** re-run at execution time and the attacker's transaction will revert. However, the attacker's transaction has already displaced the victim's legitimate nonce-1 invoke (via fee escalation or simple first-in-wins), causing the victim's transaction to be lost. The attacker can repeat this indefinitely to permanently block the victim's first post-deployment invoke.

### Impact Explanation

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

An unauthorized invoke — one whose signature has never been verified against the account's public key — is admitted to the mempool. The attacker can:
- Displace the victim's legitimate nonce-1 invoke via fee escalation, causing it to be permanently dropped.
- Repeatedly re-submit to sustain a targeted denial-of-service against any newly-deploying account.
- In the worst case (if a future code change removes the batcher's re-validation), the malicious `__execute__` call would run without any authorization check.

### Likelihood Explanation

The trigger is entirely unprivileged and requires only mempool observation. Every `deploy_account` transaction that enters the mempool creates a window of vulnerability. The `max_nonce_for_validation_skip` default of `0x1` limits the attack to nonce-1 invokes, but that is precisely the first user action after deployment — the highest-value target. [5](#0-4) 

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account`** transaction for the same address is present in the pool:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())

// Use a new mempool API:
mempool_client.deploy_account_in_pool(tx.sender_address())
```

Alternatively, require the invoke's signature to be pre-verified against the public key embedded in the `deploy_account`'s constructor calldata before skipping `__validate__`, so the skip is only granted to the same key-holder who submitted the `deploy_account`.

### Proof of Concept

```
1. Victim submits deploy_account for address X (class_hash=C, salt=S, constructor_calldata=[pub_key_P])
   → deploy_account enters mempool pool; tx_pool.contains_account(X) = true

2. Attacker submits Invoke(sender=X, nonce=1, calldata=[transfer_all_to_attacker], signature=[garbage])

3. Gateway stateless validator: passes (no sig check)
   validate_nonce: account_nonce=0, tx_nonce=1, 0 ≤ 1 ≤ 200 → passes
   validate_by_mempool: nonce gap OK → passes
   skip_stateful_validations:
     tx.nonce() == 1 && account_nonce == 0 → true
     account_tx_in_pool_or_recent_block(X) → true (victim's deploy_account is in pool)
     returns true  ← __validate__ SKIPPED
   run_validate_entry_point(skip_validate=true):
     execution_flags.validate = false
     StatefulValidator returns Ok(()) without calling __validate__

4. Attacker's invoke admitted to mempool with no signature verification.

5. If attacker's fee > victim's nonce-1 invoke fee:
   victim's invoke is evicted via fee escalation; victim's tx is lost.

6. Batcher executes block:
   deploy_account(nonce=0) → X deployed with pub_key_P
   attacker's invoke(nonce=1) → __validate__ called → sig[garbage] ≠ pub_key_P → REVERT
   (victim's legitimate invoke was already evicted; victim must resubmit)

7. Attacker repeats step 2 indefinitely → permanent DoS on victim's first post-deployment invoke.
```

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway_config/src/config.rs (L295-296)
```rust
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
```
