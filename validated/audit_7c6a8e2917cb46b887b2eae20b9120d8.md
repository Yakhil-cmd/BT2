### Title
Signature Validation Unconditionally Skipped for Invoke Transactions via `skip_stateful_validations` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validation path unconditionally skips the `__validate__` entry-point call (which verifies the transaction signature) for any Invoke transaction with `nonce == 1` submitted against an account whose on-chain nonce is `0`, provided that `account_tx_in_pool_or_recent_block` returns `true` for that sender address. Because the check is purely nonce-based and does not verify the transaction's signature before admission, an attacker who observes a legitimate `deploy_account` transaction in the mempool can flood the mempool with unsigned or maliciously-signed Invoke transactions for the same address, all of which are admitted without signature verification.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` implements a UX shortcut: [1](#0-0) 

When the conditions `tx.nonce() == Nonce(Felt::ONE)` and `account_nonce == Nonce(Felt::ZERO)` are both true, and `account_tx_in_pool_or_recent_block(sender_address)` returns `true`, the function returns `true` (skip validation).

This result propagates directly into `run_validate_entry_point`: [2](#0-1) 

Setting `execution_flags.validate = !skip_validate = false`. The blockifier's `StatefulValidator::perform_validations` then short-circuits: [3](#0-2) 

The `__validate__` entry point — which is the account contract's signature verification — is never called. The transaction is admitted to the mempool with no cryptographic proof that the sender authorized it.

The `account_tx_in_pool_or_recent_block` check is the only guard. It checks whether **any** transaction from the sender address exists in the mempool or a recent committed block — it does not verify that the pending transaction is specifically a `deploy_account`, nor does it verify the signature of the incoming Invoke. [4](#0-3) 

### Impact Explanation

An attacker who observes a legitimate user's `deploy_account` transaction in the mempool (nonce=0, address=A) can immediately submit arbitrarily many Invoke transactions with `nonce=1` from address A, carrying any calldata and any (or no) signature. All of these pass the gateway's stateful validation without the `__validate__` entry point being invoked. They are admitted to the mempool, consuming slots and processing resources. During batcher execution the transactions will fail `__validate__` (the account contract rejects the bad signature), but by then they have already displaced legitimate transactions and imposed sequencer-side execution cost with no fee paid by the attacker (failed `__validate__` means no fee is charged).

Impact category: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The trigger is entirely unprivileged and observable on-chain: any `deploy_account` transaction visible in the public mempool satisfies the precondition. No special knowledge of the victim's private key or contract internals is required. The attacker only needs the sender address, which is public.

### Recommendation

The `skip_stateful_validations` path should not bypass signature verification entirely. Instead of skipping `__validate__` when a deploy_account is pending, the gateway should either:

1. **Require a stateless signature pre-check** — perform an off-chain ECDSA/Stark-curve signature verification against the transaction hash before admitting the transaction, independent of whether the account contract exists on-chain.
2. **Restrict the skip to a single transaction per address** — once one Invoke with `nonce=1` has been admitted under the skip rule for a given address, reject all subsequent ones until the deploy_account is committed.
3. **Verify the skip condition more narrowly** — confirm that the pending mempool entry for the address is specifically a `deploy_account` transaction (not just any transaction), and limit the number of invokes that can be admitted under the skip rule.

### Proof of Concept

1. Legitimate user broadcasts `deploy_account` for address `A` (class_hash=C, salt=S). It enters the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.
2. Attacker constructs `InvokeV3 { sender_address: A, nonce: 1, calldata: <arbitrary>, signature: [] }`.
3. Attacker submits this to the gateway. `skip_stateful_validations` evaluates: `tx.nonce() == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(A)` ✓ → returns `true`.
4. `run_validate_entry_point` sets `execution_flags.validate = false`; `perform_validations` returns `Ok(())` at line 80 without calling `__validate__`.
5. The unsigned Invoke is admitted to the mempool. Attacker repeats step 2–4 thousands of times with different calldata, flooding the mempool.
6. Each transaction fails during batcher execution (account's `__validate__` rejects the empty signature), but no fee is charged and mempool capacity is exhausted for legitimate transactions. [5](#0-4) [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-313)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```
