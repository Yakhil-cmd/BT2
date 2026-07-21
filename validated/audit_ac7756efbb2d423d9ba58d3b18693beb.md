### Title
Gateway Admission Skips `__validate__` Signature Check Based on Overly Broad Pool Membership Test — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` returns `true` (skip `__validate__`) whenever `account_tx_in_pool_or_recent_block` returns `true` for the sender. That helper returns `true` for **any** transaction from the account, not only a `deploy_account`. An unprivileged attacker who observes a victim's `deploy_account` in the mempool can immediately submit a nonce-1 invoke for the same address with an arbitrary/invalid signature; the gateway accepts it without ever calling `__validate__`, blocking the victim's legitimate nonce-1 invoke with a `DuplicateNonce` error.

### Finding Description

`skip_stateful_validations` is the sequencer-native analog of the external `_withdrawFromTarget` boolean-return bug: a predicate that is supposed to evaluate a specific condition (`deploy_account` is pending) instead evaluates a strictly weaker condition (any account activity exists), causing the function to return `true` in cases where it should return `false`.

**Exact code path:**

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   ← nonce/resource-bounds checks pass
       ├─ validate_by_mempool            ← mempool nonce/fee-escalation checks pass
       └─ skip_stateful_validations      ← returns true (BUG)
            └─ account_tx_in_pool_or_recent_block(sender)
                 returns true for ANY pooled tx, not only deploy_account
  └─ run_validate_entry_point(skip_validate = true)
       └─ execution_flags.validate = false  ← __validate__ never called
``` [1](#0-0) 

The comment in the code acknowledges the broad check:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or **transactions with future nonces that passed validations**."

The second branch of that reasoning is the defect. Future-nonce transactions passing validation proves only that *those* transactions carry a valid signature; it says nothing about the signature on the nonce-1 invoke being submitted now. [2](#0-1) 

`account_tx_in_pool_or_recent_block` checks pool membership and committed-nonce history — neither of which is type-filtered to `deploy_account`: [3](#0-2) 

When `skip_validate = true`, `execution_flags.validate` is set to `false`, so `StatefulValidator::perform_validations` returns before calling the `__validate__` entry point: [4](#0-3) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can inject a nonce-1 invoke with an arbitrary signature for any account whose `deploy_account` is visible in the mempool. The gateway accepts it without signature verification. The victim's legitimate nonce-1 invoke is then rejected with `DuplicateNonce`. The fake transaction will fail at blockifier execution time, but it occupies the nonce-1 slot and forces the victim to either wait for TTL expiry or pay a fee-escalation premium to displace it.

### Likelihood Explanation

**Medium.** The attack requires only:
1. Monitoring the public mempool for `deploy_account` transactions (trivially observable).
2. Submitting a nonce-1 invoke for the victim's address before the victim's own nonce-1 invoke arrives.

No privileged access, no special account state, and no cryptographic capability is required. The deploy_account + invoke UX flow is the primary onboarding path for new accounts, making the target population large.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific check that returns `true` only when a `deploy_account` transaction for the sender is present in the pool. The mempool should expose a `deploy_account_in_pool(address) -> bool` query, and `skip_stateful_validations` should call that instead:

```rust
// Current (too broad):
return mempool_client
    .account_tx_in_pool_or_recent_block(tx.sender_address())
    .await ...;

// Correct:
return mempool_client
    .deploy_account_in_pool(tx.sender_address())
    .await ...;
```

This preserves the intended UX improvement (skip `__validate__` when the deploy_account is genuinely pending) while closing the griefing vector.

### Proof of Concept

1. Alice submits `deploy_account` for address `X` (nonce = 0). It enters the mempool.
2. Mallory observes `X` in the mempool via `account_tx_in_pool_or_recent_block`.
3. Mallory submits `invoke(sender=X, nonce=1, signature=[0xde, 0xad, ...])` — an invalid signature.
4. Gateway: `validate_nonce` passes (account_nonce=0, tx_nonce=1, within `max_allowed_nonce_gap`).
5. Gateway: `validate_by_mempool` passes (no existing nonce-1 tx for `X`).
6. Gateway: `skip_stateful_validations` — `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(X)==true` → returns `true`.
7. Gateway: `run_validate_entry_point(skip_validate=true)` → `execution_flags.validate=false` → `__validate__` not called → Mallory's fake invoke accepted.
8. Alice submits her valid `invoke(sender=X, nonce=1)` → rejected: `DuplicateNonce`.
9. Alice must pay fee-escalation premium or wait for Mallory's fake tx to expire (TTL).

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
```
