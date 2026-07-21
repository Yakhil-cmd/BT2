Looking at the `skip_stateful_validations` function in the gateway's stateful transaction validator, I can identify a direct analog to the WSHIDO `transferFrom` bug: an authorization check that has a missing condition allowing it to be bypassed.

---

### Title
Insufficient Authorization Check in `skip_stateful_validations` Allows Injection of Unsigned Invoke Transactions into Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function skips `__validate__` (signature verification) for an invoke transaction with nonce=1 when `account_tx_in_pool_or_recent_block` returns true. However, it does not verify that the transaction in the pool is specifically a `deploy_account`. An attacker who observes a victim's pending `deploy_account` in the mempool can submit an invoke with a fake signature for the victim's address, bypassing `__validate__` entirely and injecting an unauthorized transaction into the mempool.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the `skip_stateful_validations` function implements a UX feature: when a user sends `deploy_account` + `invoke` simultaneously, the invoke's `__validate__` is skipped because the account doesn't exist on-chain yet. [1](#0-0) 

The condition for skipping is:
1. Transaction is `Invoke`
2. `tx.nonce() == 1`
3. `account_nonce == 0` (account not yet deployed on-chain)
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is flawed. `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction in the pool for the address: [2](#0-1) 

An attacker can satisfy condition 4 by observing a victim's `deploy_account` (nonce=0) in the pool, then submitting their own invoke (nonce=1) for the victim's address. The victim's `deploy_account` makes `account_tx_in_pool_or_recent_block` return `true`, triggering the skip.

The `validate_by_mempool` call that precedes `skip_stateful_validations` does not prevent this: it only checks for duplicate tx_hash and nonce conflicts. Since the victim's `deploy_account` has nonce=0 and the attacker's invoke has nonce=1, there is no conflict: [3](#0-2) 

When `skip_validate=true` is returned, `run_validate_entry_point` sets `validate: false`, meaning `__validate__` (signature verification) is never called for the attacker's transaction: [4](#0-3) 

The analog to WSHIDO is exact:
- **WSHIDO**: `if allowance != 0 { deduct allowance }` — missing condition: no guard when allowance IS 0, so transfer proceeds unconditionally.
- **Sequencer**: `if account_tx_in_pool_or_recent_block(addr) { skip __validate__ }` — missing condition: no guard that the pooled transaction is a `deploy_account`, so signature verification is skipped unconditionally.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The attacker's invoke with a fake/empty signature is accepted into the mempool without any signature verification. This:

1. **Blocks the victim's legitimate invoke**: The attacker's nonce=1 invoke occupies the slot; the victim's real invoke is rejected as `DuplicateNonce` or must pay fee escalation to replace it.
2. **Disrupts the deploy_account + invoke UX flow**: The victim's intended first action after deployment is replaced by the attacker's arbitrary calldata.
3. **Potential fee drain**: When the batcher executes the block, the attacker's invoke runs `__validate__` (the batcher sets `validate: true`), which fails. The victim's newly-deployed account is charged a fee for the failed transaction.

### Likelihood Explanation

**Medium.** The attacker must:
- Monitor the public mempool for `deploy_account` transactions targeting undeployed addresses.
- Submit their malicious invoke before the victim's legitimate invoke arrives.

Both steps are straightforward for any node connected to the network. No privileged access is required.

### Recommendation

Modify `skip_stateful_validations` to verify that the transaction in the pool for the sender address is specifically a `deploy_account`, not just any transaction. A dedicated mempool API (e.g., `has_pending_deploy_account(address)`) should be used instead of the generic `account_tx_in_pool_or_recent_block`. The current check is an overly broad proxy that conflates "account is known to the mempool" with "account has a pending deploy_account." [5](#0-4) 

### Proof of Concept

```
1. Victim submits deploy_account for address A (nonce=0).
   → Accepted into mempool. account_tx_in_pool_or_recent_block(A) now returns true.

2. Attacker submits invoke for address A:
     sender_address = A
     nonce          = 1
     signature      = [] (empty / fake)
     calldata       = <arbitrary, e.g. drain funds>

3. Gateway stateful validation for attacker's invoke:
   a. validate_nonce:          nonce=1 >= account_nonce=0, within max_allowed_nonce_gap=200 → PASS
   b. validate_by_mempool:     no tx with nonce=1 for A in pool → PASS
   c. skip_stateful_validations:
        tx.nonce() == 1          → true
        account_nonce == 0       → true
        account_tx_in_pool_or_recent_block(A) → true (victim's deploy_account is pooled)
        → returns true (skip __validate__)
   d. run_validate_entry_point: validate=false → __validate__ NOT called → PASS

4. Attacker's invoke (fake signature) is accepted into the mempool.

5. Victim submits their legitimate invoke for A (nonce=1, valid signature).
   → validate_by_mempool: DuplicateNonce for A/nonce=1 → REJECTED
     (or victim must pay fee escalation to replace attacker's tx)

6. Block execution:
   - Victim's deploy_account (nonce=0) executes → account A deployed.
   - Attacker's invoke (nonce=1) executes → __validate__ called → FAILS (fake sig).
   - Victim's account A is charged a fee for the failed transaction.
   - Victim's intended invoke never executes in this block.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
