### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission for Undeployed Accounts - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call for any Invoke transaction with `nonce == 1` targeting an account whose on-chain nonce is `0`, provided that *any* transaction for that address exists in the mempool or a recent block. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a crafted Invoke (nonce=1) for the victim's address with an arbitrary or empty signature. The gateway admits this transaction without signature verification, inserting it into the mempool and occupying the victim's nonce-1 slot.

### Finding Description

`skip_stateful_validations` is an intentional UX feature that allows a user to broadcast `deploy_account + invoke(nonce=1)` simultaneously, before the account is deployed on-chain. The gateway skips the `__validate__` call because the account contract does not yet exist and cannot verify a signature. [1](#0-0) 

The skip condition is:

```
tx.nonce() == Nonce(Felt::ONE)
  && account_nonce == Nonce(Felt::ZERO)
  && mempool_client.account_tx_in_pool_or_recent_block(sender_address) == true
``` [2](#0-1) 

The third predicate calls `account_tx_in_pool_or_recent_block`, which returns `true` if the account has **any** transaction in the pool or any recently committed block — it does not verify that the pooled transaction is specifically a `deploy_account`: [3](#0-2) 

When `skip_validate` is `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so `StatefulValidator::validate` never calls `tx.validate_tx(...)`: [4](#0-3) 

The full pre-validation chain is: [5](#0-4) 

`validate_by_mempool` (called before `skip_stateful_validations`) only rejects duplicate nonces or fee-escalation violations — it does not verify signatures: [6](#0-5) 

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the mempool can:

1. Read the victim's contract address from the `deploy_account` payload (publicly visible).
2. Craft an `Invoke` transaction for that address with `nonce = 1`, arbitrary calldata, and an invalid or empty signature.
3. Submit it to the gateway. The gateway evaluates:
   - `tx.nonce() == 1` ✓
   - `account_nonce == 0` ✓ (account not yet on-chain)
   - `account_tx_in_pool_or_recent_block(victim_address)` ✓ (victim's `deploy_account` is pooled)
4. Signature validation is skipped; the attacker's Invoke is admitted to the mempool.
5. The victim's legitimate `invoke(nonce=1)` is subsequently rejected by the mempool as `DuplicateNonce`. [7](#0-6) 

The victim must perform fee escalation to displace the attacker's transaction. If the attacker continuously replaces their own transaction (fee escalation race), the victim is forced to pay progressively higher fees. The attacker's transaction will ultimately fail at blockifier execution time (the account's `__validate__` rejects the wrong signature), but the nonce-1 slot remains occupied in the mempool until that point, blocking the victim's legitimate invoke.

This matches the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The attack requires only:
- Monitoring the public mempool for `deploy_account` transactions (trivially observable).
- Submitting a single Invoke with a known address and nonce=1 (no privileged access, no special knowledge).

The window is the time between the victim's `deploy_account` entering the mempool and the victim's `invoke(nonce=1)` being submitted. For the intended UX flow (simultaneous broadcast), this window is small but non-zero due to network propagation. For users who submit `deploy_account` first and `invoke` later, the window is arbitrarily large.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a targeted query that confirms the pooled transaction is specifically a `deploy_account` for the same sender address. Alternatively, expose a `has_pending_deploy_account(address)` predicate from the mempool that inspects the transaction type, and use that as the skip condition:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())

// Use:
mempool_client.has_pending_deploy_account(tx.sender_address())
```

This ensures that signature validation is only skipped when a genuine `deploy_account` is pending, not when any arbitrary transaction (including an attacker's prior invoke) exists for the address.

### Proof of Concept

```
1. Victim broadcasts deploy_account(address=A, nonce=0, sig=valid).
   → Mempool now contains: A → [deploy_account(nonce=0)]

2. Attacker observes A in the mempool.
   Attacker crafts: invoke(sender=A, nonce=1, calldata=arbitrary, sig=EMPTY)
   Attacker submits to gateway.

3. Gateway stateful validation:
   - get_nonce_from_state(A) → 0  (account not on-chain)
   - validate_state_preconditions: nonce 1 is within [0, 0+max_gap] → OK
   - validate_by_mempool: no duplicate nonce 1 yet → OK
   - skip_stateful_validations:
       tx.nonce() == 1 ✓
       account_nonce == 0 ✓
       account_tx_in_pool_or_recent_block(A) == true ✓  ← deploy_account is pooled
     → returns true (skip)
   - run_validate_entry_point called with validate=false → __validate__ NOT called

4. Attacker's invoke(nonce=1, sig=EMPTY) is added to mempool.
   Mempool: A → [deploy_account(nonce=0), attacker_invoke(nonce=1)]

5. Victim submits legitimate invoke(sender=A, nonce=1, sig=valid).
   → Mempool rejects: DuplicateNonce { address: A, nonce: 1 }

6. Victim must fee-escalate to displace attacker's transaction.
``` [1](#0-0) [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-711)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }

    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
            return Err(MempoolError::DuplicateTransaction { tx_hash: tx_reference.tx_hash });
        }
        self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
    }
```
