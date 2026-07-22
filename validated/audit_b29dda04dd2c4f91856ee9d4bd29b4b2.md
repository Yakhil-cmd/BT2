### Title
Invoke Transaction with Invalid Signature Bypasses `__validate__` and Is Admitted to the Mempool via Overly Broad `skip_stateful_validations` Check - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry point (signature verification) for an Invoke transaction with nonce=1 when `account_tx_in_pool_or_recent_block` returns true. This check is overly broad: it returns true for **any** transaction from the account in the pool or a recent block, not exclusively for a `deploy_account` transaction. An unprivileged attacker who observes that a target account has any pending transaction in the mempool can inject a nonce=1 Invoke with an **invalid signature** that passes all gateway checks and is admitted to the mempool without signature verification.

### Finding Description

`skip_stateful_validations` (lines 429–461) is designed to improve UX for the simultaneous `deploy_account + invoke` submission pattern. It skips the blockifier `__validate__` call when all three conditions hold:

1. The transaction is an `ExecutableTransaction::Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)` (post-deploy nonce)
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet on-chain)
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

The comment on line 441–443 states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is incorrect. `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

It returns `true` for **any** transaction type from that address — including a regular nonce=0 Invoke — not only for a `deploy_account`. When the legitimate user submits a nonce=0 Invoke (account_nonce=0 in state), the attacker can immediately submit a nonce=1 Invoke with an **arbitrary/invalid signature**. The gateway path is:

1. `validate_state_preconditions` → nonce check passes (0 ≤ 1 ≤ 200)
2. `validate_by_mempool` → passes (no duplicate hash, nonce in range)
3. `skip_stateful_validations` → returns `true` (account has a tx in pool)
4. `run_validate_entry_point` is called with `execution_flags.validate = !skip_validate = false` [3](#0-2) 

With `validate = false`, `validate_tx` returns `Ok(None)` immediately without calling the account's `__validate__` entry point: [4](#0-3) 

The invalid-signature transaction is accepted into the mempool and occupies the nonce=1 slot for that account.

The `max_nonce_for_validation_skip` default is `Nonce(Felt::ONE)`, so the skip window is exactly nonce=1. [5](#0-4) 

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts an invalid (wrong-signature) transaction before sequencing.**

The attacker's nonce=1 Invoke with an invalid signature occupies the nonce=1 slot in the mempool. The legitimate user's nonce=1 Invoke is rejected as a duplicate nonce or must pay fee escalation to displace it. The invalid transaction will fail during batcher execution (the batcher calls `__validate__` with `validate=true`), but the legitimate user's transaction is blocked from the mempool in the interim. This is a targeted griefing attack against any account that has a pending nonce=0 Invoke in the mempool.

### Likelihood Explanation

**Medium.** The attacker only needs to observe the public mempool for accounts with a nonce=0 Invoke and account_nonce=0 in state, then race-submit a nonce=1 Invoke with a garbage signature. No privileged access, no special capability, and no knowledge of the account's private key is required. The attack is limited to the nonce=1 slot per account (due to `max_nonce_for_validation_skip = 1`), but it is repeatable across many accounts.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the sender address in the mempool or a recent block. Alternatively, add a dedicated `deploy_account_in_pool_or_recent_block(address)` query to the mempool that only returns `true` when a `DeployAccount` transaction is present, preserving the intended UX without opening the signature-bypass window to arbitrary pending transactions.

### Proof of Concept

```
1. Account A: on-chain nonce = 0 (not deployed).

2. Legitimate user submits:
     Invoke(sender=A, nonce=0, signature=VALID_SIG, ...)
   → Passes all gateway checks, enters mempool.
   → account_tx_in_pool_or_recent_block(A) now returns true.

3. Attacker submits:
     Invoke(sender=A, nonce=1, signature=GARBAGE, calldata=attacker_calldata)

4. Gateway stateful validation:
   a. validate_nonce: account_nonce=0, tx_nonce=1, max_gap=200 → PASS
   b. validate_by_mempool: no duplicate hash, nonce in range → PASS
   c. skip_stateful_validations:
        tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
        → returns true
   d. run_validate_entry_point(skip_validate=true):
        execution_flags.validate = false
        → __validate__ NOT called → PASS

5. Attacker's nonce=1 Invoke with GARBAGE signature is now in the mempool.

6. Legitimate user submits their nonce=1 Invoke:
   → validate_by_mempool rejects it: DuplicateNonce(A, 1)
   → Legitimate nonce=1 Invoke is blocked.

7. Batcher eventually executes attacker's nonce=1 Invoke:
   → __validate__ is called with validate=true
   → Signature verification fails → transaction reverted
   → Legitimate user's nonce=1 Invoke was never sequenced.
``` [6](#0-5) [7](#0-6) [2](#0-1)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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
