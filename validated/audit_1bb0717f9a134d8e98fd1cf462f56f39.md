Let me look at the exact `skip_stateful_validations` logic and the mempool's `account_tx_in_pool_or_recent_block` implementation more carefully.

### Title
`skip_stateful_validations` Bypasses Signature Verification for Nonce-1 Invoke Transactions via Overly Broad Mempool Presence Check - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `skip_stateful_validations` function is intended to skip `__validate__` only when a `deploy_account` transaction is pending (account not yet deployed). However, the guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction from the sender in the mempool, not exclusively a `deploy_account`. An attacker can therefore submit a nonce-1 invoke transaction with an arbitrary/invalid signature for any deployed account that currently has a pending nonce-0 invoke transaction in the mempool, and the gateway will admit it without running `__validate__`.

### Finding Description

`skip_stateful_validations` fires when three conditions are simultaneously true:

1. The incoming transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0`
3. `account_tx_in_pool_or_recent_block(sender)` returns `true` [1](#0-0) 

The code comment claims this is safe because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." That reasoning is incorrect for the case where the account is **already deployed** (has a class hash) but its on-chain nonce is still `0` because a nonce-0 invoke transaction is sitting unexecuted in the mempool.

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`tx_pool.contains_account` returns `true` whenever **any** transaction from the address is pooled — including a plain nonce-0 invoke. There is no check that the pooled transaction is a `deploy_account`.

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

The blockifier's `StatefulValidator::perform_validations` then short-circuits before calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [4](#0-3) 

The transaction is forwarded to the mempool with no signature check performed.

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction before sequencing.**

An attacker can inject a nonce-1 invoke transaction carrying an arbitrary signature for any victim account that has a pending nonce-0 invoke transaction. The gateway accepts it without running `__validate__`. The transaction enters the mempool and blocks the victim's nonce-2+ transactions from being sequenced until the batcher processes and rejects the attacker's transaction (which fails `__validate__` at execution time). Because the mempool enforces `DuplicateNonce` for the same `(address, nonce)` pair, the victim cannot replace the attacker's slot without fee escalation, and the attacker can repeat the injection after each rejection cycle. [5](#0-4) 

### Likelihood Explanation

The mempool is publicly observable. Any attacker can monitor for accounts with a pending nonce-0 invoke transaction (on-chain nonce still 0), compute the target address, and submit a nonce-1 invoke with a garbage signature. No privileged access, special keys, or contract deployment is required. The only cost is the gateway submission itself; because `__validate__` fails at execution time the transaction is rejected and no fee is charged from the attacker.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that verifies a **`deploy_account` transaction specifically** is pending for the sender. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool`, or the gateway should inspect the transaction type of the pooled entry before granting the skip. Alternatively, mirror the `native_blockifier` approach where the caller explicitly supplies the `deploy_account_tx_hash` rather than inferring it from mempool presence: [6](#0-5) 

### Proof of Concept

1. Victim account `A` is deployed (class hash set, on-chain nonce = 0).
2. Victim submits a valid nonce-0 invoke transaction `T0`; it passes `__validate__` and enters the mempool. `tx_pool.contains_account(A)` is now `true`.
3. Attacker submits an invoke transaction for `A` with `nonce = 1` and a random/invalid signature `S_bad`.
4. Gateway stateful path: `account_nonce = 0`, `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(A) == true` → `skip_validate = true` → `__validate__` is **not called**. Transaction is admitted to the mempool.
5. Batcher sequences `T0` (nonce 0 → 1), then attempts the attacker's nonce-1 transaction. `__validate__` runs, fails on `S_bad`, transaction is rejected.
6. Victim's nonce-2+ transactions were blocked for the duration of that block. Attacker repeats from step 3 as long as the victim keeps submitting nonce-0 transactions (e.g., after a reorg or fresh account deployment). [7](#0-6) [2](#0-1)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L768-789)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
