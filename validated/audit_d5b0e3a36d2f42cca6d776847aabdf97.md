### Title
Unauthenticated Invoke Transaction Bypasses `__validate__` via `skip_stateful_validations`, Occupying Victim's Nonce Slot in Mempool - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce=1` when the on-chain account nonce is `0` and `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. The check does not verify that the submitter of the invoke is the same party who submitted the deploy_account. An unprivileged attacker who observes a victim's `deploy_account` in the mempool can submit an invoke for the victim's address with an invalid signature, have it admitted to the mempool without signature verification, and thereby occupy the victim's `nonce=1` slot — causing the victim's legitimate first invoke to be rejected with `DuplicateNonce`.

### Finding Description

`skip_stateful_validations` is a UX feature that allows a user to broadcast `deploy_account` + `invoke` simultaneously. It returns `true` (skip `__validate__`) when:

1. The transaction is an `Invoke` with `tx.nonce() == 1`
2. The on-chain `account_nonce == 0` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

The third condition is satisfied by the presence of **any** transaction from `sender_address` in the mempool — including the victim's own `deploy_account`. The function does not verify that the caller of the incoming invoke is the same party who submitted the deploy_account.

When `skip_validate = true`, `run_validate_entry_point` sets `validate: !skip_validate = false`: [2](#0-1) 

This causes `StatefulValidator::perform_validations` to return `Ok(())` immediately after `perform_pre_validation_stage`, without ever calling `__validate__`: [3](#0-2) 

The `perform_pre_validation_stage` uses `strict_nonce_check = false`, so a future nonce (`1 > 0`) is accepted and the nonce is incremented in the ephemeral `CachedState` (not persisted): [4](#0-3) 

The transaction then passes `validate_by_mempool` (no existing `nonce=1` tx for the victim yet) and is forwarded to the mempool via `mempool_client.add_tx`: [5](#0-4) 

Once the attacker's invalid-signature invoke occupies `nonce=1` for the victim's address in the mempool, the victim's legitimate invoke with `nonce=1` is rejected: [6](#0-5) 

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction and rejects a valid one before sequencing.**

The attacker's invalid-signature invoke is admitted to the mempool without any signature check. The victim's correctly-signed invoke with the same nonce is rejected with `MempoolError::DuplicateNonce`. The victim's first post-deployment transaction is blocked. The attacker can repeat this each time the invalid invoke is evicted (TTL or block commit), creating a sustained DoS against the victim's account at the critical deploy+invoke window. In time-sensitive DeFi contexts this causes direct economic harm.

### Likelihood Explanation

**Medium.** The attacker must observe a victim's `deploy_account` in the mempool before the victim submits their invoke. Mempool contents are observable via the P2P gossip layer and RPC. The window is the time between the victim's `deploy_account` being admitted and the victim's invoke being submitted — a window that is deliberately widened by the UX feature itself. No special privileges are required; any network participant can submit an `RpcTransaction::Invoke` to the gateway.

### Recommendation

`skip_stateful_validations` must verify that the transaction already in the mempool for `sender_address` is specifically a `deploy_account` transaction, not merely any transaction. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool`, or the gateway should check the transaction type before granting the skip. Alternatively, the skip should only be granted when the incoming invoke's `sender_address` matches the address derived from the deploy_account's constructor arguments, binding the skip to the same identity.

### Proof of Concept

```
1. Victim V submits deploy_account for address V (nonce=0).
   → Passes gateway (nonce=0, account_nonce=0, __validate__ runs, signature valid).
   → Mempool now contains V's deploy_account; account_tx_in_pool_or_recent_block(V) = true.

2. Attacker A submits invoke(sender=V, nonce=1, calldata=[anything], signature=[garbage]).

3. Gateway stateful validation for A's invoke:
   a. validate_nonce: nonce=1, account_nonce=0, max_allowed_nonce_gap>=1 → PASS.
   b. validate_by_mempool: no existing nonce=1 tx for V → PASS.
   c. skip_stateful_validations:
        tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(V)==true
        → returns true (skip __validate__).
   d. run_validate_entry_point(skip_validate=true):
        ExecutionFlags { validate: false, strict_nonce_check: false, ... }
        → perform_pre_validation_stage passes (0 <= 1, nonce incremented in CachedState).
        → __validate__ NOT called. Signature never checked.
        → returns Ok(()).

4. A's invalid invoke is forwarded to mempool → accepted at nonce=1 for address V.

5. Victim V submits legitimate invoke(sender=V, nonce=1, valid signature).
   → validate_by_mempool → mempool.validate_tx → validate_fee_escalation:
        existing tx at (V, nonce=1) found, fee escalation disabled
        → MempoolError::DuplicateNonce.
   → V's legitimate invoke is REJECTED.

6. A's invalid invoke is eventually included in a block, __validate__ runs (validate=true),
   fails due to invalid signature, tx is reverted. Attacker repeats from step 2.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L490-497)
```rust
        let valid_nonce = if strict {
            account_nonce == incoming_tx_nonce
        } else {
            account_nonce <= incoming_tx_nonce
        };
        if valid_nonce {
            return Ok(state.increment_nonce(address)?);
        }
```

**File:** crates/apollo_gateway/src/gateway.rs (L263-286)
```rust
        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
```

**File:** crates/apollo_mempool/src/mempool.rs (L768-771)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };
```
