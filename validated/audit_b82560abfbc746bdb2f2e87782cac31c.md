### Title
Gateway Admits Unsigned Invoke Transactions via `skip_stateful_validations` Bypass — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validation path skips the `__validate__` entry-point call (the account's own signature-verification step) for any Invoke transaction with `nonce == 1` when the on-chain account nonce is `0` and *any* transaction for that address exists in the mempool or a recent block. Because the mempool check is not restricted to deploy-account transactions, an unprivileged attacker who observes a victim's pending `deploy_account` in the mempool can inject an Invoke with an arbitrary signature that is admitted without signature verification, blocking the victim's legitimate first post-deploy Invoke for at least one block.

### Finding Description

**Invariant broken:** Every transaction admitted to the mempool must have passed the account's `__validate__` entry point (signature verification).

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
1. The transaction is an Invoke with `tx.nonce() == 1`, and
2. The on-chain `account_nonce == 0`, and
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

The third check is implemented as: [2](#0-1) 

It returns `true` if the address appears in either the mempool's transaction pool **or** its committed-nonce state map — it does **not** verify that the existing transaction is specifically a `deploy_account`. The comment in the code acknowledges this:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is only sound if no other path can place a transaction for an undeployed account into the mempool. However, the `deploy_account` transaction itself is publicly visible in the mempool, and the attacker does not need to know the victim's private key to trigger the skip.

**How `skip_validate=true` propagates:** [3](#0-2) 

When `skip_validate=true`, `validate: !skip_validate` is set to `false`. Inside `validate_tx`: [4](#0-3) 

The `__validate__` entry point is never called, so the account's signature is never checked at gateway admission time.

**Attack steps:**

1. Victim broadcasts a `deploy_account` transaction for address V (nonce=0). It enters the mempool.
2. Attacker observes the pending `deploy_account` in the mempool.
3. Attacker submits `Invoke(sender=V, nonce=1, calldata=<anything>, signature=<garbage>)`.
4. Gateway reads on-chain nonce for V → `0`.
5. `validate_nonce` passes (0 ≤ 1 ≤ 200).
6. `validate_by_mempool` passes (no duplicate nonce=1 yet).
7. `skip_stateful_validations`: nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block(V)` == `true` (deploy_account is in pool) → returns `true`.
8. `run_validate_entry_point` is called with `validate=false` → `__validate__` is **not** called.
9. Attacker's Invoke is admitted to the mempool with an invalid signature.
10. Victim tries to submit their legitimate Invoke(nonce=1) → mempool rejects with `DuplicateNonce`. [5](#0-4) 

11. At execution time, the batcher runs the attacker's Invoke with `validate=true, strict_nonce_check=true` (via `new_for_sequencing`). `__validate__` runs and fails. The transaction is rejected and removed from the mempool.
12. Victim can now resubmit — but their first post-deploy Invoke has been delayed by at least one block.

### Impact Explanation

**Admission of invalid transactions (High):** The gateway admits an Invoke transaction whose signature has never been verified. The invariant "every mempool transaction has passed `__validate__`" is broken.

**Griefing / nonce-slot squatting:** The attacker occupies the victim's nonce=1 slot in the mempool, preventing the victim's legitimate Invoke from being submitted until the attacker's transaction is executed and rejected (one block later). This can be repeated indefinitely for every new account deployment observed in the mempool.

**No privileged access required:** The attacker only needs to observe the public mempool and submit a standard Invoke RPC call.

### Likelihood Explanation

The mempool is public and `deploy_account` transactions are visible to all nodes. Any attacker monitoring the mempool can trigger this for every new account deployment. The attack requires no special knowledge of the victim's private key, class hash, or constructor arguments.

### Recommendation

In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that verifies a **deploy-account** transaction specifically exists for the sender address. One approach is to expose a `deploy_account_tx_in_pool(address)` query on the mempool that only returns `true` when the pending transaction for that address at nonce=0 is of type `DeployAccount`. Alternatively, mirror the stronger check already used in `PyValidator::should_run_stateful_validations`, which requires the caller to explicitly supply the `deploy_account_tx_hash`: [6](#0-5) 

The gateway should require the client to supply the `deploy_account` transaction hash alongside the Invoke, and verify that hash exists in the mempool as a `DeployAccount` transaction before skipping `__validate__`.

### Proof of Concept

```
# Precondition: victim's deploy_account for address V is in the mempool (nonce=0)

POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<V>",
  "nonce": "0x1",
  "calldata": ["0xdeadbeef"],
  "signature": ["0x1111", "0x2222"],   # arbitrary garbage
  "resource_bounds": { ... }
}

# Expected (correct): rejected with ValidateFailure
# Actual: accepted (HTTP 200, returns tx_hash)
#
# Consequence: victim's legitimate Invoke(nonce=1) is now rejected
# with DuplicateNonce until the attacker's tx is executed and purged.
```

The gateway path that admits the transaction without calling `__validate__`: [7](#0-6) [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-314)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L757-791)
```rust
    /// `(address, nonce)` via fee escalation, without mutating any state. Returns the existing
    /// transaction to be replaced when a valid replacement exists, `None` when there is nothing to
    /// replace, or an error when a replacement is present but not permitted.
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

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

        Ok(Some(existing_tx_reference))
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L993-1001)
```rust
    fn validate_tx(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut GasCounter,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !self.execution_flags.validate {
            return Ok(None);
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
