### Title
`skip_stateful_validations` bypasses `__validate__` for invoke transactions via overly broad `account_tx_in_pool_or_recent_block` predicate — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call for an invoke transaction with `nonce=1` from an undeployed account, when a `deploy_account` transaction is already in the mempool (UX feature). However, the predicate it uses — `account_tx_in_pool_or_recent_block` — returns `true` whenever the account has **any** transaction in the pool or recent block, not specifically a `deploy_account`. When fee escalation is enabled, an attacker can exploit this by first seeding the pool with a valid invoke at `nonce=1`, then submitting a second invoke at `nonce=1` with an invalid signature and a higher fee. The second transaction passes `validate_by_mempool` via fee escalation, then `skip_stateful_validations` returns `true` because the first invoke is still in the pool, causing `__validate__` to be skipped entirely. The invalid-signature transaction is admitted to the mempool.

---

### Finding Description

**Broken invariant:** `skip_stateful_validations` must only return `true` (skip `__validate__`) when a `deploy_account` transaction for the sender is pending in the mempool. The actual check is weaker: it returns `true` whenever the account has any transaction in the pool or committed state.

**Root cause — `account_tx_in_pool_or_recent_block`:** [1](#0-0) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`tx_pool.contains_account` returns `true` for **any** transaction type (invoke, declare, deploy_account) stored for that address.

**Caller — `skip_stateful_validations`:** [2](#0-1) 

The function checks `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)`, then calls `account_tx_in_pool_or_recent_block`. The inline comment claims this is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." The second branch of that disjunction is the flaw: a future-nonce invoke that passed its own validation does **not** authorize skipping validation for a different invoke at the same nonce.

**Effect on `run_validate_entry_point`:** [3](#0-2) 

When `skip_validate=true`, `execution_flags.validate` is set to `false`, so the blockifier's `StatefulValidator::perform_validations` returns early without calling `__validate__`: [4](#0-3) 

**Fee escalation enables the replacement:** [5](#0-4) 

`validate_tx` calls `validate_fee_escalation`, which returns `Ok(Some(...))` (no error) when the incoming transaction's tip and max L2 gas price exceed the existing transaction's values by the configured percentage. `validate_by_mempool` therefore passes for the malicious transaction. [6](#0-5) 

**Ordering in `run_pre_validation_checks`:** [7](#0-6) 

`validate_by_mempool` is called first (passes via fee escalation), then `skip_stateful_validations` is called (returns `true` because the seed invoke is still in the pool). The invalid-signature transaction is then admitted.

---

### Impact Explanation

An attacker can submit an invoke transaction with an arbitrary (invalid) signature for an undeployed account and have it accepted into the mempool without any signature verification at the gateway. The admitted transaction replaces the legitimate seed transaction. When the batcher later executes it, `__validate__` runs and the transaction reverts, but:

- The legitimate seed transaction is permanently evicted from the mempool.
- The sequencer wastes execution resources on a guaranteed-to-revert transaction.
- The attack can be repeated continuously, constituting a targeted DoS against specific accounts and a resource-drain on the sequencer.

Matches impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- Requires fee escalation to be enabled (a supported, tested feature).
- Requires only two sequential HTTP calls to the gateway — no privileged access, no special tooling.
- The seed invoke (nonce=1) is accepted because the gateway allows a nonce gap of at least 1 for invoke transactions.
- The attack is repeatable and cheap.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a predicate that specifically verifies a `deploy_account` transaction is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool` that inspects transaction types, mirroring the more precise check already present in `native_blockifier/src/py_validator.rs`: [8](#0-7) 

That implementation correctly gates the skip on `deploy_account_tx_hash.is_some()` — i.e., an explicit deploy-account hash passed by the caller — rather than on the presence of any transaction for the account.

---

### Proof of Concept

```
# Prerequisites: fee escalation enabled, max_allowed_nonce_gap >= 1

# Step 1 — seed the pool with a valid invoke at nonce=1 for undeployed account A
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<A>",
  "nonce": "0x1",
  "signature": ["<valid_sig_r>", "<valid_sig_s>"],
  "tip": "0x64",                  # tip = 100
  "resource_bounds": { ... },
  "calldata": [...]
}
# → accepted; account A now has a tx in the pool; account_nonce on-chain = 0

# Step 2 — submit a replacement invoke with invalid signature and higher fee
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<A>",
  "nonce": "0x1",
  "signature": ["0xdead", "0xbeef"],   # invalid signature
  "tip": "0x6e",                        # tip = 110 (≥ 100 * 1.1, satisfies fee_escalation_percentage=10)
  "resource_bounds": { ... },
  "calldata": ["<arbitrary>"]
}

# Gateway flow for Step 2:
# 1. validate_state_preconditions: nonce=1, account_nonce=0, within gap → PASS
# 2. validate_by_mempool: fee escalation valid (tip 110 > 100*1.1) → PASS
# 3. skip_stateful_validations:
#      tx.nonce()==1 && account_nonce==0 → enters branch
#      account_tx_in_pool_or_recent_block(A) → TRUE (seed invoke is in pool)
#      returns true
# 4. run_validate_entry_point(skip_validate=true):
#      execution_flags.validate = false
#      __validate__ is NOT called
# → invalid-signature invoke admitted to mempool, seed invoke evicted
```

### Citations

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

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
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
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/native_blockifier/src/py_validator.rs (L108-120)
```rust

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
```
