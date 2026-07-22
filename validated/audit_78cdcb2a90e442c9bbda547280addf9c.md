### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions, Enabling Mempool Griefing - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` UX feature, designed to allow a deploy_account + invoke pair to be submitted atomically, can be exploited by an unprivileged attacker to inject an invoke transaction with an arbitrary (invalid) signature into the mempool for any account whose deploy_account transaction is already pending. The gateway skips the `__validate__` entry-point call entirely for such transactions, meaning no signature check is performed at admission time. The injected transaction occupies the nonce=1 slot, causing the legitimate owner's invoke to be rejected as `DuplicateNonce`.

### Finding Description

**Relevant code path:**

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs`: [1](#0-0) 

The function returns `true` (skip validation) when:
- The transaction is an `Invoke` with `nonce == 1`
- The on-chain account nonce is `0` (account not yet deployed)
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, for Invoke transactions, `perform_pre_validation_stage` is always called (nonce/fee/proof-facts checks), but the `__validate__` entry point — which is where the account contract verifies the signature — is gated on `execution_flags.validate`: [3](#0-2) 

`perform_pre_validation_stage` does **not** verify the transaction signature: [4](#0-3) 

**Attack scenario:**

1. Alice submits a `deploy_account` transaction for address `X` → admitted to mempool.
2. Attacker observes Alice's `deploy_account` in the mempool.
3. Attacker submits an `Invoke` transaction with `nonce=1`, `sender_address=X`, and an arbitrary fake signature.
4. Gateway stateless validation passes (signature length is within bounds, resource bounds are valid).
5. `validate_nonce` passes: `account_nonce=0 ≤ tx_nonce=1 ≤ max_allowed_nonce_gap`. [5](#0-4) 

6. `validate_by_mempool` passes: unique tx hash, nonce not too old. [6](#0-5) 

7. `skip_stateful_validations` returns `true` because Alice's `deploy_account` satisfies `account_tx_in_pool_or_recent_block`: [7](#0-6) 

8. The `__validate__` entry point is **never called**. The attacker's fake-signature invoke is admitted to the mempool.
9. Alice submits her legitimate `Invoke` (nonce=1) → mempool rejects it as `DuplicateNonce`: [8](#0-7) 

10. The attacker's transaction is included in a block, the account's `__validate__` runs during execution, the signature check fails, the transaction reverts — but the nonce is consumed. Alice's legitimate invoke is permanently blocked for that nonce.

The code comment in `skip_stateful_validations` states the check is "sufficient" because any account in the pool "either has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is circular: the attacker's fake invoke itself satisfies the condition after step 8, enabling further nonce-slot squatting.

### Impact Explanation

An unprivileged attacker can inject an invalid (unsigned) invoke transaction into the mempool for any account whose deploy_account is pending, causing the legitimate owner's first post-deploy invoke to be rejected. This is a direct instance of **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing"** (High impact). The invalid transaction is admitted without any signature verification, and the valid transaction is rejected with `DuplicateNonce`.

### Likelihood Explanation

The attack requires only that the attacker observe a pending `deploy_account` transaction (visible to any mempool participant in a decentralized network) and submit a competing invoke before the legitimate owner does. No privileged access, special keys, or on-chain funds are required beyond a valid-looking transaction structure. The window is the time between the `deploy_account` entering the mempool and the legitimate invoke being submitted — a race that is straightforward to win by monitoring the P2P mempool feed.

### Recommendation

The `skip_stateful_validations` check should verify that the transaction in the pool for the sender address is specifically a `deploy_account` transaction, not just any transaction. The current `account_tx_in_pool_or_recent_block` check is too broad. One approach: expose a dedicated `has_deploy_account_in_pool(address)` query from the mempool, or store the transaction type alongside the account entry so the gateway can confirm the pending transaction is a `deploy_account` before skipping signature validation.

### Proof of Concept

```
1. Alice: submit deploy_account(address=X, class_hash=C, salt=S, ctor_calldata=[pk])
   → mempool admits it; account_tx_in_pool_or_recent_block(X) = true

2. Attacker: submit invoke(sender=X, nonce=1, calldata=[drain_funds], signature=[0x1, 0x2])
   Gateway flow:
     stateless_validator.validate()          → OK (sig length ≤ max)
     convert_rpc_tx_to_internal()            → OK (hash computed)
     get_nonce_from_state(X)                 → 0
     validate_nonce(nonce=1, account=0)      → OK (0 ≤ 1 ≤ max_gap)
     validate_by_mempool(nonce=1, acct=0)    → OK (no dup hash, nonce ≥ acct)
     skip_stateful_validations(nonce=1,acct=0,pool=true) → true
     run_validate_entry_point(skip=true)     → perform_pre_validation_stage OK,
                                               __validate__ NOT called
   → attacker's invoke admitted to mempool

3. Alice: submit invoke(sender=X, nonce=1, calldata=[real_call], signature=[r,s])
   → mempool: DuplicateNonce {address: X, nonce: 1} → REJECTED

4. Block execution:
   deploy_account(X) executes → account deployed
   attacker's invoke(nonce=1) executes → __validate__ called → sig [0x1,0x2] invalid → REVERT
   (nonce consumed; Alice must now use nonce=2 and resubmit)
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-297)
```rust
            _ => {
                let max_allowed_nonce =
                    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
                if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: {account_nonce} <= nonce <= \
                         {max_allowed_nonce}, got: {incoming_tx_nonce}."
                    )));
                }
            }
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
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
        }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

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

**File:** crates/apollo_mempool/src/mempool.rs (L768-773)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
```
