### Title
`skip_stateful_validations` Accepts Invoke Transactions with Invalid Signatures When Any Transaction from the Sender Exists in the Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the account's `__validate__` entry point (signature verification) for any invoke transaction with `nonce=1` when the sender address has **any** transaction in the mempool. The check `account_tx_in_pool_or_recent_block` does not verify that the mempool transaction is specifically a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool can submit an invoke with `nonce=1` from the victim's address carrying an arbitrary/invalid signature, and the gateway will admit it without running signature verification.

---

### Finding Description

The function `skip_stateful_validations` is designed to improve UX for the deploy-account + invoke flow: when a user sends both transactions simultaneously, the invoke (nonce=1) would normally fail gateway validation because the account does not yet exist on-chain. The skip is triggered when:

1. The transaction is an `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain)
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When condition 4 is satisfied, `skip_validate = true` is returned to `run_pre_validation_checks`, which passes it to `run_validate_entry_point`: [2](#0-1) 

Inside `run_validate_entry_point`, `skip_validate=true` sets `execution_flags.validate = false`, causing the blockifier's `StatefulValidator::perform_validations` to return `Ok(())` without ever calling the account's `__validate__` entry point: [3](#0-2) [4](#0-3) 

The `account_tx_in_pool_or_recent_block` check returns `true` if the address has **any** transaction in the pool or staged/committed state — it does not filter for `deploy_account` specifically: [5](#0-4) [6](#0-5) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce validity and fee-escalation rules — it does not verify the signature: [7](#0-6) 

**Attack scenario:**

1. Victim submits a `deploy_account` for address `A`. The account's on-chain nonce is `0`; the deploy_account sits in the mempool.
2. Attacker observes the deploy_account in the mempool.
3. Attacker submits `Invoke(sender=A, nonce=1, signature=<arbitrary>)`.
4. Gateway: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block(A)=true` → `skip_validate=true` → `__validate__` is never called.
5. The attacker's invoke passes all gateway checks and is admitted to the mempool.
6. If fee escalation is enabled, the attacker submits with a higher fee than the victim's invoke, replacing it via `validate_fee_escalation` / `remove_replaced_tx`. [8](#0-7) 

7. The batcher later executes: `deploy_account` succeeds (account `A` is created), then the attacker's invoke runs with `__validate__` called (batcher always validates). The invalid signature causes a revert. The victim's legitimate invoke is gone from the mempool.

The comment in the code acknowledges the assumption but states it incorrectly: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* The second case is circular — those "future nonces that passed validations" could themselves be attacker-injected invokes that bypassed validation via this same path.

---

### Impact Explanation

**High. Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway admits invoke transactions with arbitrary/invalid signatures without running the account's `__validate__` entry point. The broken invariant is: every transaction admitted to the mempool must have passed signature verification (or have a legitimate reason to defer it). Here, the reason to defer is unsound — the presence of *any* transaction from the address is used as a proxy for a `deploy_account`, which an attacker can exploit.

Concrete consequences:
- An attacker can inject signature-invalid invoke transactions into the mempool for any address that has a pending `deploy_account`.
- Via fee escalation, the attacker can displace the victim's legitimate invoke(nonce=1), causing it to be lost.
- The victim's deploy_account succeeds but their intended invoke does not execute; they must resubmit with a new nonce (since the attacker's reverted transaction increments the nonce to 2).
- The attacker can spam the mempool with invalid transactions for all observed deploy_account senders, degrading mempool quality.

---

### Likelihood Explanation

**Medium.** The attack requires:
1. Monitoring the public mempool for `deploy_account` transactions (trivially observable).
2. Submitting an invoke with `nonce=1` from the deploying address before the victim's invoke is admitted (a race, but the attacker controls timing and fee).
3. Fee escalation must be enabled for the displacement step; without it the attacker's transaction is still admitted but cannot replace the victim's.

The deploy-account + invoke UX flow is explicitly documented and tested as a supported pattern, making it a predictable target.

---

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists in the mempool for the sender address. The mempool should expose a dedicated query such as `has_deploy_account_in_pool(address)` that inspects the transaction type, rather than returning true for any transaction type. Alternatively, the gateway can inspect the transaction type of the pooled transaction before granting the skip.

---

### Proof of Concept

```
// State: account A does not exist on-chain (nonce = 0).
// Victim submits:
//   TX1: deploy_account(sender=A, nonce=0, valid_signature)  → admitted to mempool
//   TX2: invoke(sender=A, nonce=1, calldata=transfer_to_victim, valid_signature)

// Attacker observes TX1 in mempool, then submits:
//   TX3: invoke(sender=A, nonce=1, calldata=transfer_to_attacker, signature=0xdeadbeef, tip=TX2.tip * 2)

// Gateway stateful validation for TX3:
//   account_nonce = get_nonce_from_state(A) = 0          ✓ (account not deployed)
//   tx_nonce = 1                                          ✓
//   account_tx_in_pool_or_recent_block(A) = true          ✓ (TX1 is in pool)
//   → skip_validate = true
//   → run_validate_entry_point called with validate=false
//   → __validate__ NOT called
//   → TX3 admitted to mempool

// Fee escalation: TX3.tip > TX2.tip → TX3 replaces TX2 in the mempool.

// Batcher executes block:
//   TX1 executes: deploy_account succeeds, account A created, nonce → 1
//   TX3 executes: __validate__ called with signature=0xdeadbeef → REVERT, nonce → 2

// Result: victim's TX2 is gone; victim must resubmit with nonce=2.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-315)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-95)
```rust
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
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
