### Title
`skip_stateful_validations` Overly Broad Condition Enables Signature Bypass via Fee Escalation for Nonce-0 Accounts — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function decides whether to skip the `__validate__` entry point (signature verification) for invoke transactions with nonce=1 when account_nonce=0. The condition it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction in the mempool, not only deploy_account transactions. This is the direct analog of the external report's "lenient path": one code path enforces signature verification strictly, while another silently skips it based on an overly permissive check. Combined with the fee escalation replacement mechanism, an unprivileged attacker can inject an invalid-signature invoke transaction into the mempool by replacing a legitimate one, bypassing the `__validate__` entry point entirely.

---

### Finding Description

The gateway's stateful validation flow has two inconsistent paths for invoke transactions with `tx_nonce == 1` and `account_nonce == 0`:

**Path 1 — Strict (normal invoke):** `run_validate_entry_point` is called with `validate: true`, which causes `StatefulValidator::perform_validations` to call the account's `__validate__` entry point and verify the signature.

**Path 2 — Lenient (skip path):** When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`. Inside `StatefulValidator::perform_validations`, the code returns `Ok(())` immediately after `perform_pre_validation_stage`, never reaching the `__validate__` call. [1](#0-0) 

The condition that selects the lenient path is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [2](#0-1) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

This returns `true` for **any** transaction in the mempool for that address — not only deploy_account transactions. The debug log message even says `"Checking if deploy_account transaction exists"`, revealing the intent was narrower than the implementation. [4](#0-3) 

The gateway also supports fee escalation: a transaction at the same `(address, nonce)` can replace an existing one if tip and max_l2_gas_price are each increased by at least `fee_escalation_percentage` (default 10%). [5](#0-4) 

The order of operations in `run_pre_validation_checks` is:
1. `validate_state_preconditions` — nonce range check (passes for nonce=1, account_nonce=0)
2. `validate_by_mempool` — mempool's `validate_tx`, which approves the fee escalation replacement
3. `skip_stateful_validations` — returns `true` because the victim's tx is still in the pool at this point (replacement has not yet occurred) [6](#0-5) 

After all three pass, `run_validate_entry_point` is called with `validate: false`, skipping `__validate__`. Then `mempool.add_tx` is called, which performs the actual replacement. [7](#0-6) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions.**

An attacker can inject an invoke transaction with an **invalid or forged signature** into the mempool for any account whose nonce is 0 in state and that already has a nonce=1 transaction in the mempool. The invalid transaction replaces the legitimate one via fee escalation. When the batcher later executes the invalid transaction, it fails (the `__validate__` entry point rejects the bad signature during actual execution, where `strict_nonce_check=true` and `validate=true`). The victim's valid transaction is permanently evicted from the mempool and must be resubmitted.

A second, simpler variant requires no fee escalation: if account X has only a deploy_account transaction in the mempool (nonce=0, account not yet deployed), an attacker can submit a nonce=1 invoke with an invalid signature. `account_tx_in_pool_or_recent_block` returns `true` due to the deploy_account, `__validate__` is skipped, and the invalid invoke is admitted. This allows any observer to inject failing transactions for any account in the middle of a deploy_account + invoke flow.

---

### Likelihood Explanation

**Likelihood: Medium.**

- The condition `tx_nonce == 1 && account_nonce == 0` is common: every newly deployed account and every account that has never sent a transaction is in this state.
- The mempool is observable (transactions are broadcast over P2P), so an attacker can detect when a target account has a nonce=1 tx pending.
- Fee escalation is enabled by default (`enable_fee_escalation: true`, `fee_escalation_percentage: 10`).
- No privileged access is required; any unprivileged user can submit transactions to the gateway.

---

### Recommendation

The `skip_stateful_validations` function should verify that the existing mempool entry for the account is specifically a **deploy_account** transaction, not any arbitrary transaction. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool`, and `skip_stateful_validations` should call that instead of `account_tx_in_pool_or_recent_block`.

Alternatively, the skip should only be granted when the incoming invoke's nonce equals exactly `account_nonce + 1` **and** the mempool contains a deploy_account at nonce=0 for that address, with no other nonce=1 transaction already present (to prevent fee-escalation replacement from bypassing the check).

---

### Proof of Concept

**Scenario A — Fee escalation signature bypass (existing deployed account, nonce=0):**

```
State: Account X deployed, nonce = 0 in chain state.

Step 1: Alice submits Invoke(sender=X, nonce=1, sig=VALID, tip=100, max_l2_gas_price=100)
        → passes __validate__ → admitted to mempool.

Step 2: Attacker submits Invoke(sender=X, nonce=1, sig=INVALID, tip=110, max_l2_gas_price=110)
        → validate_nonce:       0 <= 1 <= 200  ✓
        → validate_by_mempool:  10% fee escalation satisfied  ✓
        → skip_stateful_validations:
              tx.nonce() == 1  ✓
              account_nonce == 0  ✓
              account_tx_in_pool_or_recent_block(X) == true  ✓  (Alice's tx still in pool)
              returns true  →  validate = false
        → run_validate_entry_point: __validate__ SKIPPED  ✓
        → mempool.add_tx: replaces Alice's valid tx with attacker's invalid tx  ✓

Step 3: Batcher executes attacker's tx → __validate__ called with strict=true → FAILS (bad sig)
        Alice's tx is gone. Alice must resubmit.
```

**Scenario B — Deploy-account griefing (no fee escalation needed):**

```
State: Account X does not exist yet (nonce = 0).

Step 1: Alice submits DeployAccount(X, nonce=0) → admitted to mempool.

Step 2: Attacker submits Invoke(sender=X, nonce=1, sig=INVALID)
        → validate_nonce:       0 <= 1 <= 200  ✓
        → validate_by_mempool:  no existing nonce=1 tx, no duplicate  ✓
        → skip_stateful_validations:
              account_tx_in_pool_or_recent_block(X) == true  ✓  (Alice's deploy_account)
              returns true  →  validate = false
        → __validate__ SKIPPED  ✓
        → invalid invoke admitted to mempool  ✓

Step 3: Batcher executes DeployAccount → X deployed, nonce=1.
        Batcher executes attacker's invoke → __validate__ FAILS (bad sig, wasted slot).
        If Alice also submitted a valid nonce=1 invoke, attacker can replace it via Scenario A.
```

### Citations

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-458)
```rust
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L760-791)
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
```
