### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Transactions into Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (the only place where an account contract verifies its signature) for any invoke transaction with nonce 1 sent from an undeployed address, provided `account_tx_in_pool_or_recent_block` returns `true` for that address. Because that check only tests whether *any* transaction from the address is in the mempool — not that a `deploy_account` from the *same signer* is present — an unprivileged attacker who observes a victim's `deploy_account` in the mempool can inject an invoke with an arbitrary (invalid) signature from the victim's address and have it admitted to the mempool without any signature check.

---

### Finding Description

**Relevant code path:**

`add_tx_inner` → `extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `skip_stateful_validations` [1](#0-0) 

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` is called with `validate: false`: [2](#0-1) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations`, when `validate = false` the `__validate__` call is entirely skipped: [3](#0-2) 

```rust
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← exits here; __validate__ never runs
    }
    let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
    ...
}
```

`__validate__` is the account contract's only mechanism for verifying the transaction signature. Skipping it means the gateway admits the transaction without any cryptographic check on the caller's authorization.

**The broken invariant in `account_tx_in_pool_or_recent_block`:** [4](#0-3) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` whenever *any* transaction from `account_address` is present — including a `deploy_account` submitted by a completely different party. There is no check that the pending `deploy_account` was signed by the same key that would authorize the invoke.

**Mempool nonce validation does not close the gap:** [5](#0-4) 

```rust
fn validate_incoming_tx(...) -> MempoolResult<()> {
    if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
        return Err(MempoolError::DuplicateTransaction { ... });
    }
    self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
    // only checks tx_nonce < account_nonce (NonceTooOld)
}
```

There is no per-`(address, nonce)` uniqueness check, so the attacker's invoke and the victim's legitimate invoke can coexist in the mempool simultaneously.

---

### Impact Explanation

An attacker can inject an invoke transaction carrying an invalid (or entirely fabricated) signature into the mempool, bypassing the gateway's admission invariant that every accepted transaction has been authorized by its sender. The transaction will fail during block execution (because `__validate__` is called with `strict_nonce_check = true` at execution time), but:

1. **Invalid transactions are admitted** — the mempool contains a transaction that was never authorized by the account owner.
2. **Victim's legitimate invoke may be displaced or delayed** — both the attacker's and the victim's nonce-1 invokes can coexist in the mempool; the batcher may pull the attacker's first, execute it (it reverts), and leave the victim's invoke stranded until the next block.
3. **Sequencer resources are wasted** — the sequencer pays the cost of executing a transaction that was never valid.

Impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- The victim's `deploy_account` transaction is observable from the public mempool or P2P gossip layer.
- The victim's contract address is deterministic and computable from `class_hash`, `salt`, and `constructor_calldata` (all present in the `deploy_account` transaction).
- The attacker needs only to submit a single invoke with `sender_address = victim_address`, `nonce = 1`, and any signature bytes that pass the stateless size check.
- No privileged access, no special tooling, and no race condition beyond observing the mempool is required.

---

### Recommendation

**Short term:** In `skip_stateful_validations`, replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `deploy_account` transaction for the exact address is pending, and that the pending `deploy_account`'s class hash and constructor calldata are consistent with the invoke's sender. Alternatively, require that the invoke's transaction hash is co-signed with the `deploy_account` (i.e., the two are linked by the submitter).

**Long term:** Document the security invariant that every transaction admitted to the mempool has passed `__validate__`, and add an explicit assertion or audit trail for any code path that sets `validate: false` at gateway admission time.

---

### Proof of Concept

1. Alice submits `deploy_account` (class_hash `C`, salt `S`, constructor_calldata `D`) → deterministic address `A`. Gateway validates Alice's signature; transaction enters the mempool.
2. Attacker observes the mempool, computes `A = calculate_contract_address(C, S, D, 0)`.
3. Attacker calls the gateway's `add_tx` with:
   - `RpcInvokeTransaction::V3 { sender_address: A, nonce: 1, calldata: [drain_funds_selector, ...], signature: [0x1, 0x2] }`
4. Gateway stateless validation passes (signature *size* ≤ limit; resource bounds non-zero).
5. `extract_state_nonce_and_run_validations`:
   - `get_nonce_from_state(A)` → `Nonce(0)` (account not deployed).
   - `validate_nonce`: `0 ≤ 1 ≤ 0 + max_gap` → passes.
   - `validate_by_mempool`: nonce not too old → passes.
   - `skip_stateful_validations`: `nonce == 1 && account_nonce == 0 && account_tx_in_pool_or_recent_block(A) == true` → returns `true`.
6. `run_validate_entry_point` called with `validate: false` → `__validate__` never executes.
7. Attacker's invoke (with fabricated signature) is forwarded to the mempool and accepted.
8. At block execution time, the batcher may pull the attacker's invoke before Alice's; it reverts on `__validate__`, wasting gas and potentially delaying Alice's nonce-1 invoke. [6](#0-5) [7](#0-6) [1](#0-0) [8](#0-7)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-313)
```rust
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-96)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
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
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

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
