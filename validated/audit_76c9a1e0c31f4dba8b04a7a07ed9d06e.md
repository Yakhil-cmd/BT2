### Title
Unauthenticated Invoke Transaction Accepted for Any Undeployed Account via `skip_stateful_validations` Overly-Broad Mempool Check — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is designed to improve UX by allowing a user to submit a `deploy_account` + `invoke` pair simultaneously. When the conditions are met, the `__validate__` entry point (signature check) is skipped at the gateway level. The condition that gates this bypass — `account_tx_in_pool_or_recent_block(sender_address)` — checks only whether **any** transaction from that address exists in the mempool, not whether a `deploy_account` transaction specifically exists. An unprivileged attacker can exploit this to inject an invoke transaction for **any victim's undeployed account** that has a pending `deploy_account` in the mempool, without providing a valid signature, causing the gateway to admit the transaction and the mempool to queue it.

---

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` returns `true` (skip `__validate__`) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)`.
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: !skip_validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the `__validate__` call is entirely skipped and the function returns `Ok(())`: [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

This returns `true` if the address has **any** transaction in the pool — including a `deploy_account` submitted by the victim. It does **not** verify that the queued transaction is a `deploy_account` or that the caller is the account owner.

The code comment acknowledges the intent but does not restrict to deploy-account transactions: [5](#0-4) 

**Attack path:**

1. Victim Alice broadcasts a `deploy_account` for her address (nonce=0). It enters the mempool.
2. Attacker observes Alice's address in the mempool.
3. Attacker crafts an `InvokeV3` with `sender_address = Alice`, `nonce = 1`, arbitrary `calldata`, and an invalid/arbitrary `signature`.
4. Gateway stateless checks pass (valid format, resource bounds, DA modes).
5. `extract_state_nonce_and_run_validations` reads `account_nonce = 0` from state (Alice not deployed yet).
6. `skip_stateful_validations` fires: nonce=1, account_nonce=0, Alice is in pool → returns `true`.
7. `run_validate_entry_point` is called with `validate: false` → `__validate__` is **not called**.
8. The attacker's invoke passes gateway validation and is forwarded to the mempool. [6](#0-5) 

---

### Impact Explanation

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

An invoke transaction carrying an invalid (attacker-controlled) signature is admitted by the gateway and queued in the mempool for Alice's address. The batcher will eventually call `__validate__` and reject the attacker's transaction, but:

- The attacker's transaction occupies a nonce=1 slot for Alice's address in the mempool.
- If the attacker sets a higher tip, the batcher may select the attacker's transaction first, causing it to fail `__validate__`, consuming a batcher execution slot and delaying Alice's legitimate nonce=1 invoke to the next block.
- This is a direct analog to the external report: just as anyone could call `claim()` on behalf of a VestedZeroNFT holder and force an early-penalty withdrawal, here anyone can submit an invoke on behalf of an undeployed account and force its nonce=1 slot to be consumed by an invalid transaction.

---

### Likelihood Explanation

- The window is open for the entire duration that a `deploy_account` transaction sits in the mempool (potentially many seconds to minutes).
- The attacker needs only to observe the mempool for pending `deploy_account` transactions (public information via the gateway's RPC).
- No special privileges, funds, or cryptographic material are required.
- The attack is cheap: the attacker pays no fee (the transaction fails `__validate__` at the batcher, so no fee is charged).

---

### Recommendation

In `skip_stateful_validations`, replace the overly-broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** for the sender's address is pending in the mempool. Add a new mempool API method such as `deploy_account_in_pool(address) -> bool` that inspects the pool for a `DeployAccount` transaction type at nonce=0 for the given address, and use that instead. [7](#0-6) 

---

### Proof of Concept

```
1. Alice submits RpcDeployAccountTransactionV3 for address A (nonce=0).
   → Mempool now contains: {A: [deploy_account(nonce=0)]}

2. Attacker submits RpcInvokeTransactionV3:
     sender_address = A
     nonce          = 1
     calldata       = [arbitrary]
     signature      = [0x0, 0x0]   // invalid

3. Gateway stateless_tx_validator.validate() passes (format/size/DA checks only).

4. extract_state_nonce_and_run_validations():
     account_nonce = get_nonce_from_state(A) = 0   // A not deployed
     run_pre_validation_checks():
       validate_state_preconditions(): nonce 1 >= 0, within gap → OK
       validate_by_mempool(): duplicate/nonce check → OK
       skip_stateful_validations():
         tx.nonce() == 1 ✓
         account_nonce == 0 ✓
         account_tx_in_pool_or_recent_block(A) == true ✓  (deploy_account is in pool)
         → returns true (SKIP __validate__)
     run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator::perform_validations():
         if !tx.execution_flags.validate { return Ok(()); }  // __validate__ NOT called
       → returns Ok(())

5. Attacker's invoke is forwarded to mempool.add_tx().
   → Mempool now contains: {A: [deploy_account(nonce=0), attacker_invoke(nonce=1)]}

6. Batcher executes deploy_account(nonce=0) → A is deployed, nonce becomes 1.

7. Batcher picks attacker_invoke(nonce=1) (possibly before Alice's legitimate invoke
   if attacker set higher tip):
     perform_pre_validation_stage(): nonce check passes (nonce=1 == account_nonce=1)
     __validate__() called → signature [0x0, 0x0] fails → transaction REJECTED.

8. Alice's legitimate invoke(nonce=1) is delayed to the next block.
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-461)
```rust
/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
