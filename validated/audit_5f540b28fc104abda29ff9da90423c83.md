### Title
Signature Bypass via `skip_stateful_validations` Allows Admission of Unsigned Invoke Transactions into Mempool - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The `skip_stateful_validations` function in the gateway stateful validator skips the account's `__validate__` entry point (signature check) for any Invoke transaction with nonce=1 when the sender address has any transaction in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a nonce=1 Invoke transaction with an **invalid or forged signature** for the victim's address. The gateway admits it without running `__validate__`, the transaction reaches the batcher, and when executed the validation failure charges a fee from the victim's account.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

The function returns `true` (skip) when:
- The transaction is an `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)` (nonce = 1)
- `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The last check is satisfied as soon as **any** transaction from that address is in the mempool pool or the mempool's committed-block state: [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate = false`, the code returns immediately after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point: [4](#0-3) 

`perform_pre_validation_stage` with `strict_nonce_check=false` only checks that `account_nonce (0) <= tx_nonce (1)` and verifies fee bounds — it does **not** verify the transaction signature: [5](#0-4) 

The transaction is then forwarded to the mempool via `add_tx` with the unverified signature intact.

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts an invalid (unsigned) transaction before sequencing.**

The broken invariant is: *every Invoke transaction must have its signature verified by the account's `__validate__` entry point before being admitted to the mempool.* An attacker can submit a nonce=1 Invoke with an arbitrary/forged signature for any account whose `deploy_account` transaction is currently in the mempool. The transaction is admitted, reaches the batcher, and when executed the batcher runs `__validate__` (which the gateway skipped), the validation fails, and the fee is charged from the victim's account — without the victim ever authorizing the transaction.

### Likelihood Explanation

**Likelihood: Medium.** The attack window is the time between a victim's `deploy_account` transaction entering the mempool and being executed. Mempool transactions are broadcast over P2P, so an attacker can observe them in real time. The attacker pays nothing to submit the malicious Invoke (gateway submission is free); the cost is borne entirely by the victim when the fee is deducted on execution failure. The attack is limited to one nonce=1 transaction per deploy_account event, but it requires no privileged access and no knowledge of the victim's private key.

### Recommendation

1. **Do not skip `__validate__` entirely.** Instead, run `__validate__` against the class hash declared in the pending `deploy_account` transaction. The class hash is already available in the mempool entry for the deploy_account tx.
2. **Alternatively**, require the nonce=1 Invoke to carry a proof-of-authorization that can be verified without the account being deployed (e.g., a signature over the deploy_account tx hash).
3. **At minimum**, add a comment and a test that explicitly documents the invariant being relaxed and the accepted risk, so future changes do not inadvertently widen the bypass window.

### Proof of Concept

```
1. Victim submits RpcDeployAccountTransactionV3 for address A (valid, signed with victim's key).
   → deploy_account tx enters mempool; account_tx_in_pool_or_recent_block(A) == true.

2. Attacker observes the deploy_account tx via P2P broadcast.

3. Attacker constructs RpcInvokeTransactionV3:
     sender_address = A
     nonce          = 1
     signature      = [0xdead, 0xbeef]   ← arbitrary invalid signature
     calldata       = [...]               ← any calldata

4. Attacker submits the Invoke to the gateway.

5. Gateway stateful validation:
     account_nonce = get_nonce(A) = 0
     tx.nonce()    = 1
     skip_stateful_validations → account_tx_in_pool_or_recent_block(A) == true → returns true
     run_validate_entry_point(skip_validate=true) → __validate__ NOT called
     → transaction admitted to mempool ✓

6. Batcher pulls deploy_account tx (nonce=0) and executes it → account A deployed.

7. Batcher pulls attacker's Invoke tx (nonce=1) and executes it:
     perform_pre_validation_stage: nonce 0 <= 1 → OK, nonce incremented to 1
     __validate__ called → signature [0xdead, 0xbeef] fails
     → transaction reverted, fee charged from victim's balance A
``` [6](#0-5) [7](#0-6)

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
