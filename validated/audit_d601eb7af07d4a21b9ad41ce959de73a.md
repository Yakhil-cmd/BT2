### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures When Any Pending Transaction Exists for the Sender Address - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (signature verification) for invoke transactions with nonce=1 when the account's on-chain nonce is 0 and `account_tx_in_pool_or_recent_block` returns true for the sender. The check is not atomic with admission: an attacker who observes any pending transaction for address A in the mempool can submit an invoke transaction from A with nonce=1 and a completely invalid signature, and the gateway will admit it to the mempool without any signature validation.

### Finding Description

The `skip_stateful_validations` function applies three conditions to decide whether to skip `__validate__`: [1](#0-0) 

1. The transaction is an `Invoke` with `nonce == 1`
2. The account's on-chain nonce is `0` (not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

When all three hold, `skip_validate = true` is returned to `run_validate_entry_point`, which sets `execution_flags.validate = false`: [2](#0-1) 

This causes `StatefulValidator::perform_validations` to return `Ok(())` immediately after `perform_pre_validation_stage`, never calling `__validate__`: [3](#0-2) 

The code comment claims the check is sufficient because the address "either has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is broken: `account_tx_in_pool_or_recent_block` checks whether the address appears in the mempool pool or state at the moment the check runs — **before** the current transaction is admitted. It does not verify the pending transaction is a `deploy_account`, nor does it cryptographically bind the incoming invoke to any specific deployer. [4](#0-3) 

`account_tx_in_pool_or_recent_block` returns `true` if the address has any transaction in `tx_pool` or any entry in `MempoolState::committed`/`staged`: [5](#0-4) 

The preceding `validate_by_mempool` call only checks nonce ordering and fee escalation — it does not validate signatures: [6](#0-5) 

### Impact Explanation

An attacker can submit an invoke transaction from any address that has a pending deploy_account transaction in the mempool, with an arbitrary (invalid) signature, and it will be admitted to the mempool without signature verification. This is a **High** impact issue: the gateway/mempool admission path accepts cryptographically invalid transactions before sequencing. If the attacker's transaction carries a higher tip/fee than the legitimate invoke, it displaces the victim's transaction via fee escalation, causing the victim's deploy_account to succeed but their first invoke to be replaced by the attacker's failing transaction.

### Likelihood Explanation

The mempool is public. Any observer can detect a pending deploy_account for address A, then immediately submit a crafted invoke from A with nonce=1 and garbage signature. No privileged access is required. The only cost is a transaction fee bid higher than the victim's.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the sender address is pending. Alternatively, require the user to explicitly provide the deploy_account transaction hash (as the `native_blockifier` `PyValidator` does via `deploy_account_tx_hash: Option<TransactionHash>`), and verify it matches a pending deploy_account in the mempool before skipping `__validate__`. [7](#0-6) 

### Proof of Concept

1. Alice submits `deploy_account` for address A (nonce=0); it enters the mempool.
2. Attacker observes A in the mempool via `account_tx_in_pool_or_recent_block`.
3. Attacker submits `invoke` tx: `sender_address=A`, `nonce=1`, `signature=[0xdead, 0xbeef]`, valid resource bounds.
4. Gateway stateless validation passes (valid address format, valid resource bounds).
5. `extract_state_nonce_and_run_validations`:
   - `get_nonce_from_state(A)` → `Nonce(0)` (account not deployed)
   - `validate_nonce`: nonce=1, account_nonce=0, within `max_allowed_nonce_gap` → passes
   - `validate_by_mempool`: nonce not too old, fee escalation check passes → passes
   - `skip_stateful_validations`: nonce=1, account_nonce=0, A in mempool → returns `true`
   - `run_validate_entry_point(skip_validate=true)` → `__validate__` never called → `Ok(())`
6. Attacker's invoke tx with invalid signature is admitted to the mempool.
7. If attacker's tip > Alice's invoke tip, fee escalation replaces Alice's invoke with the attacker's.
8. Batcher executes: deploy_account succeeds (nonce→1), attacker's invoke fails at `__validate__` (invalid signature, nonce stays at 1).
9. Alice's legitimate invoke is gone from the mempool; she must resubmit.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
