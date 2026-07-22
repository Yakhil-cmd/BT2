### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions for Any Account With a Pending Mempool Entry - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to skip account signature validation for an invoke transaction with nonce=1 when the account is not yet deployed on-chain. The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction from the sender address, not exclusively a `deploy_account` transaction. An attacker can exploit this by waiting for any new account (on-chain nonce=0) to have a pending transaction in the mempool, then submitting an invoke with nonce=1 from that address carrying an invalid or arbitrary signature. The gateway skips the blockifier's `__validate__` entry-point call and admits the transaction.

### Finding Description

`skip_stateful_validations` triggers the bypass when three conditions hold simultaneously:

1. The submitted transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet committed on-chain). [1](#0-0) 

When all three hold, the function calls `account_tx_in_pool_or_recent_block(sender)` and returns its result as the skip decision: [2](#0-1) 

`account_tx_in_pool_or_recent_block` is implemented as: [3](#0-2) 

It returns `true` whenever the address has **any** transaction in the pool — including a plain nonce=0 invoke — not only a `deploy_account`. The code comment claims "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this is incorrect: a nonce=0 invoke from a freshly-created account satisfies the check without any deploy_account being present.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so the blockifier's `StatefulValidator` never calls the account's `__validate__` entry point: [4](#0-3) 

All earlier checks (`validate_nonce`, `validate_resource_bounds`, `validate_by_mempool`) pass without inspecting the signature: [5](#0-4) 

The nonce check explicitly allows nonce=1 when account_nonce=0 (within the `max_allowed_nonce_gap` of 200): [6](#0-5) 

### Impact Explanation

An attacker can inject an invoke transaction carrying an invalid or forged signature for any new account (on-chain nonce=0) that has a pending transaction in the mempool. The gateway admits the transaction without ever running the account's `__validate__` entry point. The invalid transaction occupies mempool capacity, and when the batcher later executes it the account validation fails, causing a revert. The victim's account is left with a stuck nonce=1 entry in the pool that blocks subsequent legitimate transactions until it is evicted or replaced.

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

New accounts submitting their first transaction (nonce=0 invoke) are common. An attacker monitoring the mempool can immediately inject a nonce=1 invoke with an arbitrary signature for any such account. No privileged access, special key material, or on-chain funds are required beyond the fee token balance needed to submit the attacker's transaction.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a targeted query that confirms a `deploy_account` transaction specifically is pending for the sender address. The mempool should expose a `deploy_account_in_pool(address)` predicate, and `skip_stateful_validations` should call that instead. Alternatively, the skip should only be granted when the gateway itself received and admitted a `deploy_account` for the same address in the same request batch.

### Proof of Concept

1. Victim `V` (on-chain nonce=0) submits a valid invoke with nonce=0. The mempool admits it; `tx_pool.contains_account(V)` is now `true`.
2. Attacker constructs `InvokeV3 { sender_address: V, nonce: 1, signature: [0xdead, 0xbeef], ... }` with an invalid signature.
3. Attacker submits the transaction to the gateway.
4. `validate_nonce`: `0 <= 1 <= 200` — passes.
5. `validate_by_mempool`: no duplicate hash, nonce in range — passes.
6. `skip_stateful_validations`: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(V)==true` → returns `true`.
7. `run_validate_entry_point` is called with `validate: false`; the blockifier skips `__validate__`.
8. The invalid-signature invoke is admitted to the mempool. [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
