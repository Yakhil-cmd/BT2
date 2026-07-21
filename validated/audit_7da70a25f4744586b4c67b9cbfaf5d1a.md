### Title
`skip_stateful_validations` Bypasses `__validate__` for Any Account Seen in a Committed Block, Not Just Accounts with a Pending `deploy_account` - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is intended to skip the `__validate__` entry-point call only when a `deploy_account` transaction is pending in the mempool (UX improvement for the deploy+invoke pattern). However, the proxy check it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** account that was ever seen in a committed block, not just accounts with a pending `deploy_account`. This allows an attacker to submit an `Invoke` transaction with nonce=1 and an invalid signature targeting any account that has nonce=0 and was previously deployed (seen in a committed block), bypassing `__validate__` at the gateway and admitting the invalid transaction to the mempool.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-461
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

The condition `tx.nonce() == 1 && account_nonce == 0` is met for any invoke targeting an undeployed-looking account. The proxy check `account_tx_in_pool_or_recent_block` is:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`self.state.contains_account` returns `true` for **any account seen in a committed block**, as confirmed by the test:

```rust
// crates/apollo_mempool/src/fee_mempool_test.rs:1125-1128
// The account has no txs in the pool, but is known through a committed block.
commit_block(&mut mempool, [(ACCOUNT_ADDRESS, 1)], []);
MempoolTestContentBuilder::new().with_pool([]).build().assert_eq(&mempool.content());
assert_eq!(mempool.account_tx_in_pool_or_recent_block(account_address), true);
```

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `skip_validate=true`, which sets `execution_flags.validate = false`. Inside `StatefulValidator::perform_validations`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:76-81
ApiTransaction::Invoke(_) => {
    ...
    if !tx.execution_flags.validate {
        return Ok(());  // __validate__ is NOT called
    }
    let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

The `__validate__` entry point — which verifies the transaction signature — is entirely skipped.

**The key mismatch (analogous to the ERC20 bug):**
- **Intended scope of skip**: "account has a pending `deploy_account` transaction" (narrow)
- **Actual scope of skip**: "account was ever seen in pool OR any committed block" (broad)

An account deployed in block N with nonce=0 that has never sent a transaction satisfies `state.contains_account` permanently. Any attacker can submit a nonce=1 invoke with an invalid/arbitrary signature to such an account and bypass `__validate__`.

### Impact Explanation

An attacker can admit transactions with invalid signatures to the mempool for any account that:
1. Has on-chain nonce = 0 (never sent a transaction after deployment)
2. Was deployed in any previous block (so `state.contains_account` returns `true`)

This is a **High** impact admission vulnerability: **Mempool/gateway/RPC admission accepts invalid transactions before sequencing.** The invalid transactions consume mempool capacity and batcher resources. When the batcher attempts execution, `__validate__` fails and the transaction is dropped without fee collection, meaning the attacker bears no cost.

### Likelihood Explanation

- Triggerable by any unprivileged user with knowledge of a deployed-but-idle account address (public on-chain data).
- Accounts with nonce=0 that were deployed in previous blocks are common (e.g., multisigs, vaults, factory-deployed contracts that haven't been used yet).
- No special privileges, no race conditions, no complex setup required.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **pending `deploy_account` transaction** exists in the mempool for the sender address. The `state.contains_account` branch (committed-block history) should not be used to justify skipping `__validate__`, because it matches accounts that were deployed long ago and have no pending deployment.

```rust
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // Only skip if a deploy_account is *currently pending* in the pool,
            // not merely if the account was ever seen in a committed block.
            return mempool_client
                .deploy_account_tx_in_pool(tx.sender_address())  // new, narrower check
                .await
                ...
        }
    }
    Ok(false)
}
```

### Proof of Concept

1. Account `A` was deployed in block 100 (nonce=0). It has never sent any transaction. `mempool.state.contains_account(A)` returns `true`.
2. Attacker crafts an `InvokeTransactionV3` with `sender_address=A`, `nonce=1`, and a garbage/invalid signature.
3. Attacker submits to the gateway's `add_tx`.
4. `StatelessTransactionValidator::validate` passes (signature length is within bounds, resource bounds are valid).
5. `extract_state_nonce_and_run_validations` fetches `account_nonce = 0` from state.
6. `validate_state_preconditions` passes: nonce=1 is within `[0, max_allowed_nonce_gap]`.
7. `validate_by_mempool` passes: mempool nonce check accepts nonce=1 for account_nonce=0.
8. `skip_stateful_validations`: `nonce==1 && account_nonce==0` → calls `account_tx_in_pool_or_recent_block(A)` → returns `true` (committed-block history) → returns `true` (skip).
9. `run_validate_entry_point` is called with `skip_validate=true` → `execution_flags.validate=false` → `__validate__` is NOT called → returns `Ok(())`.
10. Transaction with invalid signature is admitted to the mempool. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L1125-1128)
```rust
    // The account has no txs in the pool, but is known through a committed block.
    commit_block(&mut mempool, [(ACCOUNT_ADDRESS, 1)], []);
    MempoolTestContentBuilder::new().with_pool([]).build().assert_eq(&mempool.content());
    assert_eq!(mempool.account_tx_in_pool_or_recent_block(account_address), true);
```
