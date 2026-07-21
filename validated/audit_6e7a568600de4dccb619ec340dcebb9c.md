### Title
Signature Verification Bypass via `skip_stateful_validations` Admitting Unsigned Invoke Transactions for Undeployed Accounts - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (which performs signature verification) for invoke transactions with nonce=1 when `account_tx_in_pool_or_recent_block` returns `true` for the sender address. The check does **not** verify that the transaction in the mempool is specifically a `deploy_account` transaction — it returns `true` for **any** transaction type at that address. An attacker who observes a victim's `deploy_account` in the mempool can immediately submit a malicious invoke with nonce=1 for the victim's undeployed address, bypassing signature verification at the gateway, and have it admitted to the mempool.

### Finding Description

The `skip_stateful_validations` function is designed to improve UX for the `deploy_account + invoke` flow. When an invoke transaction has `tx_nonce == 1` and `account_nonce == 0`, it queries the mempool:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs, lines 429-461
async fn skip_stateful_validations(...) -> ... {
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
``` [1](#0-0) 

The mempool's `account_tx_in_pool_or_recent_block` implementation checks only whether **any** transaction exists for the address — it does not filter by transaction type:

```rust
// crates/apollo_mempool/src/mempool.rs, lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`, meaning the blockifier's `__validate__` entry point — which is responsible for signature verification — is never invoked:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs, lines 308-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

The code comment claims the check is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is incorrect for the undeployed-account case: the only transaction type that can enter the mempool for an address with `account_nonce == 0` without the account existing is a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool can exploit this by submitting an invoke with nonce=1 for the same address with an arbitrary (invalid) signature, which will be admitted without any signature check. [4](#0-3) 

### Impact Explanation

An attacker can submit an invoke transaction with an arbitrary or missing signature for any undeployed account address that has a pending `deploy_account` in the mempool. The gateway admits this transaction without calling `__validate__`, violating the invariant that every admitted transaction must have a verified signature. This constitutes unauthorized admission of an invalid transaction before sequencing.

At execution time in the batcher, the `AccountTransaction` is reconstructed with default `execution_flags` (which include `validate: true`), so `__validate__` is called. For standard accounts this causes the malicious invoke to revert. However:

1. **Mempool pollution / DoS**: The attacker can flood the mempool with unsigned invokes for every address that has a pending `deploy_account`, consuming mempool capacity and delaying legitimate transactions.
2. **Accounts with permissive `__validate__`**: If the deployed account contract's `__validate__` accepts any call during initialization (nonce=1), the malicious execute body runs with the victim's account as the caller — the direct analog of the `tx.origin` exploit in the seed report. The attacker can pre-approve token transfers, set storage, or call arbitrary contracts on behalf of the victim's newly deployed account.

**Impact category**: High — Mempool/gateway admission accepts invalid (unsigned) transactions before sequencing.

### Likelihood Explanation

The mempool is observable by any network participant. A victim broadcasting a `deploy_account` transaction exposes the target address. The attacker's window is the time between the `deploy_account` entering the mempool and being included in a block. This is a realistic race condition in a live network. No privileged access is required; the attacker only needs to submit a standard RPC transaction.

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the address in the mempool. The mempool should expose a dedicated query such as `deploy_account_in_pool(address: ContractAddress) -> bool` that inspects the transaction type stored in `tx_pool` for the given address.

Alternatively, the `skip_stateful_validations` logic should be removed and the UX flow handled differently (e.g., by having the client submit the invoke only after the `deploy_account` is confirmed).

### Proof of Concept

1. Victim submits `deploy_account` for address `A` (class_hash `C`, salt `S`). The transaction enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.

2. Attacker observes the mempool and crafts:
   ```
   InvokeV3 {
     sender_address: A,
     nonce: 1,
     calldata: [<malicious_call: approve attacker for all tokens>],
     signature: [0x0, 0x0],   // arbitrary, not verified
     resource_bounds: <valid>,
   }
   ```

3. Attacker submits the invoke to the gateway. The gateway calls `extract_state_nonce_and_run_validations`:
   - `get_nonce_from_state(A)` → `0` (account not yet deployed)
   - `validate_nonce`: `0 <= 1 <= max_allowed_nonce_gap` → passes
   - `validate_by_mempool` → passes (no duplicate, nonce gap allowed)
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0` → queries mempool → `true` → returns `true`
   - `run_validate_entry_point(skip_validate=true)` → `__validate__` **not called**
   - Transaction admitted to mempool.

4. Batcher sequences both transactions. `deploy_account` executes first, deploying account `A`. The malicious invoke then executes. If `A`'s `__validate__` is permissive at nonce=1 (e.g., accepts any call during initialization), the `approve` call succeeds. The attacker can later drain the victim's tokens. [5](#0-4) [6](#0-5) [2](#0-1)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-461)
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
}

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
