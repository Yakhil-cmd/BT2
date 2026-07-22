### Title
Gateway Admits Signature-Unverified Invoke Transactions via Overly Broad `skip_stateful_validations` Trigger — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is designed to skip `__validate__` (signature verification) only when an invoke with nonce=1 accompanies a pending `deploy_account`. However, the proxy check `account_tx_in_pool_or_recent_block` returns `true` for **any** pending transaction for the account, not exclusively a `deploy_account`. An attacker who observes that any account with `account_nonce == 0` has any transaction in the mempool can submit an invoke with nonce=1 carrying an **invalid signature**, and the gateway will admit it to the mempool without ever calling `__validate__`.

### Finding Description

In `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-460
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // Comment claims this verifies a deploy_account exists, but the
            // check returns true for ANY transaction in the pool.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: !skip_validate = false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` entry point is never called:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:79-81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The mempool's `account_tx_in_pool_or_recent_block` returns `true` for any account that has **any** transaction in the pool or a recently committed block — not specifically a `deploy_account`:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The code comment at line 440–443 explicitly claims the check is sufficient to infer a `deploy_account` exists, but this reasoning is incorrect: [5](#0-4) 

### Impact Explanation

An attacker can submit an invoke transaction with nonce=1 and an **arbitrary/invalid signature** for any account that satisfies:
- `account_nonce == 0` (account has never executed a transaction — common for freshly funded accounts)
- any transaction for that account is already in the mempool (observable by any network participant)

The gateway's full stateful validation path (`validate_state_preconditions` → `validate_by_mempool` → `skip_stateful_validations`) passes without ever verifying the signature. The transaction is forwarded to the mempool and accepted. This breaks the invariant that every transaction in the mempool has passed account-level signature verification.

**Matching impact:** *High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

### Likelihood Explanation

The preconditions are easily observable: any account with `nonce == 0` that has a pending transaction in the public mempool is a valid target. No privileged access is required. The attacker only needs to watch the mempool and submit a crafted invoke.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address)` that inspects the transaction type, rather than relying on the presence of any transaction. Alternatively, track the deploy-account nonce separately and only skip validation when the pending transaction at nonce=0 is confirmed to be a `DeployAccount`.

### Proof of Concept

1. Account `0xABCD` is funded but has `account_nonce == 0` (never executed a transaction; may or may not be deployed).
2. The legitimate owner submits a valid invoke with nonce=0 for `0xABCD`. It enters the mempool. `account_tx_in_pool_or_recent_block(0xABCD)` now returns `true`.
3. Attacker submits an invoke for `0xABCD` with `nonce=1` and a garbage signature `[0xDEAD, 0xBEEF]`.
4. Gateway stateless validation passes (signature length is within bounds).
5. Gateway stateful `validate_state_preconditions`: nonce=1 is within `[0, 0+200]`, resource bounds pass.
6. `validate_by_mempool`: nonce gap check passes (nonce=1 is a valid future nonce).
7. `skip_stateful_validations`: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block==true` → returns `true`.
8. `run_validate_entry_point` is called with `validate=false`; `__validate__` is **never invoked**.
9. The invalid-signature transaction is admitted to the mempool and forwarded for sequencing. [6](#0-5) [7](#0-6)

### Citations

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-460)
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
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
