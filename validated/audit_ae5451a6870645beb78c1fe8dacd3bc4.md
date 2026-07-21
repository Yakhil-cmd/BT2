### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions from Deployed Accounts with Nonce Zero - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to skip the `__validate__` entry-point call for the UX case where a user submits a `deploy_account` + `invoke` pair simultaneously. The guard checks that `tx.nonce() == 1` and `account_nonce == 0`, then calls `account_tx_in_pool_or_recent_block` to confirm a prior transaction exists. However, the check does not verify that the prior transaction is a `deploy_account`; any invoke with nonce=0 from a **deployed** account (which also has nonce=0 in state) satisfies the condition. This allows an attacker to submit a nonce=1 invoke with an arbitrary/invalid signature that bypasses `__validate__` at the gateway and is admitted to the mempool.

### Finding Description

The vulnerable function is `skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                // ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

The code comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This assumption is incorrect. `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction type from the address:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

When `skip_validate = true` is returned, `run_validate_entry_point` sets `validate: false` in the `ExecutionFlags`, causing the blockifier's `StatefulValidator` to skip the `__validate__` entry-point call entirely:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate` is false, the `__validate__` call is skipped:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [4](#0-3) 

**Attack path:**

1. Attacker controls a deployed account at address `X` with `nonce = 0` in blockchain state (class hash set, no prior transactions).
2. Attacker submits `Invoke(nonce=0)` with a valid signature → passes `__validate__`, enters the mempool. `account_tx_in_pool_or_recent_block(X)` now returns `true`.
3. Attacker submits `Invoke(nonce=1)` with an **invalid or empty signature**.
   - `validate_nonce` passes: `0 <= 1 <= max_allowed_nonce_gap` (default gap > 0).
   - `validate_by_mempool` passes: nonce=1 is not too old.
   - `skip_stateful_validations` returns `true` because `nonce==1`, `account_nonce==0`, and `account_tx_in_pool_or_recent_block` returns `true`.
   - `__validate__` is **not called** at the gateway.
4. The nonce=1 invoke is forwarded to the mempool and accepted.

The gateway's nonce validation for invoke transactions uses a range check, not an exact match, so nonce=1 with account_nonce=0 is accepted:

```rust
_ => {
    let max_allowed_nonce =
        Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
    if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
        return Err(create_error(...));
    }
}
``` [5](#0-4) 

### Impact Explanation

The gateway's invariant — that every admitted invoke transaction has passed its account's `__validate__` entry point — is broken. An invoke transaction with an invalid signature is admitted to the mempool without any signature verification. When the batcher later executes the transaction using `AccountTransaction::new_for_sequencing` (which always sets `validate: true`), `__validate__` runs and the transaction is reverted:

```rust
pub fn new_for_sequencing(tx: Transaction) -> Self {
    let execution_flags = ExecutionFlags {
        only_query: false,
        charge_fee: enforce_fee(&tx, false),
        validate: true,
        strict_nonce_check: true,
    };
    AccountTransaction { tx, execution_flags }
}
``` [6](#0-5) 

The reverted transaction is included in the block, consuming block space. The attacker pays the fee for the reverted transaction. This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The precondition — a deployed account with nonce=0 in state — is the normal state of any freshly deployed account before it has sent any transactions. Any such account can be used to trigger this path. The attacker only needs to submit two transactions: one valid nonce=0 invoke (to seed the mempool), and one nonce=1 invoke with an arbitrary signature. No privileged access is required.

### Recommendation

In `skip_stateful_validations`, replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the address. The current check is too broad and conflates "account has any transaction in pool" with "account has a pending deploy_account." One approach is to query the mempool for a deploy_account transaction specifically, or to require that the account has no class hash set in state (i.e., is truly undeployed) before skipping validation.

### Proof of Concept

```
1. Deploy account contract at address X (class hash set, nonce = 0 in state).
2. Submit Invoke(sender=X, nonce=0, signature=<valid>) → gateway runs __validate__, passes, tx enters mempool.
   - account_tx_in_pool_or_recent_block(X) now returns true.
3. Submit Invoke(sender=X, nonce=1, signature=<garbage/empty>).
   - Gateway stateless check: passes (signature length within limit).
   - validate_nonce: 0 <= 1 <= max_allowed_nonce_gap → passes.
   - validate_by_mempool: nonce=1 not too old → passes.
   - skip_stateful_validations: nonce==1, account_nonce==0, account_tx_in_pool_or_recent_block==true → returns true (skip).
   - run_validate_entry_point: validate=false → __validate__ NOT called.
   - Transaction forwarded to mempool and accepted.
4. Batcher picks up nonce=1 invoke, executes with validate=true.
   - __validate__ runs, fails (invalid signature), transaction reverted.
   - Reverted transaction included in block; fee charged.
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
