### Title
Signature Validation Bypass via Overly Broad `skip_stateful_validations` Predicate — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is intended to skip the `__validate__` entry-point call only when a `deploy_account` transaction for the sender is pending in the mempool (UX feature for simultaneous deploy+invoke). However, the predicate it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction type in the pool, not exclusively `deploy_account`. An unprivileged attacker who observes a target account's address in the mempool (e.g., because the legitimate owner submitted a `deploy_account` or a nonce-0 invoke) can submit a nonce-1 invoke with an **arbitrary/invalid signature** that bypasses the `__validate__` entry-point check at the gateway, causing the gateway/mempool to admit an invalid transaction.

### Finding Description

**Broken invariant.** The comment in `skip_stateful_validations` states:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

The second clause is the flaw. A nonce-0 invoke passing `__validate__` does not authorise a nonce-1 invoke from a *different* submitter to skip its own `__validate__`. The check used is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 444-456
return mempool_client
    .account_tx_in_pool_or_recent_block(tx.sender_address())
    .await
    ...
``` [1](#0-0) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`tx_pool.contains_account` returns `true` for **any** transaction type (invoke, declare, deploy_account) stored for that address: [3](#0-2) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
// lines 310-312
let strict_nonce_check = false;
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate = false` the `__validate__` call is entirely skipped:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [5](#0-4) 

**Attack path (step by step):**

1. Account A has on-chain nonce = 0 (not yet deployed, or deployed but never transacted).
2. The legitimate owner submits a `deploy_account` (or a valid nonce-0 invoke) for A. This puts A into `tx_pool` (or `state.committed`/`state.staged`).
3. Attacker observes A's address (e.g., from the public mempool or network gossip).
4. Attacker crafts a nonce-1 `Invoke` for A with an **invalid/arbitrary signature**.
5. Gateway stateless checks pass (signature length is within bounds; no semantic check).
6. `validate_state_preconditions` passes: nonce 1 satisfies `account_nonce(0) ≤ 1 ≤ max_allowed_nonce_gap`. [6](#0-5) 

7. `validate_by_mempool` passes: nonce 1 ≥ resolved account nonce 0; no duplicate hash. [7](#0-6) 

8. `skip_stateful_validations` returns `true` because `account_tx_in_pool_or_recent_block(A)` is `true` (step 2).
9. `run_validate_entry_point` is called with `skip_validate = true` → `__validate__` is **never called**.
10. The invalid-signature nonce-1 invoke is admitted to the mempool.

### Impact Explanation

The gateway/mempool accepts an invalid Starknet transaction — one whose `__validate__` entry point would reject it — before sequencing. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concrete consequences:
- The mempool is polluted with transactions that carry invalid signatures for accounts the attacker does not control.
- The batcher wastes execution resources attempting to include these transactions; they will fail `__validate__` during block execution and be rejected (no fee charged, but sequencer CPU/time is consumed).
- An attacker can front-run any account that is in the process of being deployed, injecting a nonce-1 invoke that occupies the account's next nonce slot in the mempool, potentially delaying or displacing the legitimate owner's own nonce-1 transaction (depending on fee-escalation rules).

### Likelihood Explanation

- **Trigger is unprivileged**: any external caller can submit an `RpcTransaction` to the gateway.
- **Precondition is observable**: the target account's address is visible once a `deploy_account` or nonce-0 invoke appears in the mempool.
- **No special knowledge required**: the attacker only needs the target address and to craft a nonce-1 invoke with any bytes as the signature.
- The condition `tx_nonce == 1 && account_nonce == 0` is the normal state for every newly deployed account during the deploy+invoke window, making this a recurring opportunity.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a type-specific query that verifies a **`deploy_account`** transaction (and only a `deploy_account`) is pending for the sender address. Concretely:

1. Add a `deploy_account_in_pool(address)` method to the mempool that inspects `tx_pool` for a `DeployAccount` variant at nonce 0 for the given address.
2. Replace the call in `skip_stateful_validations` with this new method.
3. Alternatively, restrict the skip to cases where the mempool's `staged` or `committed` state already reflects a nonce increment from a committed `deploy_account` (i.e., the account's mempool-resolved nonce is ≥ 1).

### Proof of Concept

```
// Precondition: account A has on-chain nonce 0.
// Step 1: legitimate owner submits deploy_account for A → A enters tx_pool.

// Step 2: attacker submits (via gateway add_tx):
RpcInvokeTransactionV3 {
    sender_address: A,
    nonce: 1,
    signature: [0xdeadbeef, 0xdeadbeef],  // invalid signature
    calldata: [...],                        // arbitrary calldata
    resource_bounds: <valid bounds>,
    ...
}

// Gateway flow:
// StatelessTransactionValidator::validate → passes (signature length ≤ max)
// extract_state_nonce_and_run_validations:
//   get_nonce_from_state(A) → 0
//   validate_state_preconditions: nonce 1 in [0, max_allowed_nonce_gap] → OK
//   validate_by_mempool: nonce 1 ≥ 0 → OK
//   skip_stateful_validations:
//     tx.nonce() == 1 && account_nonce == 0 → true
//     account_tx_in_pool_or_recent_block(A) → true (deploy_account is in pool)
//     returns true  ← SKIP __validate__
//   run_validate_entry_point(skip_validate=true):
//     execution_flags.validate = false
//     StatefulValidator::perform_validations returns Ok(()) without calling __validate__
// Transaction admitted to mempool with invalid signature.
``` [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
