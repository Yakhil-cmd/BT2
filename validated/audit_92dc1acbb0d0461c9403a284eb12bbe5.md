### Title
`skip_stateful_validations` Bypasses `__validate__` for Invoke Transactions When Any Account Transaction Exists in Mempool, Allowing Invalid Signature Admission - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the `__validate__` entry point for an invoke transaction with nonce 1 when the account has a pending deploy_account transaction in the mempool (UX improvement for the deploy+invoke flow). However, the guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction in the pool, not exclusively a deploy_account. An unprivileged attacker who observes a legitimate user's pending deploy_account for account A can immediately submit an invoke transaction for A with nonce 1 and an **invalid signature**. The gateway skips `__validate__` because the deploy_account satisfies the pool-presence check, and the invalid transaction is admitted into the mempool.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions are simultaneously true:

```
tx.nonce() == Nonce(Felt::ONE)
  && account_nonce == Nonce(Felt::ZERO)
  && account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

When all three hold, the function returns `true`, which propagates to `run_validate_entry_point` as `skip_validate = true`, setting `execution_flags.validate = false` and suppressing the `__validate__` call entirely: [2](#0-1) 

The pool-presence oracle is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`tx_pool.contains_account` returns `true` for **any** transaction type (invoke, declare, deploy_account) stored for that address. The code comment claims this is safe because the pool entry "means that either it has a deploy_account transaction or transactions with future nonces that passed validations." The second branch of that disjunction is circular: an attacker can inject a future-nonce invoke that bypasses `__validate__` precisely because the first branch (deploy_account present) satisfies the check.

**Attack path:**

1. Legitimate user U submits a valid `deploy_account` for address A (nonce 0). It passes full gateway validation (deploy_account is fully executed, not just validated) and enters the mempool.
2. Attacker observes A's deploy_account in the mempool.
3. Attacker submits `Invoke(sender=A, nonce=1, signature=<garbage>)`.
4. Gateway stateful path:
   - `validate_nonce`: nonce 1 ∈ [0, 200] — passes.
   - `validate_by_mempool` (`mempool.validate_tx`): checks only for duplicate tx_hash and nonce-range against mempool state — passes, no signature check.
   - `skip_stateful_validations`: nonce==1 ✓, account_nonce==0 ✓, `account_tx_in_pool_or_recent_block(A)` == true (U's deploy_account is in pool) ✓ → returns `true`.
   - `run_validate_entry_point` with `validate=false`: `__validate__` is **not called**.
5. Invalid invoke is admitted to the mempool. [4](#0-3) 

The `validate_by_mempool` call does not inspect signatures: [5](#0-4) 

### Impact Explanation

The gateway admits an invoke transaction carrying an invalid (attacker-forged) signature into the mempool. This violates the invariant that every transaction in the mempool has passed account-level signature validation. The invalid transaction will fail at execution time in the batcher (where `validate=true` is the default), but it occupies a mempool slot and consumes batcher resources. An attacker who continuously monitors the mempool for new deploy_account transactions can flood the mempool with invalid invokes for every newly-deploying account, causing sustained resource exhaustion.

Matching impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The attack requires only:
- Observing a pending deploy_account in the mempool (public information).
- Submitting a well-formed invoke (valid resource bounds, valid nonce 1, any signature bytes of acceptable length) targeting the same address.

No privileged access, no special contract, no fee payment beyond the resource-bounds field. The default `max_allowed_nonce_gap` of 200 and `max_nonce_for_validation_skip` of 1 bound the window to exactly nonce 1, but every new account deployment opens this window. [6](#0-5) 

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a specific query that confirms a **deploy_account** transaction (not any transaction) is pending for the address. The mempool should expose a dedicated predicate such as `deploy_account_in_pool(address) -> bool`, and `skip_stateful_validations` should call that instead. Alternatively, the mempool's `validate_tx` path should be extended to reject future-nonce invokes for accounts whose on-chain nonce is 0 unless a deploy_account is specifically present.

### Proof of Concept

```
// 1. Legitimate user deploys account A.
let deploy_tx = build_deploy_account(class_hash, salt, calldata, valid_sig);
gateway.add_tx(deploy_tx).await;   // succeeds, enters mempool

// 2. Attacker submits invalid invoke for A with nonce 1.
let evil_invoke = build_invoke(
    sender_address = A,
    nonce = 1,
    signature = vec![Felt::from(0xdeadbeef_u64)],  // garbage
    resource_bounds = valid_bounds,
);
// Gateway flow:
//   validate_nonce(1, account_nonce=0): 0 <= 1 <= 200 → OK
//   validate_by_mempool: no dup, nonce in range → OK
//   skip_stateful_validations:
//     nonce==1 ✓, account_nonce==0 ✓,
//     account_tx_in_pool_or_recent_block(A) == true (deploy_tx present) ✓
//     → returns true (skip __validate__)
//   run_validate_entry_point(skip_validate=true): __validate__ NOT called
let result

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-312)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-457)
```rust
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
