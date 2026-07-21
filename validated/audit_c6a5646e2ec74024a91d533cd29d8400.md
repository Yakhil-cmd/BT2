### Title
Overly Broad `account_tx_in_pool_or_recent_block` Guard in `skip_stateful_validations` Allows Invoke Transactions with Invalid Signatures to Bypass `__validate__` and Enter the Mempool - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator is designed to skip the `__validate__` entry point for invoke transactions with nonce=1 when a deploy_account is pending. The guard it uses — `account_tx_in_pool_or_recent_block` — is too broad: it returns `true` for **any** transaction from the account, not specifically a deploy_account. An attacker who first submits a valid deploy_account transaction can then submit an invoke transaction with nonce=1 carrying an invalid signature, and that invoke transaction will be admitted to the mempool without any signature verification.

### Finding Description

**Validation bypass path:**

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, `run_pre_validation_checks` calls three sub-checks in sequence:

```
validate_state_preconditions  →  validate_by_mempool  →  skip_stateful_validations
``` [1](#0-0) 

`validate_by_mempool` only checks nonce ordering and duplicate detection via the mempool's `validate_tx`; it does **not** verify the account signature. [2](#0-1) 

`skip_stateful_validations` then decides whether to skip the `__validate__` entry point entirely: [3](#0-2) 

The skip fires when `tx.nonce() == 1`, `account_nonce == 0`, and `account_tx_in_pool_or_recent_block` returns `true`. The comment claims this is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." However, the actual implementation of `account_tx_in_pool_or_recent_block` is: [4](#0-3) 

It returns `true` if the account has **any** transaction in the pool (`tx_pool.contains_account`) or in the committed/staged state (`state.contains_account`). It does not distinguish between a deploy_account and an invoke transaction.

**Concrete attack sequence:**

1. Attacker declares a contract class `C` whose `__validate_deploy__` always returns success (no signature check).
2. Attacker submits a deploy_account transaction for address `A` using class `C`. The gateway fully executes the deploy_account (including `__validate_deploy__`), which succeeds. The transaction enters the mempool → `tx_pool.contains_account(A) = true`.
3. Attacker submits an invoke transaction with `nonce=1` for address `A` carrying an **invalid/forged signature**.
4. Gateway calls `skip_stateful_validations`:
   - `tx.nonce() == Nonce(Felt::ONE)` ✓
   - `account_nonce == Nonce(Felt::ZERO)` ✓ (account not yet deployed on-chain)
   - `account_tx_in_pool_or_recent_block(A)` = `true` ✓ (deploy_account is in pool)
   - Returns `true` → `execution_flags.validate = false`
5. `run_validate_entry_point` is called with `skip_validate = true`, so `__validate__` is **never called**. [5](#0-4) 

6. The invoke transaction with the invalid signature is forwarded to the mempool and admitted.

**Contrast with `native_blockifier`:** The Python-facing validator in `crates/native_blockifier/src/py_validator.rs` uses a stricter guard — it requires the caller to explicitly supply a `deploy_account_tx_hash` and checks `deploy_account_tx_hash.is_some()`, not a broad pool membership query. [6](#0-5) 

The gateway path has no equivalent specificity check.

### Impact Explanation

An invoke transaction with an invalid (or entirely absent) signature is admitted to the mempool without the account's `__validate__` entry point ever running. This breaks the invariant that every transaction in the mempool has passed account-level signature validation. The batcher will eventually reject the transaction during block execution, but the invalid transaction occupies mempool capacity and forces the sequencer to perform unnecessary execution work.

**Matching impact:** High — Mempool/gateway admission accepts an invalid transaction (one that would fail `__validate__`) before sequencing.

### Likelihood Explanation

The trigger requires no special privilege:
- Declaring a contract class with a permissive `__validate_deploy__` is an ordinary on-chain operation.
- Submitting a deploy_account followed by an invoke with a forged signature requires only standard RPC access.
- The attack can be repeated for many distinct addresses, each requiring one valid deploy_account transaction as a prerequisite.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction is pending for the account. Concretely, adopt the approach already used in `native_blockifier/src/py_validator.rs`: require the caller to supply the `deploy_account_tx_hash` explicitly, and only skip `__validate__` when that hash is non-`None` and the on-chain nonce is still zero. Alternatively, add a dedicated mempool query `deploy_account_in_pool(address) -> bool` that inspects transaction types rather than mere address membership.

### Proof of Concept

```
# Step 1 – deploy_account with permissive __validate_deploy__
POST /add_transaction
{
  "type": "DEPLOY_ACCOUNT",
  "class_hash": "<class_with_always_ok_validate_deploy>",
  "contract_address_salt": "<chosen_salt>",
  "constructor_calldata": [],
  "nonce": "0x0",
  "signature": [],          # ignored by __validate_deploy__
  ...
}
# → deploy_account accepted; mempool now has tx for address A
# → account_tx_in_pool_or_recent_block(A) == true

# Step 2 – invoke with forged signature, nonce=1
POST /add_transaction
{
  "type": "INVOKE",
  "sender_address": "<address A>",
  "nonce": "0x1",
  "calldata": [...],
  "signature": ["0xdeadbeef"],   # invalid signature
  ...
}
# → skip_stateful_validations returns true
# → __validate__ is never called
# → transaction admitted to mempool with invalid signature
```

The invalid invoke transaction now sits in the mempool. When the batcher pulls it and attempts execution, `__validate__` runs and fails, causing the transaction to be rejected — but only after consuming sequencer execution resources and occupying mempool capacity.

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
