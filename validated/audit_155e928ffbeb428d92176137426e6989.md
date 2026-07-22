### Title
Invoke Transaction with Invalid Signature Admitted to Mempool via `skip_stateful_validations` Bypass — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally skips the `__validate__` entry-point execution — the only place where a transaction's cryptographic signature is verified — for any Invoke transaction with `nonce == 1` whose sender address appears anywhere in the mempool or recent-block history. An attacker who places any valid transaction for a fresh address into the mempool can then submit a second Invoke with `nonce == 1` carrying an entirely arbitrary (invalid) signature, and that transaction will be admitted to the mempool without signature verification.

---

### Finding Description

**The bypass path.**

`run_pre_validation_checks` calls `skip_stateful_validations` after the nonce/resource-bounds checks: [1](#0-0) 

`skip_stateful_validations` returns `true` (skip validation) when all four conditions hold: [2](#0-1) 

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`.

When `skip_validate == true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`: [3](#0-2) 

Inside the blockifier, `AccountTransaction::validate_tx` immediately returns `Ok(None)` when `validate == false`, so the account contract's `__validate__` entry point is never called: [4](#0-3) 

**Why the guard is insufficient.**

The code comment claims that `account_tx_in_pool_or_recent_block` is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` checks for the presence of *any* transaction from that address: [5](#0-4) [6](#0-5) 

A future-nonce Invoke (e.g., `nonce == 2`) for a fresh address (account nonce 0) passes the gateway's nonce-gap check: [7](#0-6) 

That future-nonce Invoke *does* go through full `__validate__` execution (because `skip_stateful_validations` only fires for `nonce == 1`). Once it is in the mempool, `account_tx_in_pool_or_recent_block` returns `true`, and a subsequent Invoke with `nonce == 1` and an **invalid signature** will have its `__validate__` skipped entirely.

**No other layer verifies the signature.**

The stateless validator only checks signature *length*, not cryptographic validity: [8](#0-7) 

`validate_by_mempool` only checks nonce ordering and fee-escalation rules, not the signature: [9](#0-8) 

---

### Impact Explanation

An attacker can inject Invoke transactions carrying arbitrary (cryptographically invalid) signatures into the mempool. These transactions:

- Occupy mempool capacity, potentially triggering `MempoolFull` rejections for legitimate users.
- Are forwarded to the batcher, which wastes execution resources before the transaction is eventually rejected when `__validate__` is finally called during block production.
- Violate the invariant that every transaction admitted to the mempool has a valid account signature.

This matches the allowed High impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The attacker must first place any transaction from the target address into the mempool. The cheapest path is:

1. Generate a fresh key pair; derive address `A`.
2. Fund `A` with enough STRK to satisfy `verify_can_pay_committed_bounds` for a small Invoke.
3. Submit a valid Invoke with `nonce == 2` for `A` (passes full `__validate__`; `A` is now in the mempool).
4. Submit an Invoke with `nonce == 1` for `A` with an all-zero signature. `skip_stateful_validations` fires; the transaction is admitted without signature verification.

Steps 1–3 require a one-time funding cost per address. The attacker can repeat this across many fresh addresses to flood the mempool. No privileged access is required; the gateway endpoint is public.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **deploy_account** transaction for the sender is present in the mempool. A future-nonce Invoke in the mempool does not imply that the account will ever be deployed, and should not be used to justify skipping signature verification.

Alternatively, record the deploy_account transaction hash in the mempool when it is admitted, and require that hash to be provided (and verified) before skipping `__validate__` for the paired Invoke — mirroring the `deploy_account_tx_hash` parameter already present in the `native_blockifier` path: [10](#0-9) 

---

### Proof of Concept

```
// Attacker controls private key K for address A.

// Step 1: fund address A (one-time cost).

// Step 2: submit a valid Invoke with nonce=2 for A (full __validate__ runs, signature OK).
//   → mempool now contains A; account_tx_in_pool_or_recent_block(A) == true.

// Step 3: submit an Invoke with nonce=1 for A, signature = [0x0, 0x0, ...] (invalid).
//   Gateway stateful validator:
//     account_nonce = 0  (A not deployed)
//     tx.nonce()    = 1
//     account_tx_in_pool_or_recent_block(A) = true
//   → skip_stateful_validations returns true
//   → run_validate_entry_point sets validate=false
//   → __validate__ is never called
//   → invalid-signature Invoke is admitted to the mempool.

// Repeat steps 1–3 for N fresh addresses to fill the mempool with invalid transactions.
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-194)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-118)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
