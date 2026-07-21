### Title
Invoke Transaction with Invalid Signature Bypasses `__validate__` Entry Point via Deploy-Account UX Skip — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point for any Invoke transaction with `nonce == 1` when the on-chain account nonce is `0` and the account has any transaction in the mempool or a recent block. An attacker who has submitted a valid `DeployAccount` transaction for an address can immediately follow it with an Invoke carrying a completely invalid (e.g., all-zero) signature. The gateway admits the Invoke without ever calling `__validate__`, violating the invariant that every admitted transaction must pass signature verification.

---

### Finding Description

`skip_stateful_validations` is a UX feature that allows a user to broadcast `DeployAccount` + `Invoke(nonce=1)` simultaneously, before the account is on-chain. When the following two conditions hold:

1. The incoming Invoke has `tx.nonce() == Nonce(Felt::ONE)`
2. The account's on-chain nonce is `Nonce(Felt::ZERO)` (account not yet deployed)

the function queries `mempool_client.account_tx_in_pool_or_recent_block(sender_address)`. If that returns `true`, it returns `skip_validate = true`. [1](#0-0) 

`skip_validate = true` is then passed to `run_validate_entry_point`, which sets `execution_flags.validate = !skip_validate = false`, meaning the blockifier's `StatefulValidator::validate` is called with the `validate` flag disabled — the account's `__validate__` entry point is never executed. [2](#0-1) 

The comment in the code acknowledges the check is intentionally broad:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." [3](#0-2) 

The check does **not** verify that the mempool entry is specifically a `DeployAccount` transaction, nor does it verify the Invoke's signature in any other way. `validate_by_mempool` (called before `skip_stateful_validations`) performs only nonce/fee ordering checks via `ValidationArgs`, not cryptographic signature verification. [4](#0-3) 

The full pre-validation flow is:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions  (nonce range, resource bounds)
       ├─ validate_by_mempool           (nonce/fee ordering only)
       └─ skip_stateful_validations     ← returns true; __validate__ skipped
  └─ run_validate_entry_point(skip_validate=true)  ← no signature check
``` [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction.**

An Invoke transaction carrying an arbitrary (invalid) signature is admitted to the mempool and forwarded to the batcher. The mempool is polluted with transactions that will fail during block execution when the batcher calls `__validate__` (which is not skipped there). This wastes batcher and mempool resources and can be used to mount a targeted denial-of-service against a specific account's mempool slot, preventing legitimate nonce-1 transactions from being queued.

If the batcher also inherits a similar skip path (not verified in this search), the impact escalates to Critical: an Invoke with a forged signature would be executed and included in a block without any signature check.

---

### Likelihood Explanation

**Medium.** The attacker only needs to:
1. Know (or compute) any valid Starknet account address they control.
2. Submit a valid `DeployAccount` for that address (this passes normal validation).
3. Immediately submit an Invoke with `nonce=1` and an all-zero or garbage signature.

Step 2 is a normal user action. Step 3 requires no special privilege. The window is open for as long as the `DeployAccount` remains in the mempool (i.e., until it is included in a block and the on-chain nonce advances to 1).

---

### Recommendation

In `skip_stateful_validations`, replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `DeployAccount` transaction for the sender address is present in the mempool. Alternatively, even when skipping the `__validate__` entry point for UX reasons, perform a lightweight off-chain signature pre-check (e.g., ECDSA verification against the transaction hash) before admitting the Invoke, so that a garbage signature is rejected at the gateway boundary. [1](#0-0) 

---

### Proof of Concept

1. Attacker derives account address `X` from a known public key `P` (standard Starknet address derivation).
2. Attacker submits `DeployAccount(address=X, nonce=0, signature=valid_sig_for_P)` → passes all stateless and stateful checks including `__validate__`; enters mempool.
3. Attacker submits `Invoke(sender=X, nonce=1, calldata=<anything>, signature=[0x0, 0x0])` (all-zero signature).
4. Gateway calls `extract_state_nonce_and_run_validations`:
   - `account_nonce = 0` (X not on-chain yet)
   - `tx.nonce() = 1`
   - `account_tx_in_pool_or_recent_block(X)` → `true` (DeployAccount is in mempool)
   - `skip_validate = true`
   - `run_validate_entry_point` called with `validate=false` → `__validate__` never executed
5. Invoke with all-zero signature is admitted to the mempool.
6. Batcher picks up the Invoke; calls `__validate__` → fails; transaction is dropped, wasting batcher resources and occupying the account's mempool slot.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-315)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-411)
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
