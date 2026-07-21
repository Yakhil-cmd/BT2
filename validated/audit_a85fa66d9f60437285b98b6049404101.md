### Title
Gateway Skips Signature Verification for Invoke Transactions with Nonce=1 When Any Mempool Entry Exists for the Sender - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the Apollo gateway skips the `__validate__` entry point call (the sole signature-verification step) for an Invoke transaction whose nonce is `1` and whose sender's on-chain nonce is `0`, whenever `account_tx_in_pool_or_recent_block(sender)` returns `true`. That mempool check only confirms that *some* transaction from the sender address exists in the pool or a recent block — it does not confirm that the Invoke was submitted by the legitimate key-holder. An unprivileged attacker who observes a victim's `DeployAccount` transaction in the mempool can immediately submit a second Invoke with nonce=1 from the same address, carrying arbitrary calldata and a garbage signature, and the gateway will admit it without ever calling `__validate__`.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip `__validate__`) when all three conditions hold:

1. The transaction is an `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender)` returns `true`.

**What the mempool check actually tests** [2](#0-1) 

It returns `true` if the address has *any* transaction in the pool or any committed block entry. It does **not** verify that the existing pool entry is a `DeployAccount`, nor that the Invoke was submitted by the same party.

**How the skip propagates to zero signature verification** [3](#0-2) 

When `skip_validate=true`, `execution_flags.validate` is set to `false`. [4](#0-3) 

`validate_tx` returns `Ok(None)` immediately — the account's `__validate__` entry point is never executed, so the signature is never checked.

**Contrast with the legacy Python validator**

The older `PyValidator::should_run_stateful_validations` requires the caller to supply the concrete `deploy_account_tx_hash` and only skips validation when that hash is present *and* the on-chain nonce is zero: [5](#0-4) 

The new Rust gateway path drops this hash requirement entirely, relying solely on the weaker mempool-presence check.

**Attack scenario**

1. Legitimate user submits `DeployAccount(A)` + `Invoke(A, nonce=1, calldata=C_legit, tip=T)`. Both enter the mempool.
2. Attacker observes the mempool (public), sees `A` has a pool entry.
3. Attacker submits `Invoke(A, nonce=1, calldata=C_malicious, tip=T+1, signature=garbage)`.
4. Gateway path: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block(A)=true` → `skip_validate=true` → `__validate__` not called → transaction admitted.
5. Mempool replaces the legitimate Invoke with the attacker's higher-tip Invoke.
6. Block executes: `DeployAccount(A)` succeeds; then `Invoke(A, nonce=1, C_malicious)` is executed. During block execution the blockifier *does* run `__validate__`, which fails for a standard account (invalid signature), so `__execute__` is not reached and the call is reverted — but the fee is charged from A's balance and the legitimate Invoke is permanently lost from the mempool.

For accounts whose `__validate__` is a no-op (dummy validator, or a custom account that does not check signatures), `__execute__` runs with the attacker's calldata, enabling full unauthorized execution.

### Impact Explanation

This matches **"High. Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."** The gateway admits a transaction with an invalid/absent signature, displacing the legitimate transaction from the mempool. For standard accounts the malicious `__execute__` is blocked at execution time, but the DoS (legitimate Invoke lost), fee drain, and the window for accounts with weak `__validate__` implementations constitute a clear admission-layer failure.

### Likelihood Explanation

The mempool is observable by any network participant. The triggering conditions (nonce=1, on-chain nonce=0, any pool entry for the address) are trivially detectable. No privileged access is required. The only constraint is timing: the attacker must act between the victim's `DeployAccount` entering the mempool and the block being sealed.

### Recommendation

Restore the `deploy_account_tx_hash` binding used in `PyValidator`. The gateway should require the submitter to supply the hash of the pending `DeployAccount` transaction and verify that this exact hash is present in the mempool for the sender address before skipping `__validate__`:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    deploy_account_tx_hash: Option<TransactionHash>,  // must be supplied by caller
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            if let Some(da_hash) = deploy_account_tx_hash {
                // Verify the specific DeployAccount hash is in the pool, not just any tx.
                return mempool_client
                    .deploy_account_tx_in_pool(tx.sender_address(), da_hash)
                    .await
                    ...;
            }
        }
    }
    Ok(false)
}
```

Alternatively, always run `__validate__` at the gateway regardless of the deploy-account UX skip, accepting the minor UX regression.

### Proof of Concept

```
// State: account A not deployed (on-chain nonce = 0)
// Mempool: DeployAccount(A, nonce=0) submitted by legitimate owner

// Attacker submits (no valid signature):
RpcInvokeTransactionV3 {
    sender_address: A,
    nonce: 1,
    calldata: [malicious_selector, ...],
    signature: TransactionSignature(vec![]),   // garbage
    resource_bounds: AllResourceBounds { l2_gas: { max_amount: X, max_price: Y }, .. },
    tip: legitimate_tip + 1,   // outbid the legitimate invoke
    ...
}

// Gateway evaluation:
// 1. validate_contract_address(A) → Ok (A is a valid felt)
// 2. validate_nonce: account_nonce=0, tx_nonce=1, within [0, max_gap] → Ok
// 3. validate_by_mempool → Ok (nonce valid)
// 4. skip_stateful_validations:
//      tx.nonce()==1 && account_nonce==0 → check mempool
//      account_tx_in_pool_or_recent_block(A) == true (DeployAccount is there)
//      → returns true (SKIP __validate__)
// 5. run_validate_entry_point(skip_validate=true):
//      execution_flags.validate = false
//      validate_tx returns Ok(None) immediately — signature never checked
// 6. Transaction admitted to mempool, replaces legitimate invoke (higher tip)
```

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
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
