### Title
Gateway `skip_stateful_validations` Admits Signature-Unverified Invoke Transactions into Mempool — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary
The `skip_stateful_validations` function unconditionally bypasses the `__validate__` entry-point call (the only on-chain signature check at gateway admission time) for any Invoke V3 transaction whose nonce equals 1 and whose sender address appears in the mempool or a recent block. An unprivileged attacker who observes a pending `deploy_account` for address X can immediately submit a crafted Invoke with nonce=1 for X carrying an arbitrary or invalid signature. The gateway accepts it without signature verification, inserting it into the mempool alongside the legitimate `deploy_account`. The legitimate user's own nonce-1 Invoke is then rejected as a duplicate nonce or must pay escalating fees to displace the attacker's transaction.

### Finding Description
`skip_stateful_validations` (lines 429–461 of `crates/apollo_gateway/src/stateful_transaction_validator.rs`) fires when:

```
tx.nonce() == Nonce(Felt::ONE)  &&  account_nonce == Nonce(Felt::ZERO)
```

and `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`.

When it returns `true`, `run_validate_entry_point` is called with `validate: !skip_validate = false` (line 312). Inside `StatefulValidator::perform_validations` (blockifier, lines 79–81), the branch `if !tx.execution_flags.validate { return Ok(()); }` exits immediately, so `validate_tx` / `__validate__` is never invoked. No signature check of any kind is performed on the Invoke.

The guard `validate_by_mempool` (lines 414–424) calls `mempool.validate_tx`, which only checks nonce ordering and fee-escalation rules — it does not verify signatures. `validate_state_preconditions` checks resource bounds and nonce range; it also does not verify signatures. Therefore no existing guard preserves the invariant "every transaction admitted to the mempool has had its account signature verified."

The attacker's path:
1. Observe a `deploy_account` for address X in the mempool (address is deterministic from class hash + salt + constructor calldata).
2. Craft an Invoke V3 for X with nonce=1 and any signature (e.g., all-zero).
3. Submit to the gateway. `account_nonce` from state = 0, `tx.nonce()` = 1, `account_tx_in_pool_or_recent_block(X)` = true → `skip_validate = true`.
4. Gateway returns success; the invalid Invoke is stored in the mempool.
5. The legitimate user's Invoke with nonce=1 is rejected (`DuplicateNonce`) or must pay a higher fee to replace the attacker's transaction via fee escalation.
6. The attacker can repeat with monotonically higher fees to sustain the blockade.

### Impact Explanation
The gateway admits a transaction whose signature has never been verified. This directly satisfies the "High" impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."* Concretely, the attacker can:
- Permanently occupy the nonce-1 slot for any freshly deploying account, forcing the legitimate user to pay escalating fees or abandon the transaction.
- Flood the mempool with zero-cost (failed-at-execution) invalid Invokes for every observed `deploy_account`, degrading mempool quality and wasting block space.

### Likelihood Explanation
The trigger is fully unprivileged: any party that can submit transactions to the HTTP gateway can execute this attack. The target address is publicly computable from the `deploy_account` transaction fields visible in the mempool. No special knowledge of the victim's private key is required. The only race condition is submitting before the legitimate user's Invoke, which is straightforward given that the `deploy_account` and the paired Invoke are typically submitted sequentially.

### Recommendation
- In `skip_stateful_validations`, verify that the mempool entry for the sender is specifically a `deploy_account` transaction (not just any transaction), so that an attacker-injected Invoke cannot itself serve as the "proof" that the account is deploying.
- Alternatively, record the `deploy_account` transaction hash when the UX skip is granted and bind the skip to that specific hash, preventing third-party Invokes from benefiting.
- Document the security trade-off explicitly and add a test case where an attacker submits a nonce-1 Invoke for an address whose only mempool entry is a third-party-submitted `deploy_account`.

### Proof of Concept

```
// Step 1 – legitimate user submits deploy_account for address X (nonce=0).
// X is deterministic: X = hash(class_hash, salt, constructor_calldata, deployer=0).

// Step 2 – attacker computes X from the public deploy_account tx fields.

// Step 3 – attacker submits:
RpcInvokeTransactionV3 {
    sender_address: X,
    nonce: Nonce(Felt::ONE),          // nonce = 1
    signature: TransactionSignature(vec![Felt::ZERO, Felt::ZERO].into()),  // invalid
    resource_bounds: <any valid bounds>,
    calldata: vec![],
    ...
}

// Gateway path:
//   validate_contract_address(X)          → Ok (X is a valid felt)
//   validate_resource_bounds(...)         → Ok
//   validate_nonce(X, account_nonce=0)    → Ok (0 ≤ 1 ≤ max_allowed_nonce_gap)
//   validate_by_mempool(...)              → Ok (no duplicate, nonce in range)
//   skip_stateful_validations(...)
//     tx.nonce() == 1 && account_nonce == 0 → true
//     account_tx_in_pool_or_recent_block(X) → true (deploy_account is there)
//     returns true  ← __validate__ SKIPPED
//   run_validate_entry_point(skip_validate=true)
//     execution_flags.validate = false
//     StatefulValidator::perform_validations → returns Ok(()) immediately
//   gateway returns Ok(tx_hash)

// Step 4 – legitimate user submits their own Invoke(X, nonce=1, valid_sig).
// mempool.validate_tx → DuplicateNonce error (attacker's tx already holds nonce=1).
// Legitimate user must fee-escalate or wait for attacker's tx to be evicted/executed-and-failed.
```

Key code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
