### Title
Gateway Signature Verification Bypass for Nonce-1 Invoke Transactions via `skip_stateful_validations` — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry point — the account's cryptographic signature check — for any Invoke transaction with `nonce=1` from an undeployed account, provided `account_tx_in_pool_or_recent_block` returns `true`. An unprivileged attacker who controls a deploy-account transaction (i.e., their own account) can submit a companion Invoke with an arbitrary or zeroed signature that the gateway admits to the mempool without any signature verification.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` — meaning "skip `__validate__`" — when all three conditions hold simultaneously:

1. The transaction is `ExecutableTransaction::Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet on-chain)
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` constructs `ExecutionFlags { validate: false, … }` and passes it to `StatefulValidator::validate`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, the `validate` flag is checked and the entire `__validate__` call is bypassed with an early `Ok(())`: [3](#0-2) 

`__validate__` is the only place in the gateway path where the account's signature is cryptographically verified. The earlier `validate_by_mempool` call performs only nonce/duplicate checks, not signature verification: [4](#0-3) 

The proxy guard — `account_tx_in_pool_or_recent_block` — checks whether the account has *any* transaction in the pool or appears in the committed-block state: [5](#0-4) 

This check is satisfied the moment the attacker's own `deploy_account` enters the mempool. It does **not** verify that the companion Invoke carries a valid signature.

**Attack path:**

1. Attacker derives address `A` from known constructor calldata + class hash.
2. Attacker submits `deploy_account` for `A` → admitted to mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker submits `Invoke(sender=A, nonce=1, signature=[0,0])` (invalid/arbitrary signature).
4. Gateway evaluates: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block==true` → `skip_validate=true`.
5. `run_validate_entry_point` sets `execution_flags.validate = false`; `__validate__` is never called.
6. The Invoke is admitted to the mempool **without any signature check**.

The batcher later re-creates `AccountTransaction` with its own `ExecutionFlags` (defaulting to `validate=true`) and does run `__validate__` at execution time, so the transaction will revert if the signature is invalid. However, the gateway's admission invariant — *every admitted transaction must carry a verifiable signature* — is broken at the mempool-entry boundary.

### Impact Explanation

Matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.** An unprivileged actor can inject Invoke transactions with arbitrary signatures into the mempool, bypassing the gateway's sole cryptographic admission gate. Reverted-but-admitted transactions still consume mempool slots, block space, and batcher execution resources. In account designs where `__validate__` is permissive (e.g., session-key or social-recovery accounts), the admitted transaction may also execute successfully with an unintended signer.

### Likelihood Explanation

Low barrier: any user who can submit a `deploy_account` (i.e., anyone) can immediately follow with a nonce-1 Invoke carrying a garbage signature. No privileged access, no special network position, and no race condition is required — the two transactions can be submitted in the same RPC batch.

### Recommendation

1. **Verify deploy-account type specifically.** Replace the `account_tx_in_pool_or_recent_block` proxy with a check that the pending transaction for the account is specifically a `DeployAccount` variant, not merely any transaction.
2. **Retain a lightweight signature-format check.** Even when skipping the full `__validate__` entry point, reject transactions whose signature field is empty or obviously malformed (e.g., length ≠ 2 for ECDSA accounts).
3. **Document the invariant relaxation explicitly.** If the skip is intentional, add a protocol-level note that the gateway's admission guarantee for nonce-1 Invokes is weaker than for all other transactions, so downstream components (batcher, prover) are aware they must enforce it.

### Proof of Concept

```
# Step 1 – derive address A from known (class_hash, salt, constructor_calldata)
deploy_account_tx = DeployAccountV3(
    class_hash=KNOWN_CLASS,
    contract_address_salt=SALT,
    constructor_calldata=[],
    nonce=0,
    signature=[valid_sig],   # valid sig required for deploy_account itself
    ...
)
gateway.add_transaction(deploy_account_tx)
# → mempool now has deploy_account for A; account_tx_in_pool_or_recent_block(A) == true

# Step 2 – submit Invoke with nonce=1 and INVALID signature
invoke_tx = InvokeV3(
    sender_address=A,
    nonce=1,
    calldata=[...arbitrary...],
    signature=[0x0, 0x0],   # invalid ECDSA signature
    ...
)
gateway.add_transaction(invoke_tx)
# → skip_stateful_validations returns true
# → execution_flags.validate = false
# → __validate__ is never called
# → Invoke admitted to mempool without signature verification
```

The admitted Invoke will revert during batcher execution (because `validate_tx` is called with `validate=true` there), but the gateway's admission invariant is violated: an Invoke with a provably invalid signature entered the mempool. [1](#0-0) [6](#0-5) [3](#0-2) [7](#0-6)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
