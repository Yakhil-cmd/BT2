### Title
`skip_stateful_validations` admits nonce-1 invoke transactions with invalid signatures to the mempool via overly broad `account_tx_in_pool_or_recent_block` check — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the `__validate__` entry-point (signature check) for an invoke transaction with nonce=1 when a deploy-account transaction for the same account is pending in the mempool. The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction in the pool, not only deploy-account transactions. An attacker can therefore pre-seed the mempool with a valid future-nonce invoke (e.g., nonce=5) for a target address, then submit a nonce=1 invoke with a **forged or invalid signature** that bypasses `__validate__` entirely and is admitted to the mempool. Combined with the mempool's fee-escalation replacement logic, the attacker can silently replace a legitimate user's valid nonce=1 invoke with an invalid one, causing the legitimate transaction to be permanently lost.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` (lines 429–461) decides whether to skip the blockifier's `__validate__` entry point for an incoming invoke transaction:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The intent (per the inline comment) is to allow the first post-deploy invoke to skip validation when a deploy-account is already queued, improving UX. The proxy check used is `account_tx_in_pool_or_recent_block`, whose implementation is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` for **any** transaction in the pool for that address — including future-nonce invoke transactions (nonces 1–200 are accepted by the gateway's nonce-gap rule). Consequently:

1. An attacker submits `invoke(nonce=5, valid_sig)` for victim address A. This passes `__validate__` normally (nonce=5 does not qualify for the skip). The account is now registered in the mempool pool.
2. The attacker submits `invoke(nonce=1, INVALID_SIG, tip=high)` for address A. `skip_stateful_validations` returns `true` because `account_tx_in_pool_or_recent_block` returns `true`. `run_validate_entry_point` is called with `skip_validate=true`, setting `execution_flags.validate = false`. The blockifier's `StatefulValidator::perform_validations` returns `Ok(())` immediately without calling `__validate__`.
3. The invalid-signature invoke passes `validate_by_mempool` (nonce and fee-escalation checks only; no signature check). The gateway calls `mempool.add_tx`, which — if the attacker's tip exceeds the victim's — replaces the victim's valid nonce=1 invoke via fee escalation.
4. When the batcher executes the block: the deploy-account succeeds, the attacker's nonce=1 invoke fails `__validate__` and is rejected. The victim's original nonce=1 invoke is gone.

The critical invariant broken: **every invoke transaction admitted to the mempool must have passed `__validate__` (signature verification), or be a deploy-account (which is fully executed during gateway validation)**. The `skip_stateful_validations` path violates this for nonce=1 invokes whenever any transaction from the same account is already pooled.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions.** An attacker can inject a signature-invalid invoke transaction into the mempool for any account that has any pending transaction. Via fee escalation, the attacker can replace a legitimate user's valid nonce=1 invoke with an invalid one. The victim's transaction is permanently lost (not re-queued after the attacker's transaction is rejected at execution time). This directly targets the deploy-account + invoke UX flow that the skip feature is designed to support, making the feature itself the attack surface.

### Likelihood Explanation

**Medium.** The attack requires only:
- Observing the mempool for a target account with a pending transaction (public information).
- Submitting a competing nonce=1 invoke with a higher tip (no special privilege required).

The deploy-account + invoke pattern is the standard onboarding flow for new accounts, making it a high-value target. No privileged access, no special contract, and no cryptographic capability is needed.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account** transaction exists for the account. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address)` that only returns `true` when a deploy-account transaction (nonce=0) is present. Alternatively, `skip_stateful_validations` should be restricted to cases where the mempool confirms a deploy-account transaction specifically, not any transaction.

### Proof of Concept

```
// State: account A has on-chain nonce = 0 (not yet deployed).

// Step 1: Attacker seeds the mempool with a valid future-nonce invoke.
attacker → gateway: invoke(sender=A, nonce=5, tip=1, sig=VALID)
  → skip_stateful_validations: nonce=5 ≠ 1, returns false
  → __validate__ runs, passes
  → mempool.add_tx: account A now in pool

// Step 2: Victim submits deploy_account + invoke (standard UX).
victim → gateway: deploy_account(sender=A, nonce=0, tip=10, sig=VALID)
  → fully executed, enters mempool
victim → gateway: invoke(sender=A, nonce=1, tip=10, sig=VALID)
  → skip_stateful_validations: nonce=1, account_nonce=0,
      account_tx_in_pool_or_recent_block(A) = true (attacker's nonce=5 is there)
  → __validate__ SKIPPED
  → mempool.add_tx: victim's nonce=1 invoke enters mempool

// Step 3: Attacker replaces victim's nonce=1 invoke via fee escalation.
attacker → gateway: invoke(sender=A, nonce=1, tip=100, sig=INVALID)
  → skip_stateful_validations: nonce=1, account_nonce=0,
      account_tx_in_pool_or_recent_block(A) = true
  → __validate__ SKIPPED
  → validate_by_mempool: tip=100 > tip=10, fee escalation valid
  → mempool.add_tx: REPLACES victim's valid nonce=1 invoke

// Step 4: Batcher executes block.
  deploy_account(nonce=0) → SUCCESS, account deployed
  attacker's invoke(nonce=1, INVALID_SIG) → __validate__ FAILS → REJECTED
  victim's invoke(nonce=1) → GONE (replaced in step 3)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
