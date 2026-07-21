### Title
Signature Validation Bypass via Mutable Mempool State in `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function decides whether to skip the blockifier `__validate__` entry point for an invoke transaction by querying the **live, mutable mempool state** (`account_tx_in_pool_or_recent_block`). This is the direct sequencer analog of the M-13 bug: just as `EUSDMiningIncentives` used `balanceOf(pair)` (a manipulable live value) instead of `getReserves()` (a canonical committed value) to gate reward claims, the gateway uses a live mempool membership check instead of a canonical "deploy_account exists and is valid" check to gate signature verification. An unprivileged attacker who observes a pending `deploy_account` for address X can submit an invoke with a forged signature for X, have it admitted to the mempool without any signature check, and thereby occupy X's nonce-1 slot — blocking the legitimate user's invoke from being sequenced.

---

### Finding Description

`skip_stateful_validations` at line 429 of `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when three conditions hold simultaneously:

```
tx.nonce() == Nonce(Felt::ONE)
  && account_nonce == Nonce(Felt::ZERO)
  && account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

The third condition is evaluated by:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

This returns `true` if **any** transaction from `account_address` is present in the pool or recent-block state. The code comment asserts this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." That reasoning is circular and incorrect:

- For an undeployed account (`account_nonce == 0`), the only transaction that can legitimately reach the pool is a `deploy_account` (nonce=0), because an `invoke(nonce=0)` for a non-existent account would fail `__validate__` and be rejected.
- However, once a valid `deploy_account` for address X is in the pool, `account_tx_in_pool_or_recent_block(X)` returns `true`.
- At that point, **any** `invoke(nonce=1, sender=X)` — including one with a completely forged signature — satisfies all three conditions and has `run_validate_entry_point` skipped. [3](#0-2) 

The `run_validate_entry_point` call is the only place in the gateway path where the blockifier's `StatefulValidator::validate` (which calls the account's `__validate__` Cairo entry point) is invoked. When `skip_validate = true`, the execution flags are set to `validate: false`:

```rust
let execution_flags = ExecutionFlags {
    only_query, charge_fee, validate: !skip_validate, strict_nonce_check
};
``` [4](#0-3) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce validity and duplicate hashes — it does **not** verify signatures: [5](#0-4) 

The `validate_nonce` check for an invoke with `nonce=1` and `account_nonce=0` passes because `1` is within `[0, 0 + max_allowed_nonce_gap]` (default gap = 200): [6](#0-5) 

---

### Impact Explanation

An attacker can inject an invoke transaction carrying a forged/invalid signature into the mempool for any address that has a pending `deploy_account`. The forged invoke occupies the nonce-1 slot. When the batcher later executes the block, the `deploy_account` succeeds, then the forged invoke runs `__validate__` and reverts — but the nonce is consumed. The legitimate user's `invoke(nonce=1)` was either:

- Rejected from the mempool as a duplicate nonce (if the attacker submitted first), or
- Replaced only if the user pays a higher fee than the attacker (fee-escalation race).

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

The attack is fully unprivileged and requires only the ability to submit transactions to the public gateway endpoint. The triggering condition — a `deploy_account` in the mempool — is a normal, observable network event. Any new account deployment is vulnerable during the window between `deploy_account` admission and block finalization.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `deploy_account` transaction for the sender address is present in the pool. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool` that inspects transaction types, not just address membership. Alternatively, always run `__validate__` at the gateway but use a simulated state that pre-applies the pending `deploy_account` so the validation can succeed for the legitimate user without skipping it entirely.

---

### Proof of Concept

```
1. Alice submits RpcDeployAccountTransaction for address X (valid signature, class C).
   → Gateway: __validate_deploy__ passes → admitted to mempool.
   → mempool.tx_pool.contains_account(X) == true.

2. Bob submits RpcInvokeTransaction(sender=X, nonce=1, signature=FORGED).
   → Gateway stateful path:
       get_nonce_from_state(X) → Nonce(0)          [account not deployed]
       validate_nonce: 0 <= 1 <= 200               [passes]
       validate_resource_bounds                     [passes]
       validate_by_mempool                          [passes, no sig check]
       skip_stateful_validations:
           nonce==1 && account_nonce==0 → true
           account_tx_in_pool_or_recent_block(X) → true  ← live mempool state
           returns true  →  run_validate_entry_point SKIPPED
   → Bob's forged invoke admitted to mempool at nonce=1.

3. Alice submits her legitimate invoke(sender=X, nonce=1, signature=VALID).
   → Mempool rejects: DuplicateNonce or fee-escalation race.

4. Batcher sequences the block:
   deploy_account(X) → succeeds, X deployed with class C.
   invoke(X, nonce=1, FORGED) → __validate__ runs → REVERTS.
   Alice's nonce=1 is consumed by a failed transaction.
```

The root cause is identical to M-13: a live, mutable value (`account_tx_in_pool_or_recent_block`, analogous to `balanceOf(pair)`) is used as the sole gate for an authorization decision (skip signature verification, analogous to `isOtherEarningsClaimable`), instead of a canonical, committed value that cannot be transiently manipulated.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
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

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
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
