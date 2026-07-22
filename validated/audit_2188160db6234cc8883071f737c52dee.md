### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Transactions for Undeployed Accounts — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator skips the `__validate__` entry-point check for an invoke transaction with nonce=1 when the on-chain account nonce is 0, based solely on whether the sender address has *any* transaction in the mempool. It does not verify that the invoke transaction originates from the same user who submitted the deploy-account transaction. An unprivileged attacker can submit an invoke transaction for a victim's not-yet-deployed address with arbitrary calldata and no valid signature; the gateway will accept it because the victim's deploy-account is already in the mempool.

---

### Finding Description

The UX feature that allows a user to submit a `deploy_account + invoke` pair atomically is implemented in `skip_stateful_validations`:

```
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this function returns `true`, `run_validate_entry_point` sets `ExecutionFlags { validate: false, ... }` and calls `blockifier_validator.validate(account_tx)` — which, because `validate` is `false`, skips the `__validate__` entry-point entirely: [2](#0-1) 

The only guard is `account_tx_in_pool_or_recent_block(tx.sender_address())`, which checks whether the *sender address of the incoming invoke* has any transaction in the mempool: [3](#0-2) 

This check is keyed on the sender address supplied by the attacker in the invoke transaction itself. It does not verify:
- that the invoke transaction carries a valid signature over the transaction hash,
- that the deploy-account transaction in the mempool was submitted by the same key that controls the target address, or
- any cryptographic binding between the deploy-account and the invoke.

The analog to the external report is exact: just as `executeOperation`/`onFlashLoan` checked only that the *caller* was an authorized flash-loan provider but not that the *initiator* was the swap contract itself, `skip_stateful_validations` checks only that the sender address has *some* mempool entry but not that the invoke transaction is authorized by the account owner.

---

### Impact Explanation

**Gateway/mempool admission accepts an invalid transaction before sequencing (High).**

1. The gateway accepts an invoke transaction that carries no valid account signature, because `run_validate_entry_point` is called with `validate: false`.
2. The transaction is inserted into the mempool. If the victim's legitimate invoke (same nonce=1) is already present, the attacker can displace it via fee escalation (the mempool supports replacing a same-nonce transaction with a higher-fee one).
3. When the batcher later executes the attacker's invoke, the blockifier *will* call `__validate__` (it uses `validate: true` by default). For accounts with proper signature checks this call fails, the transaction is rejected, and the nonce is not incremented — but the victim's original invoke has already been evicted from the mempool.
4. For accounts whose `__validate__` is permissive (e.g., always returns `VALID`), the attacker's arbitrary calldata executes under the victim's identity — escalating to Critical.

---

### Likelihood Explanation

The attack requires only that the attacker observe a deploy-account transaction in the public mempool (trivially possible) and submit a competing invoke for the same sender address before the victim's invoke is sequenced. No privileged access, no special keys, and no on-chain funds are required. The window is the time between the victim's deploy-account entering the mempool and the block being sealed — typically several seconds to minutes.

---

### Recommendation

The `skip_stateful_validations` function must verify that the invoke transaction is authorized by the same key that controls the target address. Two concrete options:

1. **Do not skip `__validate__` at the gateway.** The UX feature can be preserved by accepting the transaction into the mempool even when the account does not yet exist on-chain, but still running the full `__validate__` entry-point simulation against the *pending* state (i.e., after the deploy-account constructor has been applied). This is the approach analogous to the fix in the referenced PR (`require(initiator == address(this)`).

2. **Bind the skip to the deploy-account transaction hash.** Store the deploy-account tx hash alongside the mempool entry and require the invoke transaction to reference it (or derive the expected sender address from the deploy-account's class hash, salt, and constructor calldata, and verify it matches `tx.sender_address()`). This prevents an attacker from exploiting a victim's deploy-account entry to skip validation for their own forged invoke.

---

### Proof of Concept

```
// Setup: victim wants to deploy account at address V and immediately invoke.
// Victim submits:
//   deploy_account_tx  (nonce=0, sender=V, valid signature)
//   invoke_tx_victim   (nonce=1, sender=V, calldata=victim_calldata, valid signature)

// Attacker observes deploy_account_tx in the mempool.
// Attacker constructs:
//   invoke_tx_attacker (nonce=1, sender=V, calldata=arbitrary, signature=garbage,
//                       resource_bounds > victim's to win fee escalation)

// Gateway processing of invoke_tx_attacker:
// 1. StatelessTransactionValidator::validate — passes (valid structure, nonce DA mode, etc.)
// 2. extract_state_nonce_and_run_validations:
//    a. get_nonce_from_state(V) → Nonce(0)   [V not deployed yet]
//    b. validate_state_preconditions → passes (nonce 1 within allowed gap)
//    c. validate_by_mempool → passes (no duplicate tx_hash; nonce 1 ≥ account nonce 0)
//    d. skip_stateful_validations:
//         tx.nonce() == 1  ✓
//         account_nonce == 0  ✓
//         account_tx_in_pool_or_recent_block(V) → true  ✓  (victim's deploy_account is there)
//         returns true  →  skip_validate = true
//    e. run_validate_entry_point(skip_validate=true):
//         ExecutionFlags { validate: false, ... }
//         __validate__ is NOT called
//         → Ok(())
// 3. Gateway returns success; invoke_tx_attacker enters mempool,
//    displacing invoke_tx_victim via fee escalation.

// Result: victim's invoke is evicted; attacker's unsigned invoke is queued.
// If V's __validate__ is permissive, attacker's calldata executes under V's identity.
// If V's __validate__ checks signatures, the attacker achieves a persistent DoS
// (victim must resubmit; attacker can repeat indefinitely at low cost).
```

The root cause is at: [4](#0-3) 

with the missing invariant being: *the invoke transaction must be cryptographically authorized by the owner of `tx.sender_address()`*, regardless of whether a deploy-account for that address is pending.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-355)
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
