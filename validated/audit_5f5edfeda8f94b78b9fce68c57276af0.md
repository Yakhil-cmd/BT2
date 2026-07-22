### Title
Gateway Admits Invoke Transactions with Unverified Signatures via `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally skips the `__validate__` entry-point (account signature verification) for any Invoke transaction whose nonce is 1 and whose sender address appears in the mempool — regardless of who submitted the transaction that caused the address to appear there. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a forged Invoke(nonce=1) for the same address with an arbitrary or empty signature, and the gateway will admit it without verifying the signature.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after the nonce/resource-bounds checks but before the blockifier `__validate__` call:

```
run_pre_validation_checks
  └─ validate_state_preconditions   (nonce range, resource bounds)
  └─ validate_by_mempool            (duplicate-nonce / mempool state)
  └─ skip_stateful_validations      ← returns true → __validate__ skipped
```

The skip condition is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `ExecutionFlags { validate: false }` and calls `blockifier_validator.validate(account_tx)`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the function returns immediately after `perform_pre_validation_stage`, never calling `validate_tx` (which is the only place `__validate__` is invoked):

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:79-81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The proxy check `account_tx_in_pool_or_recent_block` is:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

This returns `true` for **any** address that has **any** transaction in the pool — not specifically a `deploy_account` transaction from the same sender. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this reasoning does not hold against an adversary:

- Victim submits `deploy_account` for address X → `tx_pool.contains_account(X)` becomes `true`.
- Attacker observes this and immediately submits `Invoke(sender=X, nonce=1, signature=<garbage>)`.
- Gateway evaluates: `nonce==1` ✓, `account_nonce==0` ✓, `account_tx_in_pool_or_recent_block(X)` ✓ → `skip_validate = true`.
- `__validate__` is never called; the forged transaction is admitted to the mempool.

The `validate_by_mempool` call that precedes the skip check only validates mempool-level invariants (duplicate nonce, nonce gap); it does not verify the cryptographic signature. [5](#0-4) 

### Impact Explanation

The gateway admits an Invoke transaction with an unverified (potentially forged) signature into the mempool. This directly satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concrete consequences:

1. **Displacement / griefing**: If the attacker's forged Invoke(nonce=1) reaches the mempool before the victim's legitimate Invoke(nonce=1), the victim's transaction is rejected as a duplicate nonce. The victim must resubmit (possibly at a higher fee to trigger fee-escalation replacement).
2. **Forced block-building failure**: The forged transaction will fail `__validate__` during block building (since `new_for_sequencing` always sets `validate: true`), consuming batcher resources and causing the transaction to be marked rejected.
3. **Persistent mempool pollution**: Because `state.contains_account` persists across committed blocks, the window of vulnerability is not limited to the brief period before the `deploy_account` is committed; any address ever seen in a committed block with `account_nonce==0` at query time is susceptible. [6](#0-5) 

### Likelihood Explanation

The mempool is public. Any observer can detect a pending `deploy_account` transaction and immediately race to submit a forged Invoke(nonce=1) for the same address. No privileged access, special key material, or prior relationship with the victim is required. The only cost to the attacker is the transaction fee paid when the forged transaction eventually fails during block building.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account`** transaction for the same address is pending in the mempool. Expose a dedicated mempool query such as `deploy_account_tx_in_pool(address) -> bool` that only returns `true` when a `DeployAccount` transaction (not any transaction) is present for the given address. This preserves the UX feature while closing the forgery window.

### Proof of Concept

```
1. Victim calls gateway: POST /add_transaction
      { type: DEPLOY_ACCOUNT, sender_address: 0xVICTIM, nonce: 0, ... valid sig ... }
   → Mempool: tx_pool.contains_account(0xVICTIM) = true

2. Attacker calls gateway: POST /add_transaction
      { type: INVOKE, sender_address: 0xVICTIM, nonce: 1, signature: [0x0] }
   Gateway evaluation:
     account_nonce = 0  (0xVICTIM not yet deployed)
     tx.nonce == 1      ✓
     account_nonce == 0 ✓
     account_tx_in_pool_or_recent_block(0xVICTIM) = true ✓
     → skip_validate = true
     → __validate__ NOT called
     → Transaction admitted to mempool

3. Victim calls gateway: POST /add_transaction
      { type: INVOKE, sender_address: 0xVICTIM, nonce: 1, ... valid sig ... }
   → Mempool rejects: DuplicateNonce (attacker's tx already occupies nonce=1)

4. Block building:
     deploy_account executed → 0xVICTIM deployed, nonce → 1
     attacker's Invoke(nonce=1) executed → __validate__ called → signature invalid → REJECTED
     victim's Invoke(nonce=1) is no longer in mempool → victim must resubmit
``` [7](#0-6) [8](#0-7)

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
