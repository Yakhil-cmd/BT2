### Title
Attacker-Controlled `sender_address` Bypasses Signature Verification via `skip_stateful_validations` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator uses the attacker-controlled `sender_address` field from an RPC invoke transaction to decide whether to skip the `__validate__` entry-point call entirely. An attacker who observes a victim's pending `deploy_account` transaction in the mempool can submit a spoofed invoke transaction with the victim's `sender_address` and `nonce=1`, causing the gateway to admit it to the mempool without any signature verification.

### Finding Description

`skip_stateful_validations` is called from `run_pre_validation_checks` to implement a UX feature: when a user submits a `deploy_account` + `invoke` pair simultaneously, the invoke (nonce=1) is admitted even though the account contract does not yet exist on-chain (so `__validate__` cannot run).

The skip condition is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    let account_address = tx.sender_address();   // ← attacker-controlled
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...;
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate = false`, the `__validate__` call is skipped entirely and `Ok(())` is returned:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

The mempool's own `validate_tx` only checks nonce ordering and fee escalation — it performs no signature verification:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [4](#0-3) 

`account_tx_in_pool_or_recent_block` returns `true` for any address that has any transaction in the pool or was recently committed:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

Because `sender_address` is a free field in the RPC transaction (not bound to the submitter's identity at the gateway level), any attacker can set it to any victim address.

### Impact Explanation

The gateway admits an invoke transaction to the mempool without verifying the signature. This matches **High: Mempool/gateway/RPC admission accepts invalid transactions before sequencing**.

Concrete consequences:
1. **Mempool slot squatting**: The attacker's invalid invoke tx occupies the `(victim_address, nonce=1)` slot. If the victim also submitted a legitimate invoke at nonce=1, the attacker's tx may displace it via fee escalation rules, or the victim's tx is rejected as a duplicate nonce.
2. **Wasted block space**: The attacker's tx will be included in a block (nonce ordering is satisfied after the deploy_account executes), run `__validate__` during execution, fail, and revert — consuming block gas and bouncer budget for nothing.
3. **Scalable DoS**: An attacker can monitor the mempool for all pending `deploy_account` transactions and flood each one with a spoofed nonce=1 invoke, systematically disrupting the deploy+invoke UX feature for all new accounts.

### Likelihood Explanation

- The attack requires only that a victim's `deploy_account` transaction is visible in the mempool (standard behavior for the deploy+invoke UX flow).
- No privileged access is needed; any unprivileged user can submit an RPC transaction with an arbitrary `sender_address`.
- The mempool is observable via the P2P gossip layer and the standard RPC `get_txs` path, making victim discovery straightforward.

### Recommendation

Bind the skip to the **deployer's identity**, not just the `sender_address` field. The gateway should only skip `__validate__` when the incoming invoke transaction's signature can be pre-verified against the public key committed in the pending `deploy_account` transaction's `constructor_calldata`. Concretely:

1. When `skip_stateful_validations` would return `true`, retrieve the pending `deploy_account` transaction from the mempool for `sender_address`.
2. Extract the expected public key from its `constructor_calldata`.
3. Verify the invoke transaction's signature against that public key before skipping `__validate__`.

Alternatively, restrict the skip to only the **exact transaction hash pair** submitted together (deploy_account + invoke) so that a third party cannot exploit the open slot.

### Proof of Concept

1. Victim submits `deploy_account` tx for address `V` (nonce=0). It enters the mempool. `account_tx_in_pool_or_recent_block(V)` now returns `true`.
2. On-chain state for `V`: nonce=0 (not yet deployed).
3. Attacker submits an RPC invoke transaction:
   - `sender_address = V`
   - `nonce = 1`
   - `signature = [0x0, 0x0]` (garbage)
   - `calldata` = arbitrary (e.g., drain victim's tokens)
4. Gateway stateless validation passes (no signature check there).
5. `extract_state_nonce_and_run_validations` fetches nonce for `V` → `Nonce(0)`.
6. `run_pre_validation_checks` → `validate_state_preconditions` passes (nonce 1 is within allowed gap from 0). `validate_by_mempool` passes (nonce ordering OK). `skip_stateful_validations` returns `true` because `tx.nonce()==1`, `account_nonce==0`, and `account_tx_in_pool_or_recent_block(V)==true`.
7. `run_validate_entry_point` is called with `skip_validate=true` → `execution_flags.validate=false` → `StatefulValidator::perform_validations` returns `Ok(())` without calling `__validate__`.
8. The attacker's invalid invoke tx is admitted to the mempool at `(V, nonce=1)`.
9. If the victim also submitted a legitimate invoke at nonce=1, it is rejected as `DuplicateNonce` (or requires fee escalation to displace the attacker's tx). [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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
