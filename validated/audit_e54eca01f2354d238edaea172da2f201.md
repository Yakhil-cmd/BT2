### Title
Attacker Can Front-Run Victim's Post-Deploy Invoke to Bypass Signature Validation and Block Legitimate Admission - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point for invoke transactions with `nonce=1` when the account address is present in the mempool. The check is too broad: it returns `true` if **any** transaction from the address is in the mempool, not specifically a deploy-account transaction from the same user. An attacker who observes a victim's `deploy_account` in the mempool can immediately submit an unsigned invoke with `nonce=1` from the same address, bypassing signature verification entirely. The attacker's invalid invoke occupies the `(address, nonce=1)` slot, causing the victim's legitimate invoke to be rejected as `DuplicateNonce`.

### Finding Description

`skip_stateful_validations` is designed to improve UX by allowing a user to submit a `deploy_account` + `invoke(nonce=1)` pair simultaneously, before the deploy is confirmed on-chain. [1](#0-0) 

The guard condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...;
}
```

`account_tx_in_pool_or_recent_block` returns `true` if **any** transaction from the address is in the pool or recent committed state: [2](#0-1) 

The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is circular: the very mechanism being guarded is what allows a future-nonce invoke to enter the pool without validation.

When `skip_validate=true` is returned, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside the blockifier's `StatefulValidator::perform_validations`, for an invoke with `validate=false`, `perform_pre_validation_stage` (nonce/fee bounds) runs but `__validate__` is **not** called: [4](#0-3) 

The stateless validator never checks signature validity — it only checks signature **length**: [5](#0-4) 

**Attack flow:**

1. Victim submits `deploy_account` for address `A` (valid signature, nonce=0). It passes full gateway validation (deploy_account is fully executed during gateway validation, including `__validate_deploy__`) and enters the mempool.
2. Attacker observes `A` in the mempool. Attacker crafts `invoke(sender=A, nonce=1, calldata=attacker_data, signature=random_bytes)`.
3. Gateway stateful validation for attacker's invoke:
   - `validate_state_preconditions`: nonce=1, account_nonce=0 → passes (within `max_allowed_nonce_gap`).
   - `validate_by_mempool`: no existing `(A, nonce=1)` in pool → passes.
   - `skip_stateful_validations`: `account_tx_in_pool_or_recent_block(A)` = `true` (victim's deploy_account is there) → returns `skip=true`.
   - `run_validate_entry_point` with `validate=false` → `__validate__` **not called**.
4. Attacker's unsigned invoke is admitted to the mempool.
5. Victim submits `invoke(sender=A, nonce=1, calldata=victim_data, signature=valid)`.
6. `validate_by_mempool` finds `(A, nonce=1)` already occupied → `MempoolError::DuplicateNonce` → victim's invoke **rejected**.

The attacker's invoke will revert during execution (blockifier calls `__validate__` with `validate=true` during block building), but the damage is done: the victim's legitimate invoke is blocked for the current block.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

- An invoke transaction with an arbitrary/invalid signature is admitted to the mempool without any signature check.
- The legitimate user's correctly-signed invoke is rejected as `DuplicateNonce`.
- The attacker requires no funds, no privileged access, and no knowledge of the victim's private key — only the ability to observe the mempool and submit a transaction.

### Likelihood Explanation

The mempool is observable (P2P gossip, RPC). The attack requires a single cheap transaction per victim address. Any address that uses the deploy+invoke UX pattern is vulnerable. The window is the time between the victim's `deploy_account` entering the mempool and the victim's `invoke(nonce=1)` being submitted — typically milliseconds to seconds in normal usage.

### Recommendation

The `skip_stateful_validations` check must verify that a **deploy-account transaction specifically** exists in the mempool for the sender address, not merely that any transaction from that address is present. Options:

1. Add a dedicated mempool query `has_pending_deploy_account(address) -> bool` that inspects transaction types in the pool.
2. Store a separate set of addresses with pending deploy-account transactions and consult it in `skip_stateful_validations`.
3. Require the caller to supply the deploy-account transaction hash (as `native_blockifier`'s `PyValidator::should_run_stateful_validations` already does via `deploy_account_tx_hash: Option<TransactionHash>`) and verify it is present in the mempool with the correct type. [6](#0-5) 

### Proof of Concept

```
# State: address A not deployed on-chain (account_nonce = 0)

# Step 1 – Victim submits deploy_account (valid)
POST /add_transaction
{
  "type": "DEPLOY_ACCOUNT",
  "class_hash": "0x...",
  "contract_address_salt": "0x...",
  "constructor_calldata": ["<victim_pubkey>"],
  "nonce": "0x0",
  "signature": ["<valid_sig_r>", "<valid_sig_s>"],
  ...
}
# → Accepted. address A now in mempool tx_pool.

# Step 2 – Attacker submits invoke with nonce=1, random signature
POST /add_transaction
{
  "type": "INVOKE",
  "sender_address": "<address A>",
  "calldata": ["<attacker_calldata>"],
  "nonce": "0x1",
  "signature": ["0xdeadbeef"],   # invalid
  ...
}
# Gateway: nonce=1, account_nonce=0, account_tx_in_pool_or_recent_block(A)=true
# → skip_validate=true → __validate__ NOT called → ACCEPTED into mempool

# Step 3 – Victim submits invoke with nonce=1, valid signature
POST /add_transaction
{
  "type": "INVOKE",
  "sender_address": "<address A>",
  "calldata": ["<victim_calldata>"],
  "nonce": "0x1",
  "signature": ["<valid_sig_r>", "<valid_sig_s>"],
  ...
}
# validate_by_mempool: (A, nonce=1) already occupied by attacker's tx
# → MempoolError::DuplicateNonce → REJECTED
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-95)
```rust
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
            }
        }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
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
    }
```

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
