### Title
Invoke Signature Bypass via Non-Deploy-Account Mempool Presence in `skip_stateful_validations` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is intended to skip the `__validate__` entry point (signature verification) only when a `deploy_account` transaction is pending for a new account. However, the check `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction type from that address — including a plain invoke. An attacker who controls a fresh address can first submit a valid invoke with nonce=0, then submit a second invoke with nonce=1 carrying an **invalid signature**. The gateway skips `__validate__` for the second transaction and admits it to the mempool, violating the admission invariant.

### Finding Description

In `skip_stateful_validations`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The code comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is circular and incorrect. The function `account_tx_in_pool_or_recent_block` checks:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It returns `true` for **any** transaction type in the pool — including an invoke with nonce=0. There is no check that the pending transaction is a `DeployAccount`.

The `validate_nonce` function permits both nonce=0 and nonce=1 for an account with `account_nonce=0` (the `_` arm allows `account_nonce <= incoming_tx_nonce <= account_nonce + max_allowed_nonce_gap`):

```rust
_ => {
    let max_allowed_nonce =
        Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
    if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
        return Err(create_error(...));
    }
}
```

So both invoke(nonce=0) and invoke(nonce=1) pass nonce validation when `account_nonce=0`.

The full gateway admission path in `run_pre_validation_checks` is:

1. `validate_state_preconditions` — nonce range + resource bounds (both pass)
2. `validate_by_mempool` — mempool-level nonce/fee checks (no signature check)
3. `skip_stateful_validations` — returns `true` (skip `__validate__`)
4. `run_validate_entry_point` is called with `skip_validate=true`, setting `execution_flags.validate = false` — **`__validate__` is never called**

The transaction with the invalid signature is then forwarded to the mempool via `mempool_client.add_tx(add_tx_args)`.

### Impact Explanation

The gateway's core security invariant — that every admitted invoke transaction has passed its account's `__validate__` entry point (signature verification) — is broken. Any attacker controlling a fresh address can admit an invoke transaction with an arbitrary invalid signature into the mempool. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

The admitted invalid transaction will be rejected by the blockifier during batcher execution (the batcher always runs `__validate__`), so no funds are directly drained. However:
- The mempool is polluted with signature-invalid transactions
- The batcher wastes execution resources on transactions that will always fail
- At scale, this enables a low-cost DoS against the mempool and batcher

### Likelihood Explanation

The attack requires only two sequential RPC calls from a fresh address — no privileged access, no special network position, no cryptographic capability. The attacker needs only a valid keypair for the first invoke (nonce=0) and can use any bytes as the signature for the second invoke (nonce=1). The condition `account_nonce == Nonce(Felt::ZERO)` is trivially satisfied by any new address.

### Recommendation

In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`DeployAccount`** transaction is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address)` that inspects the transaction type, not just address presence. Alternatively, the gateway can inspect the transaction pool directly for a `DeployAccount` with nonce=0 from the same sender before granting the skip.

### Proof of Concept

```
# Step 1: Submit a valid invoke with nonce=0 from fresh address A
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xA",
  "nonce": "0x0",
  "signature": [<valid_sig>],
  ...
}
# → Admitted normally. account_tx_in_pool_or_recent_block("0xA") now returns true.

# Step 2: Submit an invoke with nonce=1 and INVALID signature from same address A
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xA",
  "nonce": "0x1",
  "signature": ["0xdeadbeef"],   # invalid
  ...
}
# Gateway flow:
#   validate_nonce: account_nonce=0, tx_nonce=1, 0 <= 1 <= 200 → PASS
#   validate_by_mempool: nonce/fee checks → PASS (no signature check)
#   skip_stateful_validations:
#     tx.nonce()==1 && account_nonce==0 → true
#     account_tx_in_pool_or_recent_block("0xA") → true (nonce=0 invoke is in pool)
#     returns true (SKIP __validate__)
#   run_validate_entry_point: execution_flags.validate=false → __validate__ NOT called
# → Transaction admitted to mempool with invalid signature.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L245-297)
```rust
    fn validate_nonce(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        let incoming_tx_nonce = executable_tx.nonce();

        let create_error = |message: String| {
            debug!("{message}");
            StarknetError {
                code: StarknetErrorCode::KnownErrorCode(
                    KnownStarknetErrorCode::InvalidTransactionNonce,
                ),
                message,
            }
        };

        match executable_tx {
            // Declare transactions must have the same nonce as the account nonce.
            ExecutableTransaction::Declare(_) if self.config.reject_future_declare_txs => {
                if incoming_tx_nonce != account_nonce {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: nonce = {account_nonce}, got: \
                         {incoming_tx_nonce}."
                    )));
                }
            }
            // Deploy account transactions must have nonce 0.
            ExecutableTransaction::DeployAccount(_) => {
                if account_nonce != Nonce(Felt::ZERO) {
                    return Err(create_error(format!(
                        "Invalid deploy account transaction. Account is already deployed \
                         (nonce={account_nonce})."
                    )));
                }
                if incoming_tx_nonce != Nonce(Felt::ZERO) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: nonce = 0, got: {incoming_tx_nonce}."
                    )));
                }
            }
            // Other transactions must be within the allowed nonce range.
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
        }
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-300)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
}
```
