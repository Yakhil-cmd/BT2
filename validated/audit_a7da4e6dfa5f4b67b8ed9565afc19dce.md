### Title
Gateway Skips `__validate__` Signature Check for Nonce-1 Invoke When Any Account Transaction Is in Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is intended to bypass the `__validate__` entry-point call only when a pending `deploy_account` transaction exists for an undeployed account. However, it uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** account that has **any** transaction in the mempool pool or staged state — not specifically a `deploy_account`. An attacker who first submits a valid nonce-0 invoke for an already-deployed account can then submit a nonce-1 invoke with a forged/invalid signature that bypasses the gateway's `__validate__` call entirely and is admitted to the mempool.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` decides whether to skip the blockifier `__validate__` entry-point call at the gateway:

```rust
async fn skip_stateful_validations(...) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

The code comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is incorrect. `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`tx_pool.contains_account` returns `true` for **any** transaction type from that address — including a regular invoke with nonce 0. There is no check that the pending transaction is specifically a `deploy_account`.

**Attack sequence:**

1. Account A is deployed on-chain (nonce = 0).
2. Attacker submits `invoke_A_nonce0` with a valid signature. It passes `__validate__` normally and is admitted to the mempool.
3. Attacker submits `invoke_A_nonce1` with an **invalid/forged signature**.
4. Gateway stateful validation runs:
   - `validate_nonce`: nonce 1 is within `[0, 0+200]` → passes.
   - `validate_by_mempool`: nonce 1 ≥ 0 → passes.
   - `skip_stateful_validations`: `tx.nonce() == 1 && account_nonce == 0` → checks `account_tx_in_pool_or_recent_block(A)` → **returns `true`** because `invoke_A_nonce0` is in the pool.
   - `skip_validate = true` → `run_validate_entry_point` sets `execution_flags.validate = false` → **`__validate__` is never called**.
5. `invoke_A_nonce1` with invalid signature is admitted to the mempool. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

The gateway's `__validate__` call is the sole signature-verification gate at admission time. Bypassing it allows a transaction with an invalid or forged signature to enter the mempool and be handed to the batcher. The blockifier will reject it during block execution (because it runs `__validate__` with `validate = true` and `strict_nonce_check = true`), but the transaction has already passed the admission invariant. This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

Concrete consequences:
- An attacker can inject signature-invalid transactions into the mempool for any deployed account that has a nonce-0 invoke pending.
- The batcher wastes execution resources attempting the transaction.
- The invalid nonce-1 transaction occupies the nonce-1 slot in the mempool, potentially delaying or displacing the legitimate nonce-1 transaction from the account owner.

### Likelihood Explanation

The trigger requires only two sequential gateway calls from an unprivileged sender:
1. A valid nonce-0 invoke for the target account (or waiting for the account owner to submit one).
2. A nonce-1 invoke with any invalid signature.

No privileged access, no special contract state, and no race condition is required. The `max_allowed_nonce_gap` default of 200 ensures nonce 1 always passes the nonce range check. The condition `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` is satisfied for any freshly deployed account. [4](#0-3) 

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address)` that inspects the transaction type, not merely the account's presence. Alternatively, the gateway can track the deploy-account tx hash it accepted and pass it explicitly (as the `native_blockifier` `PyValidator` already does via `deploy_account_tx_hash`). [5](#0-4) 

### Proof of Concept

```
# Precondition: Account A is deployed on-chain, nonce = 0.

# Step 1: Submit a valid nonce-0 invoke for account A.
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<A>",
  "nonce": "0x0",
  "signature": ["<valid_r>", "<valid_s>"],   # valid ECDSA signature
  ...
}
# → Admitted. invoke_A_nonce0 is now in the mempool.

# Step 2: Submit a nonce-1 invoke for account A with a forged signature.
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<A>",
  "nonce": "0x1",
  "signature": ["0xdeadbeef", "0xdeadbeef"],  # invalid signature
  ...
}
# Gateway flow:
#   validate_nonce(1, account_nonce=0): 0 <= 1 <= 200 → OK
#   validate_by_mempool: nonce 1 >= 0 → OK
#   skip_stateful_validations:
#     tx.nonce()==1 && account_nonce==0 → true
#     account_tx_in_pool_or_recent_block(A) → true  (nonce-0 invoke is in pool)
#     skip_validate = true
#   run_validate_entry_point: execution_flags.validate = false → __validate__ NOT called
# → Admitted. invoke_A_nonce1 with forged signature is now in the mempool.
```

The forged nonce-1 transaction will be rejected by the blockifier during block execution (because `__validate__` is called there with `validate = true`), but it has bypassed the gateway's admission invariant. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
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
