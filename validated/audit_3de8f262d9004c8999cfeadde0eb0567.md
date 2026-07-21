Looking at the actual code for `skip_stateful_validations` and `run_validate_entry_point` in `stateful_transaction_validator.rs`:

### Title
Gateway Admits Invoke Transaction Without Signature Verification via `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

When a deploy-account transaction exists in the mempool (or recent block) for a given address, the gateway's `skip_stateful_validations` function returns `true` for any invoke with `nonce=1` and on-chain `account_nonce=0`. This causes `run_validate_entry_point` to set `execution_flags.validate = false`, entirely skipping the blockifier's `__validate__` entry point — the only place where the account contract verifies the invoke's signature. No other check in the gateway path verifies the signature. The invoke is admitted to the mempool without any signature verification.

### Finding Description

The call chain in `extract_state_nonce_and_run_validations` is:

1. `get_nonce_from_state` → `account_nonce = 0` (account not yet deployed on-chain)
2. `run_pre_validation_checks`:
   - `validate_state_preconditions` → checks nonce range (`0 <= 1 <= max_allowed_nonce_gap`), passes
   - `validate_by_mempool` → sends `ValidationArgs` (address, nonces, tx_hash, tip, gas price — **no signature field**), passes
   - `skip_stateful_validations` → invoke + `nonce==1` + `account_nonce==0` + `account_tx_in_pool_or_recent_block` returns `true` → **returns `true`**
3. `run_validate_entry_point(executable_tx, skip_validate=true)`:
   - Sets `execution_flags.validate = !skip_validate = false`
   - Blockifier's `StatefulValidator::validate` is called with `validate=false` → `__validate__` entry point is **not called** [1](#0-0) [2](#0-1) 

`ValidationArgs` contains only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price` — no signature — so `validate_by_mempool` cannot substitute for signature verification. [3](#0-2) 

### Impact Explanation

The gateway admits an invoke transaction with an **arbitrary/invalid signature** to the mempool. The corrupted admission value is concrete: an invoke transaction whose `__validate__` would fail is accepted as if it were valid. This matches:

> High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.

Secondary impacts:
- **Griefing**: An attacker observing Alice's deploy-account in the mempool can immediately submit an invoke with `nonce=1` for Alice's address with a forged/malicious signature. If the mempool enforces one-tx-per-nonce-per-account, this blocks Alice's legitimate invoke from being admitted.
- **Mempool pollution**: Attacker can flood the mempool with invalid nonce-1 invokes for any address with a pending deploy-account.

### Likelihood Explanation

The condition is easy to trigger: deploy-account transactions are publicly observable in the mempool. Any attacker can submit a nonce-1 invoke for any address with a pending deploy-account. No privileged access is required. The only prerequisite is that a deploy-account exists in the mempool or recent block for the target address.

### Recommendation

Before returning `true` from `skip_stateful_validations`, verify that the invoke's sender address matches the sender of the deploy-account transaction that is in the pool. Alternatively, run a lightweight signature check (e.g., ECDSA pre-check at the stateless validator level) for the nonce-1 invoke even when `skip_validate=true`, or restrict the skip to only when the deploy-account and invoke arrive in the same gateway request (i.e., as a bundle).

### Proof of Concept

```rust
// In a test: mock mempool client returns true for account_tx_in_pool_or_recent_block.
// Submit an invoke with nonce=1, sender=X, account_nonce=0 (from state), invalid signature.
// Assert: extract_state_nonce_and_run_validations returns Ok(Nonce(0))
//         and the blockifier StatefulValidator::validate was called with validate=false
//         (i.e., __validate__ was never invoked on the account contract).
let mut mock_mempool = MockMempoolClient::new();
mock_mempool
    .expect_account_tx_in_pool_or_recent_block()
    .returning(|_| Ok(true));
mock_mempool
    .expect_validate_tx()
    .returning(|_| Ok(()));

let invoke_tx = build_invoke_tx(sender=X, nonce=1, signature=INVALID);
// account_nonce from state = 0 (account not deployed)
let result = validator.extract_state_nonce_and_run_validations(
    &invoke_tx, Arc::new(mock_mempool)
).await;
assert!(result.is_ok()); // admitted without __validate__ being called
``` [4](#0-3) [5](#0-4)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-312)
```rust
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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-57)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```
