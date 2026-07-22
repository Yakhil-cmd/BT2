### Title
Unauthenticated `sender_address` Bypasses Signature Validation for Invoke Transactions via `skip_stateful_validations` - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (account signature verification) for invoke transactions whose `sender_address` field — fully attacker-controlled — resolves to any address that has a transaction in the mempool or a recent block. No check is made that the invoke transaction is actually signed by the key controlling that address. An unprivileged attacker can craft an invoke transaction with an arbitrary `sender_address` pointing to any account with a pending `deploy_account` transaction, set nonce=1, attach a garbage signature, and have it admitted to the mempool without any cryptographic authentication.

### Finding Description

`skip_stateful_validations` is the direct Sequencer analog of the external C-06 bug: just as `onUninstall` extracted `sender` from `data` and used it without checking `sender == msg.sender`, `skip_stateful_validations` extracts `sender_address` from the attacker-supplied transaction and uses it to look up mempool state without verifying the transaction is actually authorized by that address.

The function is:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())  // ← attacker-controlled
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

The three conditions that trigger the skip are:
1. Transaction type is `Invoke`
2. `tx.nonce() == 1` — attacker sets this
3. `account_nonce == 0` — true for any undeployed account

The mempool check `account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true` if the address has **any** transaction in the pool or was seen in a recent block:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

When all three conditions hold, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false` and skips the `__validate__` entry point entirely:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Neither the stateless validator nor the mempool's `validate_tx` performs any signature verification — the stateless validator only checks sizes and resource bounds, and the mempool only checks nonce ordering and fee escalation. [4](#0-3) [5](#0-4) 

### Impact Explanation

An attacker can insert invoke transactions with arbitrary (invalid) signatures into the mempool for any account that has a pending `deploy_account` transaction, bypassing the gateway's only cryptographic authentication gate. These transactions are admitted to the mempool without the account's `__validate__` entry point being called. They will fail at block execution time (when `__validate__` is called by the blockifier), but until then they occupy mempool slots, can displace legitimate nonce-1 transactions via fee escalation, and degrade sequencer throughput. The production `max_allowed_nonce_gap` is 200, so the nonce=1 check passes trivially. [6](#0-5) 

### Likelihood Explanation

The attack requires only:
1. Observing any address with a pending `deploy_account` in the mempool (publicly visible)
2. Crafting an invoke transaction with that address as `sender_address`, nonce=1, and any signature

No privileged access, no private key, no special knowledge is required. The mempool is public and the condition is trivially satisfiable whenever the deploy+invoke UX pattern is used.

### Recommendation

Before returning `true` from `skip_stateful_validations`, verify that the transaction in the mempool for `tx.sender_address()` is specifically a `deploy_account` transaction (not just any transaction). Alternatively, require that the `deploy_account` transaction hash be provided alongside the invoke transaction (as the `native_blockifier` path does via `deploy_account_tx_hash`) and verify it matches the pending deploy for the exact `sender_address`. [7](#0-6) 

### Proof of Concept

1. Alice submits `deploy_account` for address `A` (class_hash=C, salt=S). It enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`. State nonce for `A` is `0`.

2. Attacker crafts:
   ```
   RpcInvokeTransactionV3 {
       sender_address: A,       // Alice's undeployed address
       nonce: 1,                // exactly Nonce(Felt::ONE)
       signature: [0xdead],     // garbage
       resource_bounds: { l2_gas: { max_amount: 1, max_price_per_unit: 8_000_000_001 } },
       ...
   }
   ```

3. Gateway stateless validator: passes (no signature check, resource bounds non-zero).

4. `extract_state_nonce_and_run_validations`:
   - `get_nonce_from_state(A)` → `Nonce(0)` (A not deployed)
   - `validate_nonce`: Invoke branch, `0 ≤ 1 ≤ 200` → passes
   - `validate_by_mempool`: nonce/fee checks only → passes
   - `skip_stateful_validations`: nonce==1 ✓, account_nonce==0 ✓, `account_tx_in_pool_or_recent_block(A)` → `true` → returns `true`
   - `run_validate_entry_point(skip_validate=true)` → `__validate__` is **not called**

5. Attacker's invalid invoke tx is admitted to the mempool. It occupies the nonce-1 slot for address `A`, potentially displacing Alice's legitimate nonce-1 invoke if Alice also submitted one (via fee escalation rules). [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
```

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L17-18)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_allowed_nonce_gap": 200,
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1",
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
