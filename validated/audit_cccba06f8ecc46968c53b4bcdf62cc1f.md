After thorough investigation of the codebase, I found a valid analog.

---

### Title
Attacker Can Inject Unsigned Invoke Transaction for Any Account with a Pending Deploy-Account in the Mempool, Bypassing Gateway Signature Validation — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point for any invoke transaction with nonce 1 when `account_tx_in_pool_or_recent_block` returns `true` for the sender. Because that check returns `true` for **any** transaction from the account — not specifically a deploy-account transaction — an attacker who observes a victim's pending deploy-account in the mempool can immediately submit an invoke transaction with nonce 1, an arbitrary calldata, and an empty/invalid signature for the victim's address. The gateway accepts it without ever calling `__validate__`, admitting an unauthorized transaction into the mempool.

### Finding Description

`skip_stateful_validations` is a UX feature that allows a user to submit a deploy-account and a follow-up invoke together, even though the account does not yet exist on-chain:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...;
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`, which sets `ExecutionFlags { validate: false, ... }` and passes it to the blockifier — causing the account's `__validate__` entry point to be entirely skipped:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
...
blockifier_validator.validate(account_tx)
``` [2](#0-1) 

The condition that enables the skip is `account_tx_in_pool_or_recent_block`, which checks for **any** transaction from the account — not specifically a deploy-account:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

The code comment claims this is safe because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." However, the attacker's nonce-1 invoke is itself the transaction that makes `account_tx_in_pool_or_recent_block` return `true` for a second attacker, and — more critically — the victim's deploy-account alone is sufficient to trigger the skip for the attacker's nonce-1 invoke.

The stateless validator performs no signature check:

```rust
pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
    Self::validate_contract_address(tx)?;
    Self::validate_empty_account_deployment_data(tx)?;
    Self::validate_empty_paymaster_data(tx)?;
    self.validate_resource_bounds(tx)?;
    self.validate_tx_size(tx)?;
    ...
    Ok(())
}
``` [4](#0-3) 

The mempool's `validate_tx` only checks nonce validity, not signatures: [5](#0-4) 

### Impact Explanation

An attacker can submit an invoke transaction with arbitrary calldata and an invalid/empty signature for any account that has a pending deploy-account in the mempool. The gateway accepts it without calling `__validate__`. The transaction enters the mempool and is sequenced.

During batcher execution, `__validate__` is called (the batcher creates `AccountTransaction` objects independently with `validate: true`). For standard accounts the transaction reverts — but the nonce is still incremented. This causes a targeted DoS: the victim's legitimate nonce-1 invoke becomes invalid (nonce too old) after the attacker's reverted transaction consumes nonce 1. For account contracts that do not enforce signature checks in `__validate__` (e.g., `AccountWithoutValidations` used in testing, or custom accounts), the attacker's calldata executes successfully from the victim's address.

This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

Deploy-account transactions are observable in the mempool. The attack window is the time between a victim's deploy-account entering the mempool and being included in a block. The attacker needs only the victim's account address (deterministic from the deploy-account parameters) and the ability to submit a transaction. No privileged access is required.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account** transaction exists for the sender address. The mempool should expose a dedicated `deploy_account_tx_in_pool(address)` query, or the gateway should track pending deploy-account hashes and match them by sender address before granting the validation skip.

### Proof of Concept

1. Victim submits `deploy_account` (nonce 0) for account address `A` → accepted into mempool.
2. Attacker submits `invoke` with `sender_address = A`, `nonce = 1`, arbitrary `calldata`, empty `signature`.
3. **Stateless validation** (`StatelessTransactionValidator::validate`): passes — no signature check.
4. **Stateful validation** (`extract_state_nonce_and_run_validations`):
   - `get_nonce_from_state(A)` → returns `Nonce(0)` (account not deployed).
   - `validate_nonce`: `0 ≤ 1 ≤ 0 + max_gap` → passes.
   - `validate_by_mempool`: nonce 1 is within range → passes.
   - `skip_stateful_validations`: `tx.nonce() == 1`, `account_nonce == 0`, `account_tx_in_pool_or_recent_block(A) == true` (victim's deploy-account is in pool) → **returns `true`**.
   - `run_validate_entry_point(skip_validate=true)`: `ExecutionFlags { validate: false }` → `__validate__` **never called**.
5. Attacker's invoke tx is accepted into the mempool with an invalid signature.
6. Batcher executes in nonce order: `deploy_account` (nonce 0) deploys account `A`; then attacker's `invoke` (nonce 1) is executed — `__validate__` is now called by the blockifier, fails for standard accounts → transaction reverts, but **nonce is incremented to 2**.
7. Victim's legitimate `invoke` (nonce 1) is now rejected as nonce-too-old.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-342)
```rust
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

**File:** crates/apollo_mempool/src/communication.rs (L144-147)
```rust
    fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        self.mempool.validate_tx(args)?;
        Ok(())
    }
```
