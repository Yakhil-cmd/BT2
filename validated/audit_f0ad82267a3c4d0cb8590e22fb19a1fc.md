### Title
Unsigned Invoke Transaction Admitted to Mempool via `skip_stateful_validations` Signature-Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` skips the blockifier `__validate__` entry-point call for any invoke transaction whose `sender_address` already has *any* transaction in the mempool and whose nonce is exactly 1. Because the check is keyed only on the sender address — not on a specific deploy-account transaction hash — an unprivileged attacker can front-run a victim's first post-deploy invoke by submitting an invoke with the same sender address, nonce 1, and a garbage signature. The gateway admits the attacker's transaction without ever verifying the signature, and the victim's legitimate transaction is subsequently rejected as a duplicate nonce.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` decides whether to skip the blockifier `__validate__` call:

```rust
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

The sole guard is `account_tx_in_pool_or_recent_block(sender_address)`, which returns `true` whenever *any* transaction from that address is in the pool or a recent block — not specifically the deploy-account transaction that justifies the skip. [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false`, so `StatefulValidator::perform_validations` returns immediately after the pre-validation stage without ever calling `__validate__`: [3](#0-2) [4](#0-3) 

The stateless validator never checks signature correctness (only length), so no other layer catches an invalid signature: [5](#0-4) 

**Attack path:**

1. Victim submits `deploy_account(address=A, nonce=0)`. The mempool now contains a transaction from address `A`, so `account_tx_in_pool_or_recent_block(A)` returns `true`.
2. Attacker observes the pending deploy_account and submits `invoke(sender=A, nonce=1, calldata=attacker_calldata, signature=garbage)` before the victim's own invoke.
3. Gateway stateless validation passes (signature length is within bounds).
4. `validate_nonce` passes: nonce 1 ≥ account_nonce 0 and within `max_allowed_nonce_gap`.
5. `validate_by_mempool` passes: no duplicate, nonce not too old.
6. `skip_stateful_validations` returns `true` because `A` is in the pool.
7. `run_validate_entry_point` skips `__validate__`; the attacker's unsigned invoke is admitted to the mempool.
8. Victim's legitimate `invoke(sender=A, nonce=1)` is rejected by the mempool as `DuplicateNonce`. [6](#0-5) 

The contrast with the `PyValidator` path is instructive: that path requires the caller to supply the specific `deploy_account_tx_hash` and checks `deploy_account_tx_hash.is_some()`, binding the skip to a concrete deploy-account transaction: [7](#0-6) 

The gateway path has no equivalent binding.

---

### Impact Explanation

The gateway permanently admits an invoke transaction that carries an invalid (attacker-controlled) signature without any cryptographic verification. The attacker's transaction occupies nonce slot 1 for the victim's account. The victim's correctly-signed invoke is rejected as a duplicate nonce. The attacker can repeat this for every new deploy_account they observe in the mempool, persistently blocking the deploy_account + invoke UX flow for any targeted account.

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The mempool is public; deploy_account transactions are visible to any observer. The attacker needs only to monitor for deploy_account transactions and submit a competing invoke with nonce=1 before the victim. No privileged access, no special knowledge of the victim's keys, and no on-chain state is required. The attack is repeatable and cheap.

---

### Recommendation

Bind the skip to the specific deploy-account transaction hash, mirroring the `PyValidator` approach. The gateway should require the caller to supply the deploy-account transaction hash and verify that the hash matches a transaction in the pool for the same sender address before skipping validation:

```rust
// Require the deploy_account_tx_hash to be provided and match a
// pending deploy_account for the same sender address.
if let Some(deploy_hash) = deploy_account_tx_hash {
    let tx_in_pool = mempool_client
        .account_tx_in_pool_or_recent_block(sender_address)
        .await?;
    if tx_in_pool && deploy_hash_matches_pending(deploy_hash, sender_address) {
        return Ok(true); // skip validate
    }
}
```

Alternatively, require the deploy_account and invoke to be submitted atomically in a single request so the gateway can verify their relationship before admitting either.

---

### Proof of Concept

```
1. Victim calls gateway.add_tx(deploy_account(A, nonce=0, valid_sig))
   → deploy_account admitted; mempool.account_tx_in_pool_or_recent_block(A) == true

2. Attacker calls gateway.add_tx(invoke(sender=A, nonce=1, calldata=X, sig=0xdeadbeef))
   → stateless: passes (sig length OK)
   → validate_nonce: passes (1 >= 0, within gap)
   → validate_by_mempool: passes (no duplicate)
   → skip_stateful_validations: account_tx_in_pool_or_recent_block(A) == true → returns true
   → run_validate_entry_point: validate=false → __validate__ NOT called
   → attacker's invoke admitted to mempool

3. Victim calls gateway.add_tx(invoke(sender=A, nonce=1, calldata=Y, valid_sig))
   → validate_by_mempool: DuplicateNonce → REJECTED

Result: attacker's unsigned invoke occupies nonce=1 for address A;
        victim's legitimate invoke is permanently blocked until attacker's
        transaction is evicted (e.g., TTL expiry or execution failure).
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L31-54)
```rust
impl StatelessTransactionValidator {
    #[instrument(skip(self), level = Level::INFO)]
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

**File:** crates/native_blockifier/src/py_validator.rs (L109-118)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
