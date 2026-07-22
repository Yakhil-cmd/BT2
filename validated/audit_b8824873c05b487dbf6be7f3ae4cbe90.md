### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Check Based on Overly Broad Account-Presence Condition — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point (account signature verification) for an Invoke transaction with nonce=1 when the on-chain account nonce is 0. The guard condition used to justify this skip is `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction from the account — not specifically a `deploy_account` transaction. An attacker who controls an account with on-chain nonce=0 can first submit a valid nonce=0 Invoke transaction (which passes `__validate__`), then submit a nonce=1 Invoke transaction with an **invalid or forged signature**. The gateway skips `__validate__` for the nonce=1 transaction and admits it to the mempool without signature verification.

---

### Finding Description

In `skip_stateful_validations` (lines 429–461):

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // We verify that a deploy_account transaction exists for this account.
            // It is sufficient to check if the account exists in the mempool since
            // it means that either it has a deploy_account transaction or
            // transactions with future nonces that passed validations.
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`, which causes the blockifier's `StatefulValidator::validate` to skip calling the account's `__validate__` entry point entirely:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
...
blockifier_validator.validate(account_tx)
``` [2](#0-1) 

The code comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is broken. `account_tx_in_pool_or_recent_block` does not distinguish between a `deploy_account` transaction and an ordinary Invoke transaction. If the account already has code deployed (nonce=0 on-chain, but contract exists), an attacker can:

1. Submit a **valid** nonce=0 Invoke transaction → passes `__validate__` → enters mempool.
2. Submit a nonce=1 Invoke transaction with an **invalid signature**.
3. `skip_stateful_validations` fires: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block` returns `true` (the nonce=0 tx is in the pool).
4. `__validate__` is **skipped** for the nonce=1 transaction.
5. The nonce=1 transaction with an invalid/forged signature is **admitted to the mempool** without any signature check.

The analog to the external Absorber bug is exact: `is_operational()` checked `total_shares >= MINIMUM_SHARES` instead of the killed flag; here `account_tx_in_pool_or_recent_block` checks for *any* account activity instead of specifically a pending `deploy_account`.

The broken invariant: *"The `__validate__` entry point must be skipped only when a `deploy_account` transaction for the same account is pending in the mempool, because the account does not yet exist on-chain."*

---

### Impact Explanation

An Invoke transaction with an invalid or forged signature is admitted to the mempool without signature verification. This directly satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

At execution time the blockifier will call `__validate__` (the batcher creates its own `AccountTransaction` with `validate=true`), so the transaction will revert on execution. However, the gateway's pre-admission invariant — that every admitted transaction has passed its account's signature check — is violated. Consequences include:

- Mempool pollution with signature-invalid transactions that consume queue slots.
- Potential targeted displacement of legitimate nonce=1 transactions from the same account.
- For multisig or policy-enforcing accounts, a single compromised co-signer can inject transactions that bypass the multisig `__validate__` at the gateway layer, even though they revert on-chain.

---

### Likelihood Explanation

The preconditions are reachable by any unprivileged user:

- The attacker needs an account with on-chain nonce=0 that has contract code (e.g., deployed via `deploy` syscall, or any fresh account that has not yet sent a transaction).
- The attacker submits one valid nonce=0 Invoke transaction (trivially constructable if they control the account key).
- The attacker then submits the nonce=1 transaction with an arbitrary/invalid signature.

No privileged access, no admin key, and no special network position is required.

---

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the account. The mempool client interface should expose a dedicated `deploy_account_tx_in_pool_or_recent_block(address)` query, or the existing function should be renamed and its implementation constrained to only return `true` when the pending transaction is of type `DeployAccount`.

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())

// Use:
mempool_client.deploy_account_tx_in_pool_or_recent_block(tx.sender_address())
``` [3](#0-2) 

---

### Proof of Concept

**Setup:** Account `A` is deployed on-chain (has contract code), on-chain nonce = 0.

**Step 1 — Seed the mempool with a valid nonce=0 Invoke:**
```
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": A,
  "nonce": "0x0",
  "signature": [<valid_sig_for_nonce_0>],
  ...
}
```
Gateway calls `__validate__` → passes → tx enters mempool.

**Step 2 — Submit nonce=1 Invoke with invalid signature:**
```
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": A,
  "nonce": "0x1",
  "signature": ["0xdeadbeef", "0xdeadbeef"],   // invalid
  ...
}
```

Gateway path:
- `validate_nonce`: `0 <= 1 <= max_gap` → passes.
- `validate_by_mempool`: nonce/fee checks → passes (no signature check here).
- `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)` → `true` (nonce=0 tx is in pool) → **returns `true` (skip)**.
- `run_validate_entry_point`: called with `skip_validate=true` → `execution_flags.validate=false` → `__validate__` **not called**.

**Result:** The nonce=1 transaction with signature `["0xdeadbeef","0xdeadbeef"]` is accepted by the gateway and inserted into the mempool without any signature verification. [4](#0-3) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-341)
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
