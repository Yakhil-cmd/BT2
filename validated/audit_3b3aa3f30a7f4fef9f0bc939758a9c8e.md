### Title
Signature Verification Bypass via `skip_stateful_validations` Race Condition Allows Unsigned Invoke Transactions into Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry point (the account's signature-verification step) for any invoke transaction with `nonce == 1` when `account_tx_in_pool_or_recent_block` returns `true` for the sender address. The check is intended to confirm that a `deploy_account` transaction exists for the address, but it actually confirms only that *any* transaction for that address is in the pool. An attacker who observes a victim's `deploy_account` in the mempool can immediately front-run the victim's first invoke by submitting an invoke with `nonce = 1` and an arbitrary (invalid) signature for the same address. The gateway skips `__validate__`, admits the unsigned transaction to the mempool, and the victim's legitimate invoke is subsequently rejected as a duplicate nonce.

---

### Finding Description

**Vulnerable code path** (`crates/apollo_gateway/src/stateful_transaction_validator.rs`, lines 429–461):

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // "It is sufficient to check if the account exists in the mempool since it means
            //  that either it has a deploy_account transaction or transactions with future
            //  nonces that passed validations."
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...;
        }
    }
    Ok(false)
}
```

When this function returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, causing `StatefulValidator::perform_validations` to return `Ok(())` immediately after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point:

```rust
// StatefulValidator::perform_validations
if !tx.execution_flags.validate {
    return Ok(());   // __validate__ is never called
}
```

**The broken invariant**: `account_tx_in_pool_or_recent_block` returns `true` if *any* transaction for the address is in the pool or a recent committed block — it does not distinguish between a `deploy_account` submitted by the legitimate owner and an arbitrary transaction submitted by a third party. The comment's reasoning ("it means that either it has a deploy_account transaction or transactions with future nonces that passed validations") is circular: a future-nonce invoke can itself have passed validation via this same skip path.

**Concrete attack**:

1. Victim submits `deploy_account` for address `A` (nonce = 0). This transaction passes normal validation and enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
2. Attacker observes the `deploy_account` in the mempool (public information).
3. Attacker crafts an invoke for address `A` with `nonce = 1` and a garbage/invalid signature.
4. Gateway evaluates the attacker's invoke:
   - `validate_state_preconditions`: nonce = 1, account_nonce = 0, gap ≤ 200 → **passes**.
   - `validate_by_mempool`: no duplicate tx_hash, nonce within range → **passes**.
   - `skip_stateful_validations`: nonce == 1, account_nonce == 0, `account_tx_in_pool_or_recent_block(A)` == true → **returns `true`**.
   - `run_validate_entry_point`: `validate = false` → `__validate__` is **never called**.
5. The attacker's unsigned invoke is admitted to the mempool.
6. Victim submits their legitimate invoke for address `A` with `nonce = 1` and a valid signature.
7. Mempool rejects it: `DuplicateNonce` (nonce 1 for address `A` is already occupied by the attacker's transaction).

The attacker can repeat this for every new `deploy_account` they observe, permanently blocking the deploy-account-plus-invoke UX path for any victim.

**Scope of the skip**: The default `max_nonce_for_validation_skip` is `Nonce(Felt::ONE)` (config schema value `"0x1"`), so the skip applies only to nonce = 1. However, the config is operator-adjustable; a higher value widens the attack window proportionally.

---

### Impact Explanation

- **Admission of invalid transactions**: An invoke transaction with an arbitrary (attacker-controlled) signature is accepted by the gateway and placed in the mempool without any signature check. This directly violates the gateway admission invariant.
- **Rejection of valid transactions**: The victim's correctly-signed invoke with the same nonce is rejected as a duplicate, preventing the intended deploy-account-plus-invoke flow from completing.
- **Sequencer resource waste**: The invalid transaction will fail during blockifier execution (when `__validate__` runs with `strict_nonce_check = true` and `validate = true` in `new_for_sequencing`), consuming batcher resources and producing a failed receipt.

Impact category: **High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

---

### Likelihood Explanation

- **Unprivileged**: Any network participant can submit transactions to the gateway.
- **Observable trigger**: `deploy_account` transactions are visible in the public mempool.
- **No special knowledge required**: The attacker only needs the victim's address (derivable from the `deploy_account` transaction itself) and any arbitrary bytes as a signature.
- **Repeatable**: The attacker can sustain the DoS by front-running every resubmission attempt.
- **Low cost**: Submitting a transaction is cheap; the attacker's invalid transaction will eventually be evicted after execution failure, but the attacker can immediately resubmit.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `deploy_account` transaction for the address is present in the pool. The `native_blockifier` path (`crates/native_blockifier/src/py_validator.rs`) already demonstrates the correct pattern: the caller explicitly passes the `deploy_account_tx_hash`, and the skip is conditioned on that hash being non-`None`:

```rust
let deploy_account_not_processed =
    deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
```

The gateway's `skip_stateful_validations` should adopt the same approach: require the submitter to provide the hash of the pending `deploy_account` transaction, verify that hash exists in the mempool as a `DeployAccount` transaction for the same address, and only then skip `__validate__`.

---

### Proof of Concept

```
// Precondition: victim has submitted deploy_account for address A.
// Mempool state: deploy_account(A, nonce=0) is in pool.
// account_tx_in_pool_or_recent_block(A) == true.

// Attacker submits:
RpcInvokeTransactionV3 {
    sender_address: A,          // victim's address
    nonce: 1,
    signature: [0xdead, 0xbeef], // garbage bytes
    resource_bounds: <valid>,
    calldata: [],
    ...
}

// Gateway evaluation:
// 1. validate_state_preconditions: nonce=1, account_nonce=0, gap<=200 → OK
// 2. validate_by_mempool: no dup hash, nonce in range → OK
// 3. skip_stateful_validations: nonce==1 && account_nonce==0 &&
//    account_tx_in_pool_or_recent_block(A)==true → returns true
// 4. run_validate_entry_point: validate=false → __validate__ NOT called → OK
// Result: attacker's unsigned invoke admitted to mempool.

// Victim now submits their legitimate invoke(A, nonce=1, valid_sig):
// validate_by_mempool → MempoolError::DuplicateNonce → REJECTED.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
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

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
```
