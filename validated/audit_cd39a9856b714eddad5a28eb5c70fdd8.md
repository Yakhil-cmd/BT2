### Title
Gateway Skips Account `__validate__` Signature Verification for Invoke Transactions with Nonce=1 When Deploy-Account Is in Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (the account contract's signature-verification function) for any Invoke transaction with `nonce=1` when the sender's account has any transaction in the mempool or a recent block. An unprivileged attacker who first submits a valid `DeployAccount` transaction can then submit a second Invoke transaction with `nonce=1` carrying an **invalid signature**, and the gateway will admit it to the mempool without ever running the account's `__validate__` function.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` implements the deploy-account + invoke UX shortcut:

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
                ...;
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_pre_validation_checks` propagates `skip_validate = true` to `run_validate_entry_point`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

With `validate = false`, the blockifier's `perform_validations` path for Invoke transactions short-circuits before calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

`__validate__` is the **only** place where the account contract cryptographically verifies the transaction signature. Skipping it means the gateway admits the transaction to the mempool with no signature check.

The `StatefulTransactionValidatorConfig` carries a `max_nonce_for_validation_skip` field, but the gateway's `skip_stateful_validations` function **never reads it** — the nonce=1 threshold is hardcoded. The config field is only consumed by the legacy `PyValidator` path. [4](#0-3) 

The `account_tx_in_pool_or_recent_block` check is satisfied as soon as the attacker's own `DeployAccount` transaction lands in the mempool:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

---

### Impact Explanation

The gateway's invariant is that every transaction admitted to the mempool has passed account-level validation (including signature verification). For Invoke transactions with `nonce=1` submitted alongside a `DeployAccount`, this invariant is broken: a transaction carrying an **arbitrary, attacker-controlled signature** is admitted. The batcher will later attempt to execute it; `__validate__` will fail at execution time, the transaction will be rejected, and **no fee is charged to the attacker for the failed invoke** (Starknet charges no fee for `__validate__` failures). This matches the impact category:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The trigger is unprivileged: any user can submit a `DeployAccount` transaction. The only cost to the attacker is the fee for the `DeployAccount` itself. After that, one or more Invoke transactions with `nonce=1` and invalid signatures can be injected into the mempool at no additional cost, wasting mempool capacity and batcher execution resources.

---

### Recommendation

1. **Do not skip `__validate__` entirely.** The UX goal (accepting a nonce=1 invoke before the deploy-account is committed) can be achieved by relaxing only the **nonce check** in `perform_pre_validation_stage` (i.e., allowing `account_nonce < tx_nonce` without strict equality), while still running `__validate__` to verify the signature.

2. **Use the existing `max_nonce_for_validation_skip` config field** in the gateway path (it is already defined in `StatefulTransactionValidatorConfig`) so the skip threshold is operator-controlled and auditable, rather than hardcoded.

3. **Alternatively**, run a lightweight signature-only check (e.g., ECDSA/Stark curve verification for standard accounts) before admitting the transaction, independent of the full `__validate__` entry point.

---

### Proof of Concept

```
1. Attacker generates a fresh keypair → derives contract address X for a DeployAccount.
2. Attacker submits a valid DeployAccount for address X (valid signature, nonce=0).
   → Gateway validates normally; DeployAccount enters the mempool.
   → account_tx_in_pool_or_recent_block(X) now returns true.

3. Attacker submits an Invoke from address X with:
     nonce = 1
     signature = [0xdeadbeef, 0xdeadbeef]  ← completely invalid

4. Gateway stateful path:
   a. get_nonce_from_state(X) → Nonce(0)   (account not yet deployed)
   b. validate_nonce: nonce=1 is within [0, 0+200] → passes
   c. skip_stateful_validations:
        tx.nonce() == 1 ✓  &&  account_nonce == 0 ✓
        account_tx_in_pool_or_recent_block(X) → true ✓
        → returns skip_validate = true
   d. run_validate_entry_point: execution_flags.validate = false
        → __validate__ is NOT called
        → returns Ok(())

5. Invoke with invalid signature is added to the mempool.

6. Batcher later executes the Invoke:
   → __validate__ runs → signature check fails → transaction rejected.
   → No fee charged to attacker for the failed Invoke.
   → Attacker has only paid the DeployAccount fee.
``` [6](#0-5) [7](#0-6)

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
