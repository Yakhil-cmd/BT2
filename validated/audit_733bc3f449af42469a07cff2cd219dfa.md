### Title
Gateway Admits Invoke Transactions with Invalid Signatures via Overly Broad Validation-Skip Logic — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the blockifier `__validate__` entry-point (i.e., account signature verification) for any invoke transaction with `nonce == 1` when the on-chain account nonce is `0` AND `account_tx_in_pool_or_recent_block` returns `true`. The check is intended to support the deploy-account + invoke UX flow, but `account_tx_in_pool_or_recent_block` returns `true` for **any** account that has **any** transaction in the mempool — not only accounts with a pending `deploy_account`. This allows an attacker to submit an invoke transaction with a completely invalid signature for any already-deployed account (on-chain nonce = 0, any pending tx in the pool) and have it admitted to the mempool without signature verification.

### Finding Description

In `skip_stateful_validations`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

When this returns `true`, `skip_validate = true` is propagated to `run_validate_entry_point`, which sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The `account_tx_in_pool_or_recent_block` function returns `true` if the account has **any** transaction in the pool or has appeared in a recent committed block:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

The code comment claims this is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." The second case is the flaw: an already-deployed account (nonce 0 on-chain) with a valid nonce-0 invoke in the mempool satisfies the condition, yet its `__validate__` entry point is fully functional and must be run to verify signatures on nonce-1 transactions.

The `max_nonce_for_validation_skip` config (default `Nonce(Felt::ONE)`) limits the skip to nonce-1 transactions only, but does not prevent the attack. [4](#0-3) 

### Impact Explanation

An attacker can submit an `InvokeV3` transaction with `nonce = 1`, an arbitrary (invalid) signature, and any calldata, targeting any account that:
1. Has on-chain nonce `0` (never committed a transaction), and
2. Has any transaction currently sitting in the mempool.

The gateway admits the transaction without running `__validate__`, so the invalid signature is never checked at admission time. The transaction enters the mempool and is eventually handed to the batcher. During execution the blockifier **will** run `__validate__` (execution flags default to `validate: true`), the signature check fails, and the transaction is reverted — but it has already consumed mempool capacity and sequencer processing resources.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The preconditions are easy to satisfy in practice:
- Any account that has been deployed but has not yet had its first transaction committed (nonce 0 on-chain) and has a pending transaction in the mempool is vulnerable.
- The attacker needs no special privileges — only knowledge of the target address and the ability to submit RPC transactions.
- The `max_nonce_for_validation_skip` default of `Nonce(Felt::ONE)` means only nonce-1 transactions are affected, but this is a common nonce value for newly active accounts.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account** transaction is pending for the sender address. The mempool should expose a dedicated `has_pending_deploy_account(address)` query, or the pool should be queried for a transaction at nonce 0 of type `DeployAccount`. This preserves the UX feature while closing the bypass for already-deployed accounts.

Alternatively, restrict the skip to cases where the on-chain account code is absent (i.e., the account contract does not yet exist in state), which is the only situation where `__validate__` genuinely cannot be called.

### Proof of Concept

1. Deploy account `A` on-chain (nonce becomes 0 after deployment — or use any account that has nonce 0 and has never sent a committed transaction).
2. Submit a valid invoke transaction from `A` with nonce 0 to the gateway. It passes all checks and enters the mempool. Now `account_tx_in_pool_or_recent_block(A) == true`.
3. Craft an invoke transaction from `A` with nonce 1 and a completely random/invalid signature (e.g., `[Felt::ONE, Felt::TWO]`).
4. Submit it to the gateway. The gateway evaluates:
   - `tx.nonce() == Nonce(Felt::ONE)` → `true`
   - `account_nonce == Nonce(Felt::ZERO)` → `true`
   - `account_tx_in_pool_or_recent_block(A)` → `true` (from step 2)
   - Therefore `skip_validate = true`, `execution_flags.validate = false`
5. The gateway calls `StatefulValidator::validate` with `validate = false`, so `__validate__` is never executed. [5](#0-4) 
6. The transaction is forwarded to the mempool and accepted. The invalid-signature transaction now occupies a mempool slot.
7. When the batcher eventually executes it, `__validate__` runs, the signature check fails, and the transaction is reverted — but it has already been admitted and processed.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L310-312)
```rust
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-456)
```rust
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-93)
```rust
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
```
