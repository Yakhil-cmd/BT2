### Title
`skip_stateful_validations` Bypasses `__validate__` for Invoke Transactions from Existing Accounts with Any Pending Transaction in the Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call for a nonce-1 invoke transaction when a `deploy_account` transaction is still pending (UX improvement for the deploy+invoke flow). However, the guard condition uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction from the sender in the pool or a recent block — not exclusively a `deploy_account` transaction. An attacker who controls an already-deployed account (nonce 0 in state) with a legitimate nonce-0 invoke already in the mempool can submit a nonce-1 invoke carrying an **invalid signature**, and the gateway will skip `__validate__` entirely, admitting the unauthenticated transaction to the mempool.

---

### Finding Description

`skip_stateful_validations` (lines 429–461) fires when three conditions are simultaneously true:

1. The incoming transaction is an `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0`.
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

The code comment claims condition 3 implies "either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is incorrect for **already-deployed** accounts. An account that was deployed in a prior block (class hash ≠ 0, nonce = 0 in state) can have a legitimate nonce-0 invoke sitting in the mempool. In that case `account_tx_in_pool_or_recent_block` returns `true`: [2](#0-1) 

The function checks `self.state.contains_account(account_address) || self.tx_pool.contains_account(account_address)` — no transaction-type filter whatsoever.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so the blockifier's `StatefulValidator` returns early without ever calling `__validate__`: [3](#0-2) [4](#0-3) 

The mempool's `validate_tx` path (called before `skip_stateful_validations`) only checks nonce ordering, duplicate hashes, and fee escalation — it contains no signature or `__validate__` check: [5](#0-4) [6](#0-5) 

The gateway's `validate_nonce` allows nonce-1 when account nonce is 0 (within `max_allowed_nonce_gap`): [7](#0-6) 

So the full gateway admission pipeline passes for a nonce-1 invoke with an invalid signature, and the transaction enters the mempool unauthenticated.

---

### Impact Explanation

**High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

An invoke transaction whose `__validate__` entry point would reject it (e.g., wrong ECDSA signature, wrong signer, replayed transaction from a different chain) is admitted to the mempool without any account-level authentication. The mempool's invariant — that every queued transaction has passed account validation — is broken. When the batcher later executes the transaction with `validate: true`, `__validate__` will run and the transaction will revert; however, the transaction has already consumed mempool capacity, forced the batcher to attempt execution, and polluted the pending transaction pool. At scale this enables targeted DoS against specific accounts and wastes sequencer resources.

---

### Likelihood Explanation

**Medium.** The preconditions are realistic and common:

- The sender account must be deployed (class hash ≠ 0) with nonce 0 in committed state — true for any account that was just deployed in a recent block.
- The sender must have a nonce-0 invoke already in the mempool — true for any account that submitted its first post-deployment transaction.

No privileged access is required. Any external user who observes the mempool (or races with a legitimate user) can exploit this.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific query that returns `true` only when a `deploy_account` transaction (or a committed deploy-account block entry) exists for the sender. Alternatively, add a transaction-type filter inside `skip_stateful_validations` itself:

```rust
// Only skip validation when the account has a pending deploy_account tx,
// not any arbitrary transaction.
return mempool_client
    .deploy_account_tx_in_pool_or_recent_block(tx.sender_address())
    .await
    ...
```

If a type-specific mempool query is not feasible, the fallback is to remove the `skip_stateful_validations` optimization entirely and require users to wait for the `deploy_account` to be committed before submitting the first invoke.

---

### Proof of Concept

1. Deploy account `A` in block N. Account `A` now has class hash ≠ 0, nonce = 0 in state.
2. Submit a legitimate nonce-0 invoke from `A` (valid signature). It passes `__validate__` and enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Craft a nonce-1 invoke from `A` with a **garbage/invalid signature** (e.g., `[0x0, 0x0]`).
4. Submit the nonce-1 invoke to the gateway.
   - `validate_nonce`: `0 ≤ 1 ≤ 0 + max_allowed_nonce_gap` → **passes**.
   - `validate_by_mempool` (`validate_tx`): nonce is fresh, no duplicate → **passes**.
   - `skip_stateful_validations`: nonce == 1, account_nonce == 0, `account_tx_in_pool_or_recent_block` == `true` → returns `true` (skip).
   - `run_validate_entry_point` with `skip_validate = true`: `validate` flag set to `false`, blockifier returns `Ok(())` without calling `__validate__`.
5. The nonce-1 invoke with invalid signature is forwarded to the mempool via `add_tx` and accepted.
6. The batcher later dequeues the transaction, runs `__validate__` (with `validate: true`), which fails, and the transaction is reverted — but it was already admitted and consumed sequencer resources. [8](#0-7) [2](#0-1) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L306-314)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
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
            }
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
