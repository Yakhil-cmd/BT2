### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` UX Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce=1` when the sender address has *any* transaction in the mempool and the on-chain account nonce is zero. An unprivileged attacker can exploit this by submitting an invoke transaction with an arbitrary/invalid signature for a victim address that has a pending `deploy_account` in the mempool, causing the invalid transaction to be admitted to the mempool without any signature check.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

The function returns `true` (skip) when all three conditions hold:
1. The transaction is an `Invoke` with `nonce == Nonce(Felt::ONE)`
2. The on-chain `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

The third condition is satisfied by checking the mempool's internal state: [2](#0-1) 

which checks `staged` or `committed` maps, or the tx pool: [3](#0-2) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, the `__validate__` entry point is then entirely skipped: [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate transaction hashes and stale nonces — it does not verify signatures: [6](#0-5) 

The `validate_nonce` check passes for `nonce=1` when `account_nonce=0` as long as `max_allowed_nonce_gap >= 1` (the default): [7](#0-6) 

**The broken invariant**: every invoke transaction admitted to the mempool must have its signature verified by the account's `__validate__` entry point. The `skip_stateful_validations` path breaks this invariant unconditionally for any address that has *any* transaction in the mempool (not just a deploy_account), and the check is keyed solely on the attacker-controlled `sender_address` field.

### Impact Explanation

An attacker can submit an invoke transaction with an invalid signature for any victim address A where:
- `account_nonce(A) == 0` (A is not yet deployed on-chain)
- A has a transaction in the mempool (e.g., a pending `deploy_account`)

The gateway admits the invalid invoke to the mempool without signature verification. If the attacker sets a higher tip than the victim's legitimate invoke, the attacker's invalid transaction displaces the victim's valid one via fee escalation. When the batcher later executes the block, the attacker's invoke fails `__validate__` and is rejected, but the victim's valid invoke has already been evicted from the mempool and must be resubmitted.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The attack requires:
1. A victim address with a pending `deploy_account` in the mempool (a common, observable event)
2. The attacker to submit their invalid invoke before the victim's invoke is processed

Both conditions are easily satisfied by any unprivileged network participant who monitors the mempool. No special privileges or keys are required.

### Recommendation

1. **Narrow the skip condition**: Instead of checking `account_tx_in_pool_or_recent_block` (which matches any transaction type), verify that the pending transaction is specifically a `deploy_account` transaction for the sender address.
2. **Verify the signature independently**: Even when skipping the on-chain `__validate__` entry point for UX reasons, perform a stateless signature check at the gateway level before admitting the transaction.
3. **Document the invariant**: Add an explicit assertion that `skip_validate = true` is only set when a valid `deploy_account` for the exact sender address is confirmed in the mempool.

### Proof of Concept

```
1. Victim submits RpcDeployAccountTransaction for address A (nonce=0) to the gateway.
   → Gateway validates and adds it to the mempool.
   → mempool.account_tx_in_pool_or_recent_block(A) now returns true.

2. Attacker crafts RpcInvokeTransactionV3:
     sender_address = A
     nonce          = 1
     signature      = [0xdeadbeef, 0xdeadbeef]  // invalid
     tip            = victim_tip + 1             // higher tip for fee escalation

3. Attacker submits the crafted invoke to the gateway.

4. Gateway stateful validation:
   a. get_nonce_from_state(A) → Nonce(0)          // A not deployed
   b. validate_nonce: 0 <= 1 <= 0+gap → passes
   c. validate_by_mempool: nonce not too old → passes
   d. skip_stateful_validations:
        tx.nonce() == 1  ✓
        account_nonce == 0  ✓
        account_tx_in_pool_or_recent_block(A) == true  ✓
        → returns true (skip)
   e. run_validate_entry_point(skip_validate=true):
        execution_flags.validate = false
        StatefulValidator::perform_validations → returns Ok(()) immediately
        // __validate__ is NEVER called; signature is NEVER checked

5. Attacker's invalid invoke is admitted to the mempool.
   → If tip > victim's invoke tip, victim's valid invoke is displaced.

6. Batcher executes block:
   - deploy_account (nonce=0) executes successfully; A is deployed.
   - Attacker's invoke (nonce=1) is executed with validate=true;
     __validate__ fails (invalid signature); transaction is rejected.
   - Victim's valid invoke (nonce=1) is no longer in the mempool.

7. Victim must resubmit their invoke.
``` [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
