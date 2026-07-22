### Title
Gateway Admits Invoke Transactions with Invalid Signatures via Unconstrained `skip_stateful_validations` Check - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the Apollo Gateway's stateful transaction validator bypasses the `__validate__` entry-point (signature verification) for invoke transactions with nonce=1 when the account's on-chain nonce is 0 and `account_tx_in_pool_or_recent_block` returns `true`. The mempool check is too broad: it returns `true` for **any** transaction from the sender address in the pool, not specifically a `deploy_account`. An attacker who observes a victim's `deploy_account` transaction in the mempool can submit a competing invoke with nonce=1 carrying an invalid signature, have it admitted without signature verification, and — if they outbid the victim's fee — replace the victim's valid invoke with their invalid one. When the batcher executes the block, the victim's account is charged fees for a reverted transaction and their intended invoke is never executed.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
1. The transaction is an `Invoke`.
2. `tx.nonce() == 1`.
3. `account_nonce == 0` (account not yet on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [2](#0-1) 

The comment claims the mempool check is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This is incorrect: `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from that address — including one submitted by a third party — and does not distinguish a `deploy_account` from an `invoke`. [3](#0-2) 

**How the skip propagates to execution flags**

When `skip_validate = true`, `run_validate_entry_point` sets `validate = false`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate = false` the `__validate__` call is entirely skipped: [5](#0-4) 

**Fee-escalation replacement path**

Before `skip_stateful_validations` is evaluated, `validate_by_mempool` is called: [6](#0-5) 

The mempool's `validate_tx` checks for duplicate hashes and fee escalation but does **not** verify signatures: [7](#0-6) 

If the attacker's invoke carries a higher fee than the victim's, `validate_fee_escalation` permits the replacement. The attacker's transaction is then added to the mempool via `add_tx_inner`, evicting the victim's valid invoke.

### Impact Explanation

An attacker can:

1. Observe a victim's `deploy_account` transaction for address A in the mempool.
2. Craft an `invoke` with `nonce=1`, sender=A, **invalid signature**, and a fee higher than the victim's paired invoke.
3. Submit it to the gateway. The gateway reads `account_nonce=0`, `tx_nonce=1`, finds A in the mempool, sets `skip_validate=true`, and admits the transaction **without calling `__validate__`**.
4. The mempool replaces the victim's valid invoke with the attacker's invalid one.
5. The batcher executes the block: `deploy_account` deploys the account; the attacker's invoke runs `__validate__` → fails → reverts → fees are charged to the victim's newly deployed account.
6. The victim's intended invoke is never executed.

This matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing**.

### Likelihood Explanation

- The mempool is observable (P2P propagation, RPC `pending` block).
- The attack requires only submitting a single transaction with a slightly higher fee.
- No privileged access is needed.
- The window is the time between the victim's `deploy_account` entering the mempool and the block being sealed — typically several seconds to minutes.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction for the sender address is present in the mempool. Alternatively, require the caller to supply the `deploy_account` transaction hash (as the `PyValidator` path already does via `deploy_account_tx_hash`) and verify it matches a pending `deploy_account` in the pool before skipping `__validate__`. [8](#0-7) 

The `PyValidator` path is safer because it requires an explicit `deploy_account_tx_hash` supplied by the caller; the new Apollo Gateway path should adopt the same constraint.

### Proof of Concept

```
1. Alice broadcasts:
     deploy_account(address=A, nonce=0, sig=valid)   → mempool admits it
     invoke(address=A, nonce=1, sig=valid, fee=100)  → mempool admits it (skip_validate=true)

2. Attacker observes A in mempool, broadcasts:
     invoke(address=A, nonce=1, sig=INVALID, fee=101)

3. Gateway stateful path:
     get_nonce_from_state(A) → 0          (account not on-chain yet)
     validate_nonce: 0 ≤ 1 ≤ 200 → OK
     validate_by_mempool: no dup hash, fee escalation allowed (101 > 100) → OK
     skip_stateful_validations:
       tx.nonce()==1 && account_nonce==0 → true
       account_tx_in_pool_or_recent_block(A) → true (Alice's deploy_account is there)
       returns true  ← __validate__ SKIPPED
     run_validate_entry_point: validate=false → no __validate__ call → admitted

4. Mempool: attacker's invoke (fee=101) replaces Alice's invoke (fee=100).

5. Batcher executes block:
     deploy_account(A, nonce=0) → account deployed, nonce→1
     invoke(A, nonce=1, sig=INVALID) → __validate__ called → FAILS → revert
     Fee charged to A for the reverted transaction.
     Alice's valid invoke is gone.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
