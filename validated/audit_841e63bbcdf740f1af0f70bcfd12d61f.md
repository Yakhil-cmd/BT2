### Title
`skip_stateful_validations` Bypasses Signature Verification for Any Account with a Pending Invoke Transaction — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the `__validate__` entry point (which performs signature verification) only when an account's `deploy_account` transaction is pending. However, the predicate it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** account that has **any** transaction in the mempool, not exclusively a `deploy_account`. An attacker can therefore inject an invoke transaction with an invalid signature for any victim account that has a pending nonce-0 invoke, bypassing the gateway's signature check entirely.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions are simultaneously true:

1. The incoming transaction is an `Invoke`.
2. The transaction nonce is exactly `1`.
3. The on-chain account nonce is `0`.

When all three hold, the function calls `account_tx_in_pool_or_recent_block(sender_address)` and, if it returns `true`, returns `true` itself — causing `run_validate_entry_point` to set `validate: false`, which skips the `__validate__` entry-point call entirely. [1](#0-0) 

The code comment states the rationale:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is incorrect. `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

`tx_pool.contains_account` returns `true` for **any** transaction type in the pool — including a regular nonce-0 invoke submitted by the victim themselves. `state.contains_account` returns `true` for any address whose nonce has been staged or committed in recent blocks. [3](#0-2) 

When `skip_validate=true`, `run_validate_entry_point` constructs `ExecutionFlags { validate: false, … }` and calls `blockifier_validator.validate(account_tx)`. Inside `StatefulValidator::perform_validations`, the branch for `Invoke` checks `if !tx.execution_flags.validate { return Ok(()); }` — the `__validate__` call is never reached. [4](#0-3) [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate hashes and nonce ordering — it does not verify signatures. [6](#0-5) [7](#0-6) 

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid (unsigned) transaction before sequencing.**

An attacker can submit an invoke transaction with an arbitrary or empty signature for any victim account that has a pending nonce-0 transaction. The gateway admits it without calling `__validate__`. When the batcher later executes the block:

- The victim's nonce-0 transaction executes first (nonce advances to 1).
- The attacker's nonce-1 transaction enters `perform_pre_validation_stage` with `strict_nonce_check=true`; the nonce check passes and the nonce is incremented to 2.
- `__validate__` is then called (execution uses `new_for_sequencing` which sets `validate: true`) and fails on the invalid signature, reverting the transaction body.
- The victim's account is charged fees for the reverted transaction and their nonce is permanently advanced to 2, invalidating any legitimate nonce-1 transactions they had queued. [8](#0-7) [9](#0-8) 

### Likelihood Explanation

Any account that has ever submitted a transaction (nonce-0 invoke) is permanently vulnerable for the window between submission and block commitment. The attacker only needs to observe the public mempool to identify eligible targets, then submit a crafted nonce-1 invoke with a garbage signature. No privileged access, no special keys, and no coordination with the victim are required.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` predicate with a check that specifically verifies a `deploy_account` transaction is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool` that inspects the transaction type stored in the pool, rather than merely checking address presence. Until that is available, the skip should be disabled or the nonce-1 invoke should still be run through `__validate__` with a lenient nonce mode (the account contract does not exist yet, so the call will fail anyway if the signature is wrong, but it will correctly reject the transaction at the gateway rather than at execution time).

### Proof of Concept

```
// State: victim account V is deployed, on-chain nonce = 0.

// Step 1: Victim submits a legitimate nonce-0 invoke.
//   POST /gateway/add_transaction
//   { type: INVOKE, sender_address: V, nonce: 0, signature: <valid>, ... }
//   → accepted, enters mempool tx_pool for address V.

// Step 2: Attacker submits a nonce-1 invoke with a garbage signature.
//   POST /gateway/add_transaction
//   { type: INVOKE, sender_address: V, nonce: 1, signature: [0xdead, 0xbeef], ... }
//
//   Gateway flow:
//     account_nonce = get_nonce_from_state(V) = 0
//     validate_nonce: 0 <= 1 <= 0+max_gap  → OK
//     validate_by_mempool: nonce 1 >= 0     → OK (no signature check)
//     skip_stateful_validations:
//       tx.nonce() == 1 && account_nonce == 0  → true
//       account_tx_in_pool_or_recent_block(V)  → true  (victim's nonce-0 tx is in pool)
//       returns true
//     run_validate_entry_point(skip_validate=true):
//       ExecutionFlags { validate: false, ... }
//       __validate__ is NOT called
//   → attacker's transaction ADMITTED to mempool with invalid signature.

// Step 3: Batcher sequences both transactions.
//   Tx(nonce=0) executes → V's nonce becomes 1.
//   Tx(nonce=1, bad sig) executes:
//     perform_pre_validation_stage: nonce check passes, nonce incremented to 2.
//     __validate__ called → FAILS (bad signature) → tx reverts.
//     Fee charged from V's balance.
//
// Result: V's nonce is now 2, V paid fees for a transaction they never signed,
//         and any legitimate nonce-1 tx V had queued is now stale.
``` [10](#0-9) [2](#0-1) [11](#0-10)

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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L68-95)
```rust
    pub fn perform_validations(&mut self, tx: AccountTransaction) -> StatefulValidatorResult<()> {
        // Deploy account transaction should be fully executed, since the constructor must run
        // before `__validate_deploy__`. The execution already includes all necessary validations,
        // so they are skipped here.
        // Declare transaction should also be fully executed - otherwise, if we only go through
        // the validate phase, we would miss the check that the class was not declared before.
        match tx.tx {
            ApiTransaction::DeployAccount(_) | ApiTransaction::Declare(_) => self.execute(tx),
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```
