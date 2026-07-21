### Title
`skip_stateful_validations` Admits Invoke Transactions with Fake Signatures via Overly Broad `account_tx_in_pool_or_recent_block` Proxy Check — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function skips the blockifier `__validate__` entry-point call for an Invoke transaction with `nonce == 1` on an undeployed account whenever `account_tx_in_pool_or_recent_block` returns `true`. That helper returns `true` for **any** transaction in the pool for the sender address, not exclusively a `DeployAccount` transaction. An attacker who observes a victim's pending `DeployAccount` can immediately submit a malicious Invoke with `nonce = 1` and a fabricated signature; the gateway admits it without ever verifying the signature, and the transaction enters the mempool.

### Finding Description

`skip_stateful_validations` is the UX feature that lets a user broadcast `DeployAccount + Invoke(nonce=1)` atomically. Its guard is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

When `skip_validate` is `true`, `run_validate_entry_point` sets `validate: false`:

```rust
// lines 310-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate` is `false` the function returns immediately after `perform_pre_validation_stage`, never reaching the `__validate__` call:

```rust
// blockifier/src/blockifier/stateful_validator.rs  lines 78-81
tx.perform_pre_validation_stage(self.state(), &tx_context)?;
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

`perform_pre_validation_stage` checks nonce, fee bounds, and balance — but **not the cryptographic signature**. The signature is only verified inside `__validate__`.

The proxy check itself is:

```rust
// mempool/src/mempool.rs  lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

This returns `true` for **any** transaction type in the pool. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." The second branch of that disjunction is circular: a future-nonce Invoke that itself skipped validation is already in the pool, so the check trivially passes for the next malicious Invoke — even after the original `DeployAccount` has been evicted by TTL or fee-escalation replacement.

**Attack path:**

1. Victim broadcasts `DeployAccount` for address `A` (legitimate; passes full execution in the gateway).
2. Attacker submits `Invoke{sender: A, nonce: 1, calldata: [malicious], signature: [garbage]}`.
   - `validate_nonce`: `0 ≤ 1 ≤ 0 + max_gap` → passes.
   - `validate_by_mempool`: no duplicate hash, nonce valid → passes.
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true` (DeployAccount is in pool) → returns `true`.
   - `run_validate_entry_point`: `validate=false` → `__validate__` **never called**.
   - Malicious Invoke is admitted to the mempool with an unverified signature.
3. Attacker re-submits with a higher fee to replace the victim's legitimate `Invoke(nonce=1)` via fee escalation.
4. Batcher executes: `DeployAccount` succeeds → attacker's Invoke runs `__validate__` (now mandatory in the batcher), fails on the invalid signature, is reverted, but **nonce is consumed** (nonce incremented in `perform_pre_validation_stage` before revert).
5. Victim's legitimate Invoke is gone from the mempool; victim must resubmit with `nonce = 2`.

**Self-referential loop (analog to H-02's "startingBalance recorded after withdrawal"):** Once the malicious Invoke with `nonce=1` is in the pool, the `DeployAccount` can be evicted (TTL, replacement). `account_tx_in_pool_or_recent_block` still returns `true` because the malicious Invoke itself is in the pool. A second malicious Invoke (higher fee, different calldata) can now replace the first — again skipping `__validate__` — because the baseline check is satisfied by the very transaction that bypassed it.

### Impact Explanation

Matches **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.** Any account whose `DeployAccount` is visible in the mempool can have its first Invoke slot (nonce=1) hijacked by an attacker with no knowledge of the account's private key. The malicious transaction fails at execution time, but it consumes the nonce and evicts the legitimate transaction, forcing the victim to resubmit with an incremented nonce. At scale this is a targeted DoS on every new account deployment.

### Likelihood Explanation

The `DeployAccount` mempool is public. The attack requires only: (1) observing a pending `DeployAccount`, (2) constructing an Invoke with any calldata and any bytes as signature, (3) paying a small fee (lost on revert). No privileged access, no special contract, no cryptographic capability is required.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` proxy with a type-specific check. The mempool should expose a dedicated predicate such as `has_pending_deploy_account(address) -> bool` that inspects only `DeployAccount` entries in the pool. Alternatively, store the `deploy_account_tx_hash` alongside the pending Invoke in the mempool and verify it still exists before granting the skip.

### Proof of Concept

```
// State: account A not deployed (on-chain nonce = 0)
// Victim submits:
DeployAccount { contract_address: A, nonce: 0, signature: <valid> }
// → admitted, in mempool

// Attacker submits (no valid key for A):
Invoke { sender: A, nonce: 1, calldata: [0xdead], signature: [0xff, 0xff] }

// Gateway stateful path:
get_nonce_from_state(A)                          // → 0
validate_nonce(account=0, tx=1, gap=N)           // → Ok  (0 ≤ 1 ≤ N)
validate_by_mempool(...)                         // → Ok  (no dup, nonce valid)
skip_stateful_validations:
  nonce==1 && account_nonce==0                   // → true
  account_tx_in_pool_or_recent_block(A)          // → true  (DeployAccount is there)
  → returns true (SKIP __validate__)
run_validate_entry_point(validate=false)         // → Ok  (__validate__ never called)

// Malicious Invoke is now in the mempool with unverified signature.
// Attacker bumps fee → replaces victim's Invoke(nonce=1) via fee escalation.
// Batcher: DeployAccount executes → Invoke executes → __validate__ fails → reverted,
//          but nonce incremented to 2.  Victim's Invoke is gone.
``` [5](#0-4) [4](#0-3) [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
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
