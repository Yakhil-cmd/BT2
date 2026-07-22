### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Verification for Invoke Transactions with Nonce=1 When Account Has Any Pending Transaction - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (the only place where the account's signature is verified) for any invoke transaction with nonce=1 when the sender address has *any* transaction in the mempool and the on-chain nonce is 0. An unprivileged attacker who observes a pending `deploy_account` transaction in the mempool can submit a competing invoke with nonce=1 and an arbitrary/invalid signature, which the gateway admits without ever verifying the signature. This is the direct analog of M-03: just as `cooldown()` was missing `whenNotPaused` and allowed users to game the system during an emergency state, `skip_stateful_validations` is missing a check that the account specifically has a `deploy_account` transaction pending, allowing attackers to bypass signature verification during the deploy+invoke UX window.

---

### Finding Description

**Root cause — `skip_stateful_validations` condition is too broad** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:
1. The transaction is an `Invoke` with `nonce == 1`
2. The account's on-chain nonce is `0` (not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

Condition 3 is satisfied by **any** transaction from that address in the mempool — not specifically a `deploy_account` transaction. The comment in the code says "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this is not enforced.

**How `skip_validate=true` suppresses signature verification**

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

This flag is passed into `StatefulValidator::perform_validations`, which returns early before calling `__validate__`: [3](#0-2) 

The `__validate__` entry point is the only place where the account contract verifies the transaction signature. `perform_pre_validation_stage` (which still runs) only checks nonce, fee bounds, and proof facts — it does not verify the signature: [4](#0-3) 

**`account_tx_in_pool_or_recent_block` checks for any account presence, not deploy_account specifically** [5](#0-4) 

`MempoolState::contains_account` returns `true` if the address appears in either `staged` or `committed` maps: [6](#0-5) 

`TransactionPool::contains_account` returns `true` if the address has any transaction in the pool: [7](#0-6) 

Neither check distinguishes a `deploy_account` transaction from any other transaction type.

**The mempool's `validate_incoming_tx` does not check signatures either** [8](#0-7) 

It only rejects duplicate tx hashes and nonces that are too old. An attacker's invoke with a different tx hash (different signature bytes) and nonce=1 passes all mempool checks.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions**

An attacker can submit an invoke transaction with an arbitrary/invalid signature from any address that has a pending `deploy_account` in the mempool. The gateway admits this transaction without ever calling `__validate__`. The invalid transaction enters the mempool and will be included in a block proposal. When the batcher executes it with `validate=true`, the `__validate__` entry point runs, the signature check fails, and the transaction reverts — but the nonce is consumed. The legitimate user's invoke with nonce=1 is now stale and is dropped from the mempool, breaking the deploy+invoke UX flow.

Additionally, the attacker can front-run the legitimate user's invoke: if the attacker's invalid tx is admitted first, the legitimate user's invoke with nonce=1 may be rejected by the mempool as a duplicate nonce (depending on mempool replacement policy), or it may be displaced when the attacker's tx consumes nonce=1 at execution time.

---

### Likelihood Explanation

**Likelihood: Low-Medium**

- The attack window is narrow: only invoke txs with nonce=1 from accounts with on-chain nonce=0 are affected.
- The attacker must observe a pending `deploy_account` transaction in the mempool (feasible via public RPC).
- The attacker must submit the invalid invoke before the legitimate user's invoke is admitted (race condition, but feasible since `deploy_account` and `invoke` are often submitted in the same batch).
- No privileged access is required; any unprivileged actor can submit transactions to the gateway.

---

### Recommendation

Replace the generic `account_tx_in_pool_or_recent_block` check with a specific check that verifies the account has a **`deploy_account` transaction** pending in the mempool. This requires exposing a new mempool API such as `has_pending_deploy_account(address: ContractAddress) -> bool` that inspects the transaction type, not just the address presence.

Alternatively, the gateway could perform a lightweight signature pre-check (e.g., verifying the signature length and format) even when skipping the full `__validate__` entry point, to prevent obviously invalid signatures from being admitted.

The `max_nonce_for_validation_skip` config parameter already limits the skip to nonce=1 by default: [9](#0-8) 

But this does not prevent the attack — it only bounds the nonce range.

---

### Proof of Concept

1. Alice submits `deploy_account` for address `A` (on-chain nonce=0). The tx is admitted to the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.

2. Attacker calls the gateway's `add_tx` endpoint with an invoke transaction:
   - `sender_address = A`
   - `nonce = 1`
   - `signature = [0x0, 0x0]` (arbitrary invalid bytes)

3. Gateway stateful validation path:
   - `get_nonce_from_state(A)` → `Nonce(0)` (not deployed yet)
   - `validate_state_preconditions`: nonce=1 ≥ account_nonce=0 → passes
   - `validate_by_mempool`: no duplicate hash, nonce not too old → passes
   - `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block(A)=true` → returns `true`

4. `run_validate_entry_point` is called with `skip_validate=true`:
   - `execution_flags.validate = false`
   - `StatefulValidator::perform_validations` hits the early return at line 79–81
   - `__validate__` is **never called**; signature is **never verified**

5. The invalid invoke tx is admitted to the mempool.

6. Alice's legitimate invoke with nonce=1 is either rejected (duplicate nonce) or displaced.

7. Batcher builds a block: `deploy_account` executes (nonce → 1), attacker's invoke executes with `validate=true` → `__validate__` fails → tx reverts (nonce → 2). Alice's invoke with nonce=1 is now stale and dropped. [1](#0-0) [10](#0-9) [11](#0-10)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L50-53)
```rust
impl<S: StateReader> StatefulValidatorTrait for StatefulValidator<S> {
    fn validate(&mut self, account_tx: AccountTransaction) -> StatefulValidatorResult<()> {
        self.perform_validations(account_tx)
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L702-711)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
            return Err(MempoolError::DuplicateTransaction { tx_hash: tx_reference.tx_hash });
        }
        self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
    }
```

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
