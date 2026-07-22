Looking at the external report's invariant — **a check is performed but the action is not tracked, allowing unauthorized replay** — the Sequencer analog is: a condition is checked to decide whether to skip signature verification, but the condition is too broad, allowing an attacker to inject an invalid-signature transaction that bypasses the `__validate__` entry point at the gateway admission layer.

Let me trace the exact code path.

---

### Title
`skip_stateful_validations` skips `__validate__` for deployed accounts with nonce=0 that have any pending transaction, admitting invalid-signature invoke transactions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry point (signature verification) for the deploy_account + invoke UX case, where the account does not yet exist on-chain. However, the condition `account_nonce == Nonce(Felt::ZERO)` is equally true for accounts that **are** deployed but have not yet had any transaction committed. Combined with `account_tx_in_pool_or_recent_block` returning `true` for **any** pending transaction (not specifically a deploy_account), an attacker can inject an invoke with an invalid signature into the mempool for any deployed account with nonce=0 that has a pending transaction.

---

### Finding Description

`skip_stateful_validations` at line 429 of `stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when all three conditions hold: [1](#0-0) 

```
1. tx is Invoke with nonce == 1
2. account_nonce == 0  (on-chain state)
3. account_tx_in_pool_or_recent_block(sender) == true
```

The function's own comment claims this is safe because the pool entry "means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is incorrect.

`account_tx_in_pool_or_recent_block` is implemented as: [2](#0-1) 

It returns `true` for **any** transaction from that address — including a valid invoke with nonce=0 submitted by the legitimate owner of a freshly deployed account. It does not distinguish between a deploy_account and an invoke.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

This causes `StatefulValidator::perform_validations` to return `Ok(())` without ever calling `__validate__`: [4](#0-3) 

The transaction is then admitted to the mempool with no signature check.

During actual block execution by the batcher, `validate_tx` is called with `execution_flags.validate = true` (the default for sequencing), so `__validate__` **is** invoked: [5](#0-4) 

The invalid signature causes `__validate__` to fail, the transaction reverts, and the victim account is charged fees for a transaction it never authorized.

---

### Impact Explanation

**High. Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can inject an invoke transaction bearing an invalid (or zero) signature into the mempool for any account that:
- Has nonce=0 in the last committed state (freshly deployed, no committed transactions yet), and
- Has any pending transaction in the mempool pool.

The invalid transaction is included in a block, fails during execution (signature check in `__validate__` fails), and the victim account pays fees for the reverted transaction. The attacker does not need to know the victim's private key.

---

### Likelihood Explanation

**Medium.** Freshly deployed accounts with nonce=0 and a pending invoke in the mempool are a common, predictable state (e.g., immediately after a deploy_account is committed and the owner submits their first invoke). The attacker only needs to observe the mempool for such accounts.

---

### Recommendation

Before returning `true` from `skip_stateful_validations`, verify that the account is **not yet deployed** by checking that its class hash is zero (i.e., the contract does not exist on-chain). This ensures the skip only applies to the intended UX case where the account cannot yet execute `__validate__` because it has not been deployed.

```rust
// Proposed additional guard inside skip_stateful_validations:
let class_hash = state.get_class_hash_at(account_address)?;
if class_hash != ClassHash::default() {
    return Ok(false); // Account is deployed; do not skip validation.
}
```

Alternatively, the mempool's `account_tx_in_pool_or_recent_block` check should be narrowed to only return `true` when a deploy_account transaction specifically is present for that address.

---

### Proof of Concept

1. Account `X` is deployed on-chain (class_hash ≠ 0, nonce = 0 in committed state).
2. The legitimate owner of `X` submits a valid invoke with nonce=0 → passes `validate_nonce` (0 ≤ 0 ≤ max_gap), passes `validate_by_mempool`, admitted to mempool. `account_tx_in_pool_or_recent_block(X)` now returns `true`.
3. Attacker submits an invoke from `X` with nonce=1 and an **invalid/arbitrary signature**.
4. Gateway stateful validation:
   - `account_nonce = 0` (from `get_nonce_from_state`) ✓
   - `validate_nonce`: `0 ≤ 1 ≤ max_gap` ✓
   - `validate_by_mempool`: nonce gap accepted ✓
   - `skip_stateful_validations`: nonce==1 ✓, account_nonce==0 ✓, `account_tx_in_pool_or_recent_block(X)` == `true` ✓ → returns `true`
   - `run_validate_entry_point` sets `validate=false` → `__validate__` **skipped** → transaction admitted.
5. Batcher executes the block:
   - Owner's invoke (nonce=0): `__validate__` called, valid signature, succeeds, nonce advances to 1.
   - Attacker's invoke (nonce=1): `__validate__` called with `validate=true`, invalid signature → `PanicInValidate` / `ValidateCairo0Error` → transaction **reverts**.
6. Account `X` is charged fees for the reverted transaction it never authorized. [6](#0-5) [2](#0-1) [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L992-1001)
```rust
impl ValidatableTransaction for AccountTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut GasCounter,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
