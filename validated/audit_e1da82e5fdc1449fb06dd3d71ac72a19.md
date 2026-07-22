Looking at the `skip_stateful_validations` logic, the `account_tx_in_pool_or_recent_block` check, and the `perform_pre_validation_stage` flow when `skip_validate=true`, I've identified a concrete exploitable invariant break.

---

### Title
Signature Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Injection for Pre-Funded Undeployed Accounts — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce=1` when `account_tx_in_pool_or_recent_block` returns `true`. That helper returns `true` if the account has **any** transaction in the pool — not specifically a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool can inject an invoke with `nonce=1`, arbitrary calldata, and an arbitrary signature for the same address. The gateway accepts it (balance check passes because Starknet accounts are pre-funded before deployment), the transaction enters the mempool, and the batcher later executes it — charging the victim fees for a transaction they never authorized.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
1. The incoming tx is an `Invoke` with `nonce == 1`
2. The on-chain `account_nonce == 0`
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

**The overly broad pool check:** [2](#0-1) 

`tx_pool.contains_account` returns `true` if the account has **any** transaction in the pool. The comment in `skip_stateful_validations` claims this implies a `deploy_account` is present, but it does not — any pooled transaction for that address suffices.

**What `skip_validate=true` actually skips:** [3](#0-2) 

`execution_flags.validate = !skip_validate`, so `validate=false`. Inside `StatefulValidator::perform_validations`: [4](#0-3) 

`perform_pre_validation_stage` still runs (nonce, fee-bounds, balance checks), but the `__validate__` entry-point call is entirely skipped.

**Pre-validation still passes for the attacker's tx:** [5](#0-4) 

- `handle_nonce` with `strict_nonce_check=false`: `0 ≤ 1` → passes, nonce incremented in ephemeral state.
- `check_fee_bounds`: passes if attacker supplies non-zero resource bounds (required by stateless validator).
- `verify_can_pay_committed_bounds`: passes because Starknet accounts are **pre-funded before deployment** (standard flow: compute address → send STRK → submit `deploy_account`).

**Gateway nonce check also passes:** [6](#0-5) 

With `max_allowed_nonce_gap=200` (production default), `0 ≤ 1 ≤ 200` → accepted. [7](#0-6) 

**Mempool `validate_tx` also passes:** [8](#0-7) 

`tx_nonce(1) >= account_nonce(0)` → no `NonceTooOld`. No existing nonce=1 tx → no `DuplicateNonce`.

---

### Impact Explanation

The gateway admits an invoke transaction whose signature has never been verified. The batcher later executes it: after the `deploy_account` (nonce=0) runs, the attacker's invoke (nonce=1) is executed with `strict_nonce_check=true` (nonce matches), `__validate__` is called, it fails (wrong signature), the transaction reverts, and **the victim's account is charged fees for a transaction they never authorized**. Additionally, the attacker occupies the victim's nonce=1 slot, forcing the victim to use fee escalation or wait for the failed tx to clear before their own invoke can proceed.

Matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

The standard Starknet account-deployment UX requires pre-funding the address before submitting `deploy_account`, so the balance precondition is met in virtually every real deployment. The attacker only needs to watch the public mempool for `deploy_account` transactions and race to submit an invoke with `nonce=1` before the victim does. No private key knowledge is required.

---

### Recommendation

1. **Narrow the pool check**: instead of `tx_pool.contains_account`, verify that the pooled transaction for the address is specifically a `deploy_account` (check the transaction type stored in the pool).
2. **Or remove the skip entirely**: require users to submit `deploy_account` and the first invoke in separate rounds; the UX benefit does not justify the security trade-off.
3. **Or validate the signature off-chain**: run `__validate__` against the class hash declared in the pending `deploy_account` rather than skipping it.

---

### Proof of Concept

```
1. Victim generates keypair, derives address X.
2. Victim sends STRK to address X (pre-fund, standard flow).
3. Victim submits deploy_account(class_hash=C, salt=S, nonce=0, sig=valid).
   → deploy_account enters mempool; tx_pool.contains_account(X) = true.

4. Attacker observes deploy_account in mempool.
5. Attacker submits invoke(sender=X, nonce=1, calldata=[anything],
                           signature=[0x0, 0x0],   ← arbitrary
                           resource_bounds=[non-zero]).

6. Gateway stateless validator: resource_bounds non-zero → OK.
7. Gateway stateful validator:
   a. validate_nonce: 0 ≤ 1 ≤ 200 → OK.
   b. validate_by_mempool: nonce 1 ≥ 0, no dup nonce → OK.
   c. skip_stateful_validations:
        nonce==1 ✓, account_nonce==0 ✓,
        account_tx_in_pool_or_recent_block(X)==true ✓
        → skip_validate = true.
   d. run_validate_entry_point(skip_validate=true):
        perform_pre_validation_stage:
          handle_nonce: 0≤1 → OK (ephemeral nonce→1).
          check_fee_bounds: non-zero bounds → OK.
          verify_can_pay_committed_bounds: pre-funded balance → OK.
        execution_flags.validate=false → return Ok().
   → Gateway accepts attacker's invoke.

8. Attacker's invoke added to mempool (nonce=1 slot occupied).
   Victim's own invoke(nonce=1) rejected with DuplicateNonce.

9. Batcher: executes deploy_account(nonce=0) → account deployed, nonce→1.
10. Batcher: executes attacker's invoke(nonce=1):
      __validate__ called → signature [0x0,0x0] fails → tx reverts.
      Fee charged to victim's account for validation gas.

Result: victim pays fees for an unauthorized transaction;
        victim's first invoke is blocked until attacker's tx clears.
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
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
