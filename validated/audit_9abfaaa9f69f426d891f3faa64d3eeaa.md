### Title
`skip_stateful_validations` accepts any mempool transaction as a deploy-account surrogate, allowing an invoke with nonce=1 to bypass `__validate__` signature verification — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is designed to skip the blockifier `__validate__` entry point (i.e., signature verification) for an invoke transaction with nonce=1 when a `deploy_account` transaction for the same address is pending in the mempool. The UX intent is to let users broadcast `deploy_account + invoke` atomically. However, the predicate used — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction type from that address, not exclusively `deploy_account`. An attacker can therefore self-refer: submit a valid invoke(nonce=0) to seed the mempool, then submit a second invoke(nonce=1) carrying an **invalid signature**, which is admitted without ever calling `__validate__`.

---

### Finding Description

`skip_stateful_validations` at lines 429–461 of `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions hold simultaneously:

1. The incoming transaction is `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (from on-chain state).

When all three hold it calls `account_tx_in_pool_or_recent_block(sender_address)` and, if that returns `true`, returns `skip_validate = true`. [1](#0-0) 

The return value propagates directly into `run_validate_entry_point`, which sets `ExecutionFlags { validate: !skip_validate, … }`. [2](#0-1) 

When `validate = false` the blockifier's `StatefulValidator::perform_validations` returns `Ok(())` immediately for an invoke without ever calling `tx.validate_tx(…)` (the `__validate__` entry point that verifies the ECDSA signature). [3](#0-2) 

The mempool's `account_tx_in_pool_or_recent_block` is a pure presence check — it returns `true` if the address has **any** transaction in the pool or in a recently committed block, regardless of transaction type: [4](#0-3) 

The code comment inside `skip_stateful_validations` acknowledges the ambiguity ("either it has a deploy_account transaction **or** transactions with future nonces that passed validations") but the second branch is the exploitable one: an invoke(nonce=0) that passed its own `__validate__` is sufficient to satisfy the check, even though it provides no cryptographic guarantee about the validity of a subsequent invoke(nonce=1).

The production default `max_allowed_nonce_gap = 200` means nonce=1 is always within the accepted range when `account_nonce = 0`, and `max_nonce_for_validation_skip = 0x1` (Nonce ONE) is the exact nonce targeted. [5](#0-4) 

---

### Impact Explanation

An invoke transaction carrying an **invalid signature** is admitted through the gateway and inserted into the mempool. The batcher will later call `__validate__` during block execution and the transaction will revert, but the admission decision is already wrong. Concretely:

* **Scenario A (self-referral):** An attacker who controls account A (nonce=0 on-chain) submits invoke(nonce=0, valid\_sig) → mempool accepts it. Immediately after, the attacker submits invoke(nonce=1, **invalid\_sig**) → `skip_stateful_validations` returns `true` because account A is now in the pool → `__validate__` is skipped → the invalid transaction is admitted. The attacker can repeat this pattern to fill the mempool with signature-invalid transactions at the cost of one valid nonce-0 transaction per account.

* **Scenario B (third-party interference):** A legitimate user broadcasts `deploy_account` for address X. An attacker who does **not** control X observes the pending deploy_account in the mempool and immediately submits invoke(nonce=1, **invalid\_sig**) for X. `account_tx_in_pool_or_recent_block(X)` returns `true` (the deploy_account is there), so `__validate__` is skipped and the invalid invoke is admitted. This can front-run or displace the user's own legitimate invoke(nonce=1) via fee escalation, causing the user's post-deployment transaction to fail.

This matches the **High** impact tier: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

---

### Likelihood Explanation

The attack requires no privileged access. Any unprivileged user can:

* Observe the public mempool for pending `deploy_account` transactions (Scenario B), or
* Control any account with on-chain nonce=0 (Scenario A — trivially satisfied by deploying a fresh account).

The nonce window is narrow (nonce=1 only, by default), but the `max_nonce_for_validation_skip` config parameter is operator-adjustable and could be raised, widening the window.

---

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account`** transaction exists for the address. Either:

1. Add a dedicated mempool query `deploy_account_tx_in_pool(address) -> bool` that only returns `true` when the pending transaction for that address is of type `DeployAccount`.
2. Alternatively, tighten the skip condition to require that the account nonce is 0 **and** no contract code exists at the address yet (i.e., the account is genuinely undeployed), and that the mempool entry is a `deploy_account`.

The current comment in `skip_stateful_validations` — *"it means that either it has a deploy_account transaction or transactions with future nonces that passed validations"* — is the root of the confusion and should be corrected alongside the fix.

---

### Proof of Concept

```
// Prerequisites:
//   - Account A is deployed on-chain with nonce = 0.
//   - max_allowed_nonce_gap = 200 (production default).
//   - max_nonce_for_validation_skip = 0x1 (production default).

// Step 1: Submit a valid invoke with nonce=0 for account A.
//   - validate_nonce: account_nonce(0) <= tx_nonce(0) <= max_allowed(200) → OK
//   - skip_stateful_validations: tx_nonce != 1 → returns false
//   - run_validate_entry_point: validate=true → __validate__ called → valid sig → ACCEPTED
//   → invoke(nonce=0) is now in the mempool for account A.

// Step 2: Submit an invoke with nonce=1 and a GARBAGE/INVALID signature for account A.
//   - validate_nonce: account_nonce(0) <= tx_nonce(1) <= max_allowed(200) → OK
//   - validate_by_mempool: checks nonce gap / duplicate, not signature → OK
//   - skip_stateful_validations:
//       tx_nonce == 1 ✓
//       account_nonce == 0 ✓
//       account_tx_in_pool_or_recent_block(A) == true  ← invoke(nonce=0) is there ✓
//       → returns skip_validate = true
//   - run_validate_entry_point: validate = !true = false → __validate__ NOT called
//   → invoke(nonce=1, invalid_sig) ADMITTED to mempool without signature check.

// Outcome: mempool contains a signature-invalid transaction.
// Batcher will execute it, __validate__ will fail, transaction reverts.
// Block space is wasted; in Scenario B the user's legitimate invoke is displaced.
``` [6](#0-5) [2](#0-1) [4](#0-3) [5](#0-4)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
