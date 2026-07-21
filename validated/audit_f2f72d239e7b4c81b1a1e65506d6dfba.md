### Title
Invoke transactions with nonce=1 bypass `__validate__` signature check at gateway admission for undeployed accounts with pending `deploy_account` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the blockifier `__validate__` entry point — the sole signature-verification step — for any Invoke transaction with `nonce=1` targeting an account whose on-chain nonce is `0` and which has a `deploy_account` transaction in the mempool or a recent block. An attacker who observes such a pending `deploy_account` can submit an Invoke with an arbitrary/invalid signature for that account and have it admitted to the mempool without any signature check.

---

### Finding Description

The gateway's stateful validation for Invoke transactions has two distinct paths:

**Path A — Full validation** (normal case):
1. `perform_pre_validation_stage` — checks nonce, fee bounds, proof facts
2. `__validate__` entry point — the account contract's signature verification
3. `PostValidationReport::verify` — post-validation fee check

**Path B — Skipped validation** (UX shortcut):
1. `perform_pre_validation_stage` only — signature check is **never reached**

`skip_stateful_validations` selects Path B when all of the following hold:

```
tx is Invoke
tx.nonce() == Nonce(Felt::ONE)
account_nonce == Nonce(Felt::ZERO)
account_tx_in_pool_or_recent_block(sender) == true
``` [1](#0-0) 

The result is that `run_validate_entry_point` is called with `validate: false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate` is `false`, the function returns `Ok(())` immediately after `perform_pre_validation_stage`, never invoking `__validate__`: [3](#0-2) 

Because Starknet uses account abstraction, the sequencer has **no independent signature-verification step**; the account contract's `__validate__` function is the only place signatures are checked. Skipping it means the gateway performs zero cryptographic authentication for these transactions.

The analog to the reported bug is direct:

| Numa Protocol | Sequencer |
|---|---|
| Deprecated market → bad debt position | Undeployed account + `deploy_account` in mempool |
| Regular liquidation path (with profit incentive) accessible | Path B (no `__validate__`) accessible |
| Bad debt liquidation path (no profit) bypassed | Full validation path (with signature check) bypassed |
| Liquidator profits at protocol expense | Attacker admits unsigned transactions to mempool |

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can submit Invoke transactions with completely invalid or forged signatures for any account that has a pending `deploy_account`. The gateway admits them to the mempool without any authentication. At batcher execution time, `new_for_sequencing` sets `validate: true`, so `__validate__` is called and the transaction reverts — but the admission bypass is already complete. [4](#0-3) 

Consequences:
- Mempool pollution: attacker can flood the mempool with unauthenticated Invoke transactions targeting any account currently being deployed.
- Block space waste: reverted transactions still occupy block capacity.
- Ordering interference: attacker's invalid nonce-1 transactions can displace or delay the legitimate owner's nonce-1 invoke.

---

### Likelihood Explanation

**Medium.** The trigger condition — an account with a pending `deploy_account` in the mempool — is a routine, observable event during every new account creation. The attacker only needs to monitor the public mempool for `deploy_account` transactions and respond with a crafted Invoke. No privileged access is required.

---

### Recommendation

The `skip_stateful_validations` shortcut was designed to improve UX for users who submit `deploy_account` + Invoke simultaneously. However, it should not skip signature verification entirely. Two options:

1. **Restrict the skip to the transaction submitter only**: verify that the Invoke's sender matches the `deploy_account` submitter already in the mempool, so only the legitimate account owner benefits from the skip.
2. **Perform stateless signature-format validation** (e.g., check that the signature field is non-empty and well-formed) even when skipping the full `__validate__` entry point, raising the cost of flooding.

The `validate_state_preconditions` path already enforces nonce and fee bounds regardless of the skip: [5](#0-4) 

Signature verification should be similarly unconditional.

---

### Proof of Concept

1. **Setup**: Account `X` (controlled by victim) submits a `deploy_account` transaction. It enters the mempool. On-chain nonce for `X` is `0`.

2. **Attacker observes**: Attacker sees `X`'s `deploy_account` in the mempool. `account_tx_in_pool_or_recent_block(X)` will return `true`.

3. **Attacker submits**: Attacker crafts an Invoke transaction with `sender=X`, `nonce=1`, and a garbage/invalid signature (e.g., all-zero bytes).

4. **Gateway evaluation** (`extract_state_nonce_and_run_validations`):
   - `account_nonce = 0` ✓
   - `validate_state_preconditions`: nonce gap `[0,1]` is within `max_allowed_nonce_gap` ✓
   - `validate_by_mempool`: checks fee/nonce rules, not signature ✓
   - `skip_stateful_validations`: nonce=1, account_nonce=0, account in pool → returns `true` ✓
   - `run_validate_entry_point` called with `validate: false` → `__validate__` **never called** ✓

5. **Result**: The Invoke with invalid signature is admitted to the mempool. The gateway returns success to the attacker.

6. **At execution**: Batcher calls `new_for_sequencing` (validate=true) → `__validate__` runs → signature fails → transaction reverts. But the invalid transaction was already sequenced into a block, consuming block resources. [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-313)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
