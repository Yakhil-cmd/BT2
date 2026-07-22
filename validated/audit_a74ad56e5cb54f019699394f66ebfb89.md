### Title
Gateway Skips Account Signature Verification (`__validate__`) for Invoke Transactions with Nonce=1 from Undeployed Accounts - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (the account's signature verification) for any invoke transaction whose nonce equals 1 and whose sender's on-chain nonce is 0, provided the sender address appears in the mempool. An attacker who observes a victim's `deploy_account` transaction in the mempool can submit a crafted invoke with nonce=1 and an arbitrary/invalid signature from the victim's pre-funded, undeployed address. The gateway admits this transaction to the mempool without verifying the signature. When the batcher later executes it, `__validate__` runs, the signature fails, the transaction reverts, and the fee is charged from the victim's account. If the attacker front-runs the victim's own legitimate invoke (same nonce=1), the victim's transaction is displaced from the mempool, causing a denial-of-service and fee drain.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks`, which is itself called from `extract_state_nonce_and_run_validations` — the single entry point for all stateful gateway validation:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (resource bounds + nonce range)
       ├─ validate_by_mempool            (duplicate-nonce / mempool rules)
       └─ skip_stateful_validations      ← returns true when nonce==1 && account_nonce==0 && account in pool
  └─ run_validate_entry_point(skip_validate=true)
       └─ ExecutionFlags { validate: false, … }
       └─ StatefulValidator::perform_validations
            └─ if !tx.execution_flags.validate { return Ok(()); }  ← __validate__ never called
``` [1](#0-0) 

The condition that triggers the skip:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await …;
}
``` [2](#0-1) 

`account_tx_in_pool_or_recent_block` returns `true` if the address has **any** transaction in the pool or in a recently committed block:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

When `skip_validate = true`, `run_validate_entry_point` sets `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

Inside `StatefulValidator::perform_validations`, the `__validate__` call is guarded by this flag:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [5](#0-4) 

Critically, the `execution_flags` used at the gateway are **not** persisted into the `InternalRpcTransaction` stored in the mempool. When the batcher later converts the stored transaction to an executable form, it creates a fresh `AccountTransaction` with default flags (`validate: true`):

```rust
InternalRpcTransactionWithoutTxHash::Invoke(tx) => {
    Ok(AccountTransaction::Invoke(executable_transaction::InvokeTransaction {
        tx: tx.into(),
        tx_hash,
    }))
}
``` [6](#0-5) 

So `__validate__` **does** run during batcher execution. A transaction with an invalid signature will fail `__validate__`, revert, and still have its fee charged.

The `max_nonce_for_validation_skip` field exists in `StatefulTransactionValidatorConfig` but is **not used** in `skip_stateful_validations` — the skip is hardcoded to `Nonce(Felt::ONE)`: [7](#0-6) 

### Impact Explanation

An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can:

1. Submit an invoke transaction with nonce=1, an arbitrary/invalid signature, and sufficient resource bounds from the victim's pre-funded, undeployed address.
2. The gateway skips `__validate__` (signature check) because `tx.nonce()==1`, `account_nonce==0`, and the deploy_account is in the pool.
3. `perform_pre_validation_stage` still runs the balance check (`verify_can_pay_committed_bounds`), which passes because the address is pre-funded.
4. The transaction is admitted to the mempool. If the attacker front-runs the victim's own nonce=1 invoke, the victim's legitimate transaction is displaced (duplicate nonce rejection or fee-escalation replacement).
5. During batcher execution, `__validate__` runs with the invalid signature, the transaction reverts, and the fee is charged from the victim's account.

**Concrete broken invariant**: The gateway must not admit transactions whose account signature has not been verified. This invariant is violated for the specific nonce=1 / account_nonce=0 case.

**Matching impact category**: *High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

### Likelihood Explanation

- Starknet's deploy-account-then-invoke pattern is common and well-documented; pre-funding an address before deployment is standard practice.
- The deploy_account transaction is visible in the public mempool, giving the attacker the target address and the timing window.
- The attack requires no special privileges, only the ability to submit transactions to the gateway.
- The window is narrow (only while the deploy_account is pending), but the attack is deterministic and requires no brute force.

### Recommendation

The `skip_stateful_validations` function should not return `true` (skip signature verification) solely because the account address appears in the mempool. The UX goal (allowing the first post-deploy invoke to be queued) can be preserved while still verifying the signature, by one of the following approaches:

1. **Do not skip `__validate__` at the gateway.** Instead, allow the transaction to fail gateway validation and rely on the client to retry after the deploy_account is committed. This is the safest option.

2. **If the UX skip must be preserved**, ensure that the `__validate__` entry point is still called at the gateway using the *class* from the deploy_account transaction (which is already known from the mempool), so the signature is verified against the correct account contract before admission.

3. At minimum, add a note in the config that `max_nonce_for_validation_skip` is currently unused in `skip_stateful_validations` and wire it in, so operators can set it to `0` to disable the skip entirely.

### Proof of Concept

```
1. Victim pre-funds address A (sends STRK to A).
2. Victim submits deploy_account tx (nonce=0) for address A → admitted to mempool.
3. Attacker observes deploy_account in mempool, learns address A.
4. Attacker submits invoke tx: sender=A, nonce=1, signature=[0xdead, 0xbeef] (invalid).
   Gateway check:
     - tx.nonce() == 1  ✓
     - account_nonce(A) == 0  ✓
     - account_tx_in_pool_or_recent_block(A) == true  ✓  (deploy_account is in pool)
     → skip_validate = true → __validate__ NOT called → tx admitted to mempool.
5. Victim submits their own invoke tx: sender=A, nonce=1, valid signature.
   Gateway check: mempool already has nonce=1 for A → rejected (DuplicateNonce or fee-escalation).
6. Batcher executes block:
     - deploy_account(A, nonce=0) → A deployed, nonce becomes 1.
     - attacker's invoke(A, nonce=1) → __validate__ runs → invalid signature → REVERT.
       Fee charged from A's balance.
7. Victim's legitimate invoke was never executed; victim's balance is reduced by the fee.
``` [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

**File:** crates/apollo_transaction_converter/src/transaction_converter.rs (L272-277)
```rust
            InternalRpcTransactionWithoutTxHash::Invoke(tx) => {
                Ok(AccountTransaction::Invoke(executable_transaction::InvokeTransaction {
                    tx: tx.into(),
                    tx_hash,
                }))
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
