### Title
Invoke Transactions with Nonce=1 from Undeployed Accounts Bypass `__validate__` Signature Check at Gateway Admission — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` UX path in the gateway unconditionally skips the `__validate__` entry-point execution for any Invoke V3 transaction whose nonce is exactly 1 and whose sender address has nonce 0 in state, provided the address appears in the mempool or a recent block. Because the account contract does not yet exist at that moment, the account's signature-verification logic is never run. An unprivileged attacker who observes a `deploy_account` transaction in the mempool can immediately submit a crafted Invoke with nonce=1 from the same address, carrying an arbitrary or invalid signature, and the gateway will admit it to the mempool without any signature check. This is the direct sequencer analog of the external report's "bridge burn/remint path bypasses TransferHook": a second admission path achieves the same economic effect (placing a transaction in the mempool) while skipping the policy check (signature verification) that the normal path enforces.

---

### Finding Description

**Normal path (nonce ≥ 2, or account already deployed):**

`extract_state_nonce_and_run_validations` calls `run_validate_entry_point` with `skip_validate = false`, which sets `execution_flags.validate = true` and runs `StatefulValidator::validate` → `AccountTransaction::validate_tx` → the account's `__validate__` entry point. Signature verification is enforced. [1](#0-0) 

**Skip path (nonce = 1, account nonce = 0, address in mempool):**

`skip_stateful_validations` returns `true` when all three conditions hold:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...;
}
``` [2](#0-1) 

`run_validate_entry_point` then sets `execution_flags.validate = !skip_validate = false`, so `StatefulValidator::perform_validations` reaches the early-return branch and never calls `validate_tx`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

`run_validate_entry_point` sets the flag:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

**What is still checked on the skip path:**

- `validate_state_preconditions` → nonce range check (nonce=1 is within `max_allowed_nonce_gap=200` of account nonce=0) and L2 gas price threshold.
- `validate_by_mempool` → duplicate-hash and fee-escalation checks.
- `perform_pre_validation_stage` inside `StatefulValidator` → nonce increment, fee bounds, balance check.

**What is NOT checked:** the account's `__validate__` entry point, which is the only place the account's own signature-verification logic runs. [5](#0-4) 

---

### Impact Explanation

**Mempool admission of a transaction with an invalid/arbitrary signature.**

Attack scenario:

1. Victim broadcasts `deploy_account` for address `X` (deterministic from class hash + salt + calldata). The transaction enters the mempool; `account_tx_in_pool_or_recent_block(X)` now returns `true`.
2. Attacker computes `X` from the observed `deploy_account` parameters and immediately submits `Invoke(sender=X, nonce=1, calldata=<arbitrary>, signature=<garbage>)` with a tip higher than the victim's planned invoke.
3. Gateway: `account_nonce(X) == 0`, `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(X) == true` → `skip_validate = true` → `__validate__` is never called → transaction is admitted to the mempool.
4. Victim submits their legitimate `Invoke(sender=X, nonce=1)`. `validate_by_mempool` sees a conflicting nonce=1 entry with a higher tip and rejects the victim's transaction with a fee-escalation error.
5. Batcher executes: `deploy_account` succeeds (account deployed). Attacker's invoke runs `__validate__` (now the account exists), signature check fails, transaction reverts. Fee is still charged to `X`.
6. Victim's legitimate invoke was never sequenced; victim's account loses gas to the failed attacker invoke.

This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."* [6](#0-5) 

---

### Likelihood Explanation

- The attack requires only passive mempool observation (public information in a distributed sequencer) and a single crafted transaction submission — no privileged access.
- The `deploy_account` address is fully deterministic and computable from the public transaction fields.
- The timing window is the interval between the `deploy_account` entering the mempool and the victim's invoke arriving. In the deploy_account + invoke UX flow (documented in integration tests), users are expected to submit both transactions nearly simultaneously, but network propagation differences create a race window.
- The production config sets `max_nonce_for_validation_skip = 0x1`, which limits the attack to nonce=1 only, but that is exactly the nonce used in the intended UX flow. [7](#0-6) [8](#0-7) 

---

### Recommendation

The root cause is that the skip path cannot run `__validate__` because the account contract does not yet exist. Two mitigations:

1. **Bind the skip to the exact deploy_account transaction hash.** Instead of checking only that *some* transaction from the address is in the mempool, require the caller to supply the deploy_account transaction hash and verify it matches the pending deploy_account for that address. This prevents an attacker from exploiting the skip for an address they did not deploy.

2. **Defer mempool admission of the invoke until the deploy_account is committed.** Accept the deploy_account + invoke pair as an atomic bundle; only admit the invoke to the mempool after the deploy_account has been executed and the account exists, at which point `__validate__` can be run normally.

The current check `account_tx_in_pool_or_recent_block` is too coarse: it returns `true` for *any* transaction from the address, not specifically a deploy_account, and it does not bind the skip to the specific deploy_account the invoke is paired with. [9](#0-8) 

---

### Proof of Concept

```
# Prerequisites:
# - Gateway running with default config (max_nonce_for_validation_skip = 0x1)
# - Attacker can observe the mempool

# Step 1: Victim submits deploy_account for address X
POST /gateway/add_transaction
{
  "type": "DEPLOY_ACCOUNT",
  "sender_address": "0x<X>",
  "nonce": "0x0",
  ...
}
# X is now in mempool; account_tx_in_pool_or_recent_block(X) == true

# Step 2: Attacker submits malicious invoke with nonce=1, arbitrary signature, high tip
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0x<X>",
  "nonce": "0x1",
  "calldata": ["0xdeadbeef"],   # arbitrary
  "signature": ["0x1", "0x2"],  # invalid — will NOT be checked
  "tip": 9999999,               # higher than victim's planned invoke
  ...
}
# Gateway: account_nonce(X)==0, tx.nonce==1, account_tx_in_pool_or_recent_block(X)==true
# → skip_validate=true → __validate__ skipped → ADMITTED

# Step 3: Victim submits legitimate invoke with nonce=1, lower tip
POST /gateway/add_transaction { "type": "INVOKE", "sender_address": "0x<X>", "nonce": "0x1", "tip": 100, ... }
# → validate_by_mempool sees conflicting nonce=1 with higher tip → REJECTED (fee escalation)

# Result: attacker's unsigned invoke is in the mempool; victim's signed invoke is rejected.
# Batcher executes deploy_account (success), then attacker's invoke (__validate__ fails, reverts,
# fee charged to X). Victim's invoke never executes.
``` [6](#0-5) [10](#0-9) [11](#0-10)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L426-461)
```rust
/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L18-18)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1",
```

**File:** crates/apollo_integration_tests/src/utils.rs (L713-726)
```rust
/// Generates a deploy account transaction followed by an invoke transaction from the same account.
/// The first invoke_tx can be inserted to the first block right after the deploy_tx due to
/// the skip_validate feature. This feature allows the gateway to accept this transaction although
/// the account does not exist yet.
pub fn create_deploy_account_tx_and_invoke_tx(
    tx_generator: &mut MultiAccountTransactionGenerator,
    account_id: AccountId,
) -> Vec<RpcTransaction> {
    let undeployed_account_tx_generator = tx_generator.account_with_id_mut(account_id);
    assert!(!undeployed_account_tx_generator.is_deployed());
    let deploy_tx = undeployed_account_tx_generator.generate_deploy_account();
    let invoke_tx = undeployed_account_tx_generator.generate_trivial_rpc_invoke_tx(1);
    vec![deploy_tx, invoke_tx]
}
```
