### Title
Gateway Admits Unsigned Invoke Transactions via `skip_stateful_validations` Front-Run — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` UX feature, designed to let users submit a `deploy_account + invoke` pair atomically, can be abused by any observer to inject an invoke transaction for a victim's undeployed account **without a valid signature**. The gateway skips the blockifier `__validate__` entry-point call entirely for such transactions, so the signature is never checked before the transaction enters the mempool.

### Finding Description

`skip_stateful_validations` returns `true` (skip the `__validate__` call) when all three conditions hold:

1. The transaction is an `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` sets `validate: !skip_validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is skipped entirely and `Ok(())` is returned: [3](#0-2) 

`validate_tx` also short-circuits on `validate == false`: [4](#0-3) 

**Attack path:**

1. Victim broadcasts `deploy_account` (nonce 0) + `invoke` (nonce 1) for a fresh account at address `A`.
2. Attacker observes the `deploy_account` in the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`. [5](#0-4) 

3. Attacker crafts an `Invoke V3` with `sender_address = A`, `nonce = 1`, arbitrary calldata, and an **invalid/empty signature**.
4. Gateway stateless checks pass (no signature check there). [6](#0-5) 

5. `extract_state_nonce_and_run_validations` reads on-chain nonce = 0, calls `run_pre_validation_checks`, which calls `skip_stateful_validations` → returns `true`. [7](#0-6) 

6. `run_validate_entry_point` is called with `skip_validate = true`; blockifier validation is skipped; the attacker's transaction is forwarded to the mempool with no signature verification.
7. The attacker's transaction occupies the `(A, nonce=1)` slot in the mempool. If submitted before the victim's invoke, the victim's legitimate transaction is rejected by the mempool as a duplicate nonce. [8](#0-7) 

### Impact Explanation

The gateway admits an invoke transaction carrying an **invalid signature** into the mempool. This directly violates the admission invariant: every transaction in the mempool must have passed account-level signature validation. The attacker can target any account that has a pending `deploy_account` transaction, which is publicly visible. The victim's legitimate `invoke` (nonce 1) is either rejected as a duplicate nonce or displaced by the attacker's higher-tip invalid transaction, causing a targeted DoS against the deploy-account + invoke UX flow.

Matches: **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

- The attack requires only passive mempool observation (no privileged access).
- The victim's `deploy_account` transaction is public.
- The attacker's transaction is structurally valid (correct nonce, correct sender address, valid resource bounds) and passes all stateless checks.
- The only cost to the attacker is the gas fee for a transaction that will be rejected during block execution.

### Recommendation

`skip_stateful_validations` must not skip the `__validate__` entry-point call entirely. Instead, it should only relax the **nonce strictness** (allow nonce=1 when account nonce=0), while still running `__validate__` to verify the signature. The `strict_nonce_check = false` flag already exists for exactly this purpose. The fix is to pass `skip_validate = false` and `strict_nonce_check = false` together, so the signature is always verified but a future nonce is tolerated:

```rust
// In run_validate_entry_point, always validate the signature:
let execution_flags = ExecutionFlags {
    only_query,
    charge_fee,
    validate: true,          // always run __validate__
    strict_nonce_check: false, // tolerate nonce=1 when account nonce=0
};
``` [9](#0-8) 

### Proof of Concept

```
1. Victim submits:
   - deploy_account(salt=S, class_hash=C, ...)  → contract_address = A, nonce=0
   - invoke(sender=A, nonce=1, calldata=[transfer ...], sig=<valid_sig>)

2. Attacker observes deploy_account in mempool:
   mempool.account_tx_in_pool_or_recent_block(A) == true

3. Attacker submits:
   invoke(sender=A, nonce=1, calldata=[anything], sig=[0x0])
   → on-chain nonce of A == 0, tx.nonce == 1
   → skip_stateful_validations returns true
   → __validate__ is NOT called
   → transaction enters mempool

4. Victim's invoke(nonce=1) is rejected:
   MempoolError::DuplicateNonce { address: A, nonce: 1 }

5. deploy_account executes in block N; invoke(nonce=1) slot is held by
   attacker's invalid tx, which fails __validate__ during execution.
   Victim's invoke is permanently lost from the mempool.
``` [10](#0-9) [11](#0-10)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
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
