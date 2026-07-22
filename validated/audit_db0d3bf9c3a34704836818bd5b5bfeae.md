### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` Signature Check for Invoke Transactions from Already-Deployed Accounts with Pending Nonce-0 Transactions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator skips the `__validate__` entry point (which performs signature verification) for any invoke transaction with nonce 1 when the account's on-chain nonce is 0 and `account_tx_in_pool_or_recent_block` returns `true`. The function was designed for the deploy-account + invoke UX case, but the mempool check it relies on is not specific to deploy-account transactions. An attacker can exploit this to submit an invoke transaction with an invalid signature for any already-deployed account that has a pending nonce-0 transaction in the mempool, bypassing signature verification and gaining admission to the mempool.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` implements the following logic: [1](#0-0) 

When the conditions `tx.nonce() == Nonce(Felt::ONE)` and `account_nonce == Nonce(Felt::ZERO)` are met, the function queries the mempool via `account_tx_in_pool_or_recent_block`. If that returns `true`, the function returns `true` (skip validation). This result is then used in `run_validate_entry_point`: [2](#0-1) 

When `skip_validate = true`, `execution_flags.validate` is set to `false`. Inside `AccountTransaction::validate_tx`, this causes an immediate early return without calling the `__validate__` entry point: [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check in the mempool is: [4](#0-3) 

It returns `true` if the account has **any** transaction in the pool (`tx_pool.contains_account`) or in the committed/staged state (`state.contains_account`): [5](#0-4) 

The code comment in `skip_stateful_validations` states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* However, this reasoning is flawed. If Account A is already deployed (nonce 0 in state) and has a legitimate invoke with nonce 0 in the mempool, `account_tx_in_pool_or_recent_block` returns `true`. An attacker can then submit an invoke with nonce 1 for Account A with an **invalid signature**. The gateway will skip `__validate__` because the condition is met, and the invalid transaction is admitted to the mempool without any signature verification.

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce validity and duplicate detection — it does not verify signatures: [6](#0-5) 

The `StatefulTransactionValidatorConfig` contains a `max_nonce_for_validation_skip` field, but the gateway's `skip_stateful_validations` function does **not** use it — the nonce-1 check is hardcoded: [7](#0-6) 

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

An attacker can submit an invoke transaction with an arbitrary (invalid) signature for any already-deployed account that has a pending nonce-0 transaction in the mempool. The transaction bypasses the `__validate__` entry point at the gateway and is admitted to the mempool. When the batcher later executes the transaction, `__validate__` is called with `validate = true`, the signature check fails, the transaction reverts, and the fee is charged from the victim account's balance. The attacker can cause the victim to lose funds (one transaction's fee) without possessing the victim's private key.

### Likelihood Explanation

**Medium.** The attacker must observe that a target account has a pending nonce-0 transaction in the mempool (publicly observable) and submit the malicious nonce-1 transaction before the nonce-0 transaction is committed to a block. The duplicate-nonce protection in the mempool limits the attacker to one such transaction per account per window.

### Recommendation

The `skip_stateful_validations` function should verify that the pending transaction for the account is specifically a **deploy-account** transaction, not just any transaction. The mempool's `account_tx_in_pool_or_recent_block` API does not distinguish transaction types. Either:

1. Add a new mempool API `has_deploy_account_in_pool(address)` that checks specifically for a pending deploy-account transaction, and use that instead of `account_tx_in_pool_or_recent_block`; or
2. Restrict the skip condition to only apply when the account has **no deployed class** (i.e., `get_class_hash_at(sender_address) == ClassHash::default()`), which is the true invariant for the deploy-account + invoke UX case.

### Proof of Concept

1. Account A is deployed: `class_hash != 0`, on-chain nonce = 0.
2. Account A's owner submits a legitimate invoke with nonce 0 to the gateway; it passes `__validate__` and is admitted to the mempool.
3. Attacker observes the pending nonce-0 transaction for Account A in the mempool.
4. Attacker constructs an invoke transaction: `sender_address = Account A`, `nonce = 1`, `signature = [0xdeadbeef]` (invalid).
5. Gateway stateful validation:
   - `account_nonce = 0` (from state), `tx_nonce = 1` → condition met.
   - `account_tx_in_pool_or_recent_block(Account A)` → `true` (nonce-0 tx is in pool).
   - `skip_stateful_validations` returns `true`.
   - `run_validate_entry_point` sets `validate = false`; `__validate__` is **not called**.
6. Invalid transaction is admitted to the mempool.
7. Batcher executes the transaction with `validate = true`; `__validate__` is called, fails (invalid signature), transaction reverts, fee is charged from Account A's balance. [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L992-1014)
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
        let remaining_validation_gas = &mut remaining_gas.limit_usage(
            tx_context.block_context.versioned_constants.os_constants.validate_max_sierra_gas,
        );
        let limit_steps_by_resources = self.execution_flags.charge_fee;
        let mut context = EntryPointExecutionContext::new_validate(
            tx_context,
            limit_steps_by_resources,
            SierraGasRevertTracker::new(GasAmount(*remaining_validation_gas)),
        );
        let tx_info = &context.tx_context.tx_info;
        if tx_info.is_v0() {
            return Ok(None);
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

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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
}
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L74-96)
```rust
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
    }
```
