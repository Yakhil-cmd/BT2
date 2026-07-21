### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Check for Deployed Accounts with Nonce=0 in Committed State — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is designed to skip the `__validate__` entry-point call only when a `deploy_account` transaction is pending for an account that has not yet been deployed. Its guard condition uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** account that has a transaction in the pool — not exclusively for accounts with a pending `deploy_account`. An attacker who controls an account that is already deployed but has nonce=0 in committed state (e.g., deployed via the `deploy` syscall from another contract) can first submit a legitimate Invoke with nonce=0 to seed the pool, then submit a second Invoke with nonce=1 carrying an invalid or absent signature. The second transaction passes all nonce and fee checks, `skip_stateful_validations` returns `true`, and `run_validate_entry_point` is called with `validate=false`, so `__validate__` is never executed. The unsigned transaction is admitted to the mempool.

### Finding Description

`extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`: [1](#0-0) 

`skip_stateful_validations` returns `true` (skip validation) when three conditions hold simultaneously: [2](#0-1) 

1. The transaction is an `Invoke` with `nonce == 1`.
2. The account's committed-state nonce is `0`.
3. `account_tx_in_pool_or_recent_block` returns `true`.

The comment at lines 440–443 asserts: *"it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This claim is incorrect.

`account_tx_in_pool_or_recent_block` is implemented as: [3](#0-2) 

It returns `true` whenever `tx_pool.contains_account(address)` is true — i.e., whenever **any** transaction from that address is in the pool, regardless of type. A deployed account with nonce=0 in committed state can have a legitimate Invoke(nonce=0) in the pool, which satisfies this check without any `deploy_account` being present.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: !skip_validate = false`: [4](#0-3) 

This causes `StatefulValidator::perform_validations` to return early without calling `__validate__`: [5](#0-4) 

The nonce gap check in `validate_nonce` allows nonce=1 when account_nonce=0 because the production `max_allowed_nonce_gap` is 200: [6](#0-5) [7](#0-6) 

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions.**

An Invoke transaction with nonce=1 carrying an invalid or absent signature is admitted to the mempool without signature verification. The corrupted admission decision is the `skip_validate=true` flag, which causes `__validate__` to be skipped entirely at the gateway stateful-validation stage. Any account deployed via the `deploy` syscall (a standard Starknet mechanism) starts with nonce=0 in committed state and is immediately exploitable.

### Likelihood Explanation

**High.** The precondition — a deployed account with nonce=0 in committed state — is routinely satisfied by accounts deployed via the `deploy` syscall from factory contracts, which is a common Starknet pattern. The attacker only needs to submit two sequential HTTP requests to the gateway: one legitimate Invoke(nonce=0) to seed the pool, and one malicious Invoke(nonce=1) with a forged or empty signature. No privileged access is required.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a type-specific check that verifies a `deploy_account` transaction is pending for the address. The mempool should expose a dedicated `has_pending_deploy_account(address)` query, or `skip_stateful_validations` should inspect the transaction type of the pooled transaction before deciding to skip validation.

### Proof of Concept

```
Precondition:
  Account A is deployed via `deploy` syscall from contract B.
  A's committed-state nonce = 0 (never executed a transaction).
  A implements __validate__ / __execute__ (it is an account contract).

Step 1 — Seed the pool:
  Submit Invoke(sender=A, nonce=0, signature=<valid>)
  → validate_nonce: account_nonce=0, tx_nonce=0, 0 <= 0 <= 200 ✓
  → run_validate_entry_point: validate=true, __validate__ called, passes ✓
  → Invoke(nonce=0) is now in the pool; tx_pool.contains_account(A) = true

Step 2 — Bypass signature check:
  Submit Invoke(sender=A, nonce=1, signature=<invalid or empty>)
  → validate_nonce: account_nonce=0, tx_nonce=1, 0 <= 1 <= 200 ✓
  → validate_by_mempool: nonce=1 >= committed nonce=0, passes ✓
  → skip_stateful_validations:
      tx.nonce() == 1 ✓
      account_nonce == 0 ✓
      account_tx_in_pool_or_recent_block(A) == true  ← nonce=0 invoke is in pool ✓
      returns true (skip validation)
  → run_validate_entry_point called with validate=false
  → __validate__ is NOT called
  → Invoke(nonce=1, invalid signature) admitted to mempool ✓
```

The malicious Invoke(nonce=1) with an invalid signature is accepted by the gateway and forwarded to the mempool, violating the admission invariant that every accepted transaction must have passed account signature verification.

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
