### Title
Gateway Admits Invoke Transactions Without Signature Verification via `skip_stateful_validations` Bypass - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point (account signature verification) for any invoke transaction with nonce=1 when `account_tx_in_pool_or_recent_block` returns `true`. An attacker can trigger this condition by first submitting a valid `deploy_account` transaction to the mempool, then submitting an invoke transaction with nonce=1 carrying an **invalid signature**. The gateway admits the invalid invoke to the mempool without ever verifying the account's `__validate__` entry point.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` during gateway stateful admission: [1](#0-0) 

The bypass fires when three conditions hold simultaneously: [2](#0-1) 

1. The transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

When all three hold, the function returns `true` (skip validation). Back in `run_validate_entry_point`, this causes `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is entirely skipped: [4](#0-3) 

`perform_pre_validation_stage` (which **is** still called) only checks nonce, fee bounds, balance, and proof facts — it does **not** verify the account signature: [5](#0-4) 

The code comment in `skip_stateful_validations` asserts: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is correct for the honest UX case, but it does not prevent an attacker from deliberately pairing a valid `deploy_account` with an invoke carrying an **invalid signature**, because `account_tx_in_pool_or_recent_block` checks for **any** transaction from the account — not specifically a `deploy_account`: [6](#0-5) 

The mempool's `validate_tx` path (called before `skip_stateful_validations`) only checks for duplicate hashes and nonce ordering — it never inspects the signature: [7](#0-6) 

### Impact Explanation

The gateway/mempool admits an invoke transaction whose account signature has never been verified. This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

The admitted invalid invoke will fail during batcher execution when `__validate__` is called with `validate=true` (the batcher reconstructs `execution_flags` independently of the gateway). However, the transaction occupies mempool capacity and consumes sequencer resources before that failure is detected. At scale, an attacker can flood the mempool with invalid invoke transactions (each backed by a cheap valid `deploy_account`), evicting legitimate transactions and degrading throughput — the sequencer-native analog of the external report's "bots blocking withdrawals forever by consuming available liquidity before legitimate users can act."

### Likelihood Explanation

The attacker must submit one valid `deploy_account` transaction per invalid invoke to satisfy condition 3. This imposes a real cost but is not prohibitive: `deploy_account` fees are bounded, and the attacker can reuse the same account address across multiple attack rounds (the `committed` state retains the address for `committed_nonce_retention_block_count = 100` blocks by default). [8](#0-7) 

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a targeted query that confirms a **`deploy_account`** transaction specifically is present in the mempool for the sender address. Alternatively, expose a `deploy_account_in_pool(address)` API on the mempool that inspects transaction types, and use that in `skip_stateful_validations` instead of the generic account-existence check.

### Proof of Concept

1. Attacker picks a fresh salt and computes the deterministic `deploy_account` contract address `A`.
2. Attacker submits a **valid** `deploy_account` transaction for `A` (correct constructor calldata, valid signature). It is admitted to the mempool; `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker submits an `Invoke` transaction from `A` with `nonce = 1` and an **invalid/arbitrary signature** (e.g., all-zero signature bytes).
4. Gateway stateful path: `account_nonce = 0` (A not yet on-chain), `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(A) == true` → `skip_stateful_validations` returns `true`.
5. `run_validate_entry_point` sets `validate = false`; the blockifier skips `__validate__`; the invoke is admitted to the mempool **without signature verification**.
6. Batcher later picks up both transactions. `deploy_account` executes successfully. The invoke's `__validate__` is called with `validate = true` → fails (invalid signature) → transaction is rejected at execution time, but it occupied mempool capacity and sequencer CPU throughout.

Repeating steps 1–5 with fresh salts fills the mempool with signature-invalid invokes, evicting legitimate transactions.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-458)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

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

**File:** crates/apollo_deployments/resources/app_configs/mempool_config.json (L1-8)
```json
{
  "mempool_config.dynamic_config.transaction_ttl": 300,
  "mempool_config.static_config.capacity_in_bytes": 1073741824,
  "mempool_config.static_config.committed_nonce_retention_block_count": 100,
  "mempool_config.static_config.declare_delay": 20,
  "mempool_config.static_config.enable_fee_escalation": true,
  "mempool_config.static_config.fee_escalation_percentage": 10
}
```
