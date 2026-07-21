### Title
`skip_stateful_validations` Bypasses `__validate__` Signature Check for Nonce-1 Invoke Transactions — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's UX optimization for the `deploy_account + invoke` simultaneous submission pattern unconditionally skips the blockifier's `__validate__` entry-point call — which is the only place the account's signature is cryptographically verified — for any invoke transaction with `nonce == 1` whose sender address appears anywhere in the mempool. An attacker who controls a fresh account can exploit this to inject an invoke transaction carrying an arbitrary (invalid) signature into the mempool without any signature check.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip) when three conditions hold simultaneously:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet on-chain).
4. `account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_pre_validation_checks` propagates that value to `extract_state_nonce_and_run_validations`, which passes `skip_validate = true` into `run_validate_entry_point`. [2](#0-1) 

Inside `run_validate_entry_point`, `skip_validate = true` causes `validate: false` to be set in `ExecutionFlags`: [3](#0-2) 

The blockifier's `StatefulValidator::perform_validations` for invoke transactions checks `tx.execution_flags.validate` and returns `Ok(())` immediately when it is `false`, never calling `validate_tx` (the `__validate__` entry point): [4](#0-3) 

`validate_tx` is the sole place where the account contract's `__validate__` selector is dispatched, which is where ECDSA/Stark signature verification actually occurs: [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate hashes, nonce ordering, and fee escalation — `ValidationArgs` carries no signature field at all: [6](#0-5) 

The stateless validator only checks signature *length*, not cryptographic validity: [7](#0-6) 

**Trigger sequence (unprivileged):**

1. Attacker generates a fresh key pair and computes the corresponding Starknet account address.
2. Attacker submits a well-formed `deploy_account` transaction (nonce 0, valid signature) for that address. It passes all checks and enters the mempool. `account_tx_in_pool_or_recent_block` now returns `true` for this address.
3. Attacker submits an `invoke` transaction (nonce 1) for the same address, with a completely arbitrary/invalid signature.
4. Gateway reads `account_nonce = 0` from state (account not deployed yet), sees `tx_nonce = 1`, and calls `skip_stateful_validations`.
5. Condition 4 is satisfied because the deploy_account is in the mempool. `skip_stateful_validations` returns `true`.
6. `run_validate_entry_point` is called with `validate = false`; the `__validate__` entry point is never executed.
7. The invalid-signature invoke transaction is admitted to the mempool.

The comment in the code acknowledges the proxy nature of the check but incorrectly concludes it is "sufficient": [8](#0-7) 

The reasoning is flawed: the presence of a deploy_account in the mempool says nothing about the validity of the invoke's signature.

### Impact Explanation

The gateway's admission invariant — *every invoke transaction entering the mempool has had its account signature verified* — is broken. An attacker can inject invoke transactions with arbitrary signatures for any fresh account they control. The transactions will fail during blockifier execution (revert), but they bypass the gateway's signature gate entirely. This enables:

- Mempool pollution with signature-invalid transactions at the cost of only one valid `deploy_account` per account.
- Potential resource exhaustion: the batcher must execute and revert these transactions, consuming CPU and bouncer budget.

This matches the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The trigger is fully unprivileged and requires only two sequential HTTP calls to the gateway. The attacker controls the account address (by choosing their own key pair and salt), so no victim cooperation is needed. The `max_nonce_for_validation_skip` config field is set to `Nonce(Felt::ONE)` by default, meaning the window is exactly nonce=1 — one invalid invoke per fresh account. [9](#0-8) 

### Recommendation

The skip logic should verify the signature of the invoke transaction even when the account is not yet deployed, rather than skipping `__validate__` entirely. Two concrete options:

1. **Verify signature without executing `__validate__`**: Perform a standalone ECDSA/Stark signature check against the transaction hash before skipping the entry-point call. This preserves the UX benefit while enforcing cryptographic authenticity.

2. **Restrict the skip to deploy_account presence only**: Query the mempool for a `deploy_account` transaction specifically (not any transaction) for the sender address, and even then still run `__validate__` against the not-yet-deployed class hash using the class provided in the deploy_account's constructor data.

3. **Remove the skip entirely**: Require users to wait for the `deploy_account` to be included before submitting the invoke. This is the safest option but degrades UX.

### Proof of Concept

```
# Step 1: submit a valid deploy_account for a fresh account at address A
POST /add_transaction
{
  "type": "DEPLOY_ACCOUNT",
  "sender_address": "0xA",
  "nonce": "0x0",
  "signature": [<valid ECDSA sig>],
  ...
}
# → 200 OK, tx admitted to mempool

# Step 2: submit an invoke with nonce=1 and a garbage signature
POST /add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xA",
  "nonce": "0x1",
  "signature": ["0xdeadbeef", "0xdeadbeef"],   # invalid
  ...
}
# → 200 OK, tx admitted to mempool WITHOUT __validate__ being called
# The invalid-signature invoke is now in the mempool.
```

The gateway calls `skip_stateful_validations`, which queries `account_tx_in_pool_or_recent_block("0xA")` → `true` (deploy_account is present), returns `true`, and `run_validate_entry_point` is invoked with `validate = false`, skipping the `__validate__` entry point entirely. [10](#0-9)

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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-70)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}

impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
        }
    }
}
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-194)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
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
