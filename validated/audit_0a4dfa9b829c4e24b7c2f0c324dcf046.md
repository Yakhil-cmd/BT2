### Title
Invoke Transaction with Nonce=1 Bypasses `__validate__` Signature Verification via `skip_stateful_validations` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point call (which performs signature verification) for any Invoke transaction with `nonce=1` whenever the sender's on-chain nonce is `0` and **any** transaction from that address exists in the mempool. An attacker who first places a valid transaction in the mempool for address A can then submit a second Invoke with `nonce=1` and a completely invalid signature; the gateway admits it to the mempool without ever verifying the signature.

### Finding Description

In `extract_state_nonce_and_run_validations`, the gateway:

1. Reads the on-chain nonce for the sender.
2. Calls `run_pre_validation_checks`, which calls `skip_stateful_validations`.
3. Passes the returned `skip_validate` flag to `run_validate_entry_point`. [1](#0-0) 

Inside `run_validate_entry_point`, when `skip_validate=true`, the execution flags are built with `validate: false`: [2](#0-1) 

This means `StatefulValidator::perform_validations` is called with `validate=false`, so the `__validate__` entry point — which is the account's signature-checking function — is **never executed**: [3](#0-2) 

The skip decision is made in `skip_stateful_validations`: [4](#0-3) 

The condition triggers when:
- The transaction is `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)`
- `account_nonce == Nonce(Felt::ZERO)` (on-chain)
- `account_tx_in_pool_or_recent_block(sender)` returns `true`

The last check is satisfied by **any** transaction from that address in the mempool — not exclusively a `deploy_account`: [5](#0-4) 

`contains_account` returns `true` if the address appears in either the staged/committed nonce map or the transaction pool: [6](#0-5) 

No other check in the pipeline verifies the signature. The stateless validator only checks signature **size**, not validity: [7](#0-6) 

`ValidationArgs` passed to the mempool contains no signature field: [8](#0-7) 

### Impact Explanation

An Invoke transaction carrying an invalid (attacker-forged) signature is admitted to the mempool and forwarded to the batcher. The batcher will later execute it with `validate=true`, causing the `__validate__` entry point to fail and the transaction to revert. This constitutes **mempool/gateway admission accepting an invalid transaction** — the gateway's core invariant (only admit transactions that would pass `__validate__`) is broken. Repeated exploitation wastes batcher execution resources and can be used for sustained DoS against the sequencer.

This matches the allowed impact: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

The attacker needs only two conditions:
1. The target address has on-chain nonce `0` (true for any freshly deployed or undeployed account).
2. Any transaction from that address is already in the mempool (the attacker can place one themselves with a valid nonce-0 transaction).

Both conditions are trivially achievable by the attacker themselves, making this reliably exploitable by any unprivileged user.

### Recommendation

1. **Restrict the skip to provably undeployed accounts**: check that the class hash at the sender address is zero (i.e., the account contract does not exist on-chain) before skipping `__validate__`. A nonce of `0` alone does not prove the account is undeployed.

2. **Restrict the mempool check to `deploy_account` transactions only**: instead of `account_tx_in_pool_or_recent_block` (which returns `true` for any transaction type), query specifically whether a `deploy_account` transaction for the address is pending.

3. **Alternatively, remove the skip entirely** and require users to submit the `deploy_account` first, waiting for it to be included before submitting the subsequent Invoke.

### Proof of Concept

```
// Step 1: Attacker submits a valid Invoke(nonce=0) for address A
//         (or a valid deploy_account for A).
//         This is admitted normally and lands in the mempool.
gateway.add_tx(valid_invoke_nonce_0_for_A);

// Step 2: Attacker submits an Invoke(nonce=1) with a FORGED signature for address A.
//         Gateway state: on-chain nonce(A) = 0, tx.nonce = 1.
//         skip_stateful_validations:
//           - tx is Invoke ✓
//           - tx.nonce() == 1 ✓
//           - account_nonce == 0 ✓
//           - account_tx_in_pool_or_recent_block(A) == true ✓  (step 1 tx is in pool)
//         => skip_validate = true
//         => run_validate_entry_point called with validate=false
//         => __validate__ is NEVER called
//         => forged-signature Invoke admitted to mempool.
gateway.add_tx(invoke_nonce_1_invalid_signature_for_A);  // succeeds, no error

// Step 3: Batcher later executes the forged Invoke with validate=true.
//         __validate__ is called, fails (bad signature), transaction reverts.
//         Sequencer resources wasted; attack can be repeated indefinitely.
```

The root cause is in `skip_stateful_validations` at: [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-178)
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L142-150)
```rust
    fn validate_tx_size(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        self.validate_tx_extended_calldata_size(tx)?;
        self.validate_tx_signature_size(tx)?;
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_proof_size(invoke_tx)?;
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L72-83)
```rust
impl From<&AddTransactionArgs> for ValidationArgs {
    fn from(args: &AddTransactionArgs) -> Self {
        Self {
            address: args.tx.contract_address(),
            account_nonce: args.account_state.nonce,
            tx_hash: args.tx.tx_hash(),
            tx_nonce: args.tx.nonce(),
            tip: args.tx.tip(),
            max_l2_gas_price: args.tx.resource_bounds().l2_gas.max_price_per_unit,
        }
    }
}
```
