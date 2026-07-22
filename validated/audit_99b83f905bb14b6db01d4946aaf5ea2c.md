### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` Signature Check for Nonce-1 Invoke Transactions — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the account's `__validate__` entry-point (signature verification) for any Invoke transaction whose nonce is exactly `1` and whose sender address appears in `account_tx_in_pool_or_recent_block`. The check used to justify the skip is too broad: it returns `true` for any address that has *any* transaction in the mempool pool or committed state, not specifically a `deploy_account`. An unprivileged attacker can therefore submit an Invoke transaction with an arbitrary/invalid signature for any address that has a pending `deploy_account` in the mempool, and the gateway will admit it without verifying the signature.

### Finding Description

In `extract_state_nonce_and_run_validations`, after nonce and resource-bound checks pass, the gateway calls `skip_stateful_validations` to decide whether to run the blockifier's `__validate__` entry point:

```
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate = false`, the function returns immediately after `perform_pre_validation_stage` without ever calling `validate_tx` (which is where `__validate__` / signature verification runs):

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

The justification in the code comment is: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

However, `account_tx_in_pool_or_recent_block` checks for **any** transaction from the sender, not specifically a `deploy_account`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The reasoning is circular: the skip condition is triggered by the presence of *any* transaction in the pool, but the attacker's own invalid nonce-1 Invoke is the transaction being evaluated — it has not yet passed validation. A third party who observes a legitimate user's pending `deploy_account` in the mempool can immediately submit an Invoke with nonce `1` and an arbitrary signature for that same address. Because the legitimate `deploy_account` is already in the pool, `account_tx_in_pool_or_recent_block` returns `true`, the skip fires, and the forged Invoke is admitted without any signature check.

### Impact Explanation

The gateway admits an Invoke transaction with an invalid/forged signature into the mempool. The transaction will later fail during batcher execution (the blockifier calls `__validate__` with `validate = true` during actual block building), so it will not produce wrong state. However, the admission decision itself is wrong: an invalid transaction that should have been rejected at the gateway is accepted and queued for sequencing. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Secondary effects include mempool pollution, wasted batcher CPU (fetching and attempting to execute a transaction that will always fail `__validate__`), and potential ordering interference with the legitimate user's own nonce-1 transaction.

### Likelihood Explanation

The attack requires only:
1. Observing a pending `deploy_account` transaction in the public mempool (trivially observable).
2. Constructing an Invoke transaction with nonce `1`, the target sender address, and any bytes in the signature field.
3. Submitting it to the gateway.

No privileged access, no special knowledge of the account's private key, and no on-chain funds are required. The condition `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` is satisfied for every freshly-submitted `deploy_account` before it is committed.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the sender address in the mempool. Alternatively, expose a `deploy_account_in_pool(address)` query on the mempool that only returns `true` when the pending transaction for that address is of type `DeployAccount`. This preserves the UX intent (allowing the paired Invoke to be submitted before the `deploy_account` is processed) while closing the gap that allows arbitrary signatures to bypass gateway validation.

### Proof of Concept

1. Legitimate user submits `deploy_account` for address `A` (nonce 0). It is admitted to the mempool pool.
2. Attacker calls the gateway's `add_tx` endpoint with:
   - `type = INVOKE`
   - `sender_address = A`
   - `nonce = 1`
   - `signature = [0x0, 0x0]` (invalid)
   - valid resource bounds and calldata
3. Gateway flow:
   - `StatelessTransactionValidator::validate` passes (signature length ≤ max, resource bounds non-zero).
   - `convert_rpc_tx_to_internal` computes the tx hash and produces an `InternalRpcTransaction`.
   - `extract_state_nonce_and_run_validations`:
     - `get_nonce_from_state(A)` → `Nonce(0)` (account not yet deployed).
     - `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` → passes.
     - `validate_resource_bounds` → passes.
     - `validate_by_mempool` → passes (no duplicate, nonce not too old).
     - `skip_stateful_validations`: nonce == 1, account_nonce == 0, `account_tx_in_pool_or_recent_block(A)` == **true** (deploy_account is in pool) → returns **true**.
     - `run_validate_entry_point(skip_validate=true)`: sets `validate=false`, `__validate__` is **never called**.
4. The forged Invoke is added to the mempool via `mempool_client.add_tx(...)`.
5. The batcher later fetches both transactions, executes the `deploy_account` (deploys the contract), then attempts the forged Invoke. `__validate__` is called with the invalid signature, fails, and the transaction is rejected — but it was admitted to the mempool without any signature check. [5](#0-4) [6](#0-5) [4](#0-3) [7](#0-6)

### Citations

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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
