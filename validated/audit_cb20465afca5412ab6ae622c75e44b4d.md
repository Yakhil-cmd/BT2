### Title
`skip_stateful_validations` Accepts Signature-Bypassed Invoke Transactions for Accounts with Pending Deploy-Account in Mempool - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator uses `account_tx_in_pool_or_recent_block` as a proxy for "a deploy_account transaction exists in the mempool for this sender." However, that check returns `true` for **any** account that has **any** transaction in the mempool or a recent block — not specifically a deploy_account. An unprivileged attacker who observes a victim's deploy_account transaction in the mempool can immediately submit a nonce=1 invoke for the same address with an arbitrary (invalid) signature. The gateway skips the `__validate__` entry-point call, accepts the transaction, and forwards it to the mempool. When the block is built, the transaction executes, `__validate__` fails, the transaction reverts, and the fee is charged to the victim's account. The victim's nonce=1 slot is also occupied, preventing them from submitting their own first invoke.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after nonce and resource-bound checks pass:

```
crates/apollo_gateway/src/stateful_transaction_validator.rs:399-410
``` [1](#0-0) 

The skip logic fires when `tx_nonce == 1` AND `account_nonce == 0` AND `account_tx_in_pool_or_recent_block` returns `true`: [2](#0-1) 

The code comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is flawed. `account_tx_in_pool_or_recent_block` checks whether the sender address appears in the mempool pool or the committed-block state: [3](#0-2) 

It does **not** distinguish between a deploy_account and any other transaction type. When `skip_validate=true` is returned, `run_validate_entry_point` sets `validate: false`, which suppresses the `__validate__` entry-point call entirely: [4](#0-3) 

The full gateway admission path is: [5](#0-4) 

### Impact Explanation

**Attack steps (unprivileged, zero knowledge of victim's private key):**

1. Victim broadcasts a deploy_account transaction (nonce=0) to the gateway. It enters the mempool. `account_tx_in_pool_or_recent_block(victim_address)` now returns `true`.
2. Attacker submits an invoke transaction: `sender_address=victim_address`, `nonce=1`, arbitrary calldata, **any signature**.
3. Gateway stateless validation passes (valid resource bounds, correct DA modes, size within limits).
4. `validate_nonce`: `account_nonce=0 ≤ tx_nonce=1 ≤ max_allowed_nonce_gap` — passes.
5. `validate_by_mempool`: nonce=1 is not a duplicate of the nonce=0 deploy_account — passes.
6. `skip_stateful_validations`: `tx_nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block==true` → returns `true`.
7. `run_validate_entry_point(skip_validate=true)`: `__validate__` is **not called**. Transaction accepted.
8. Gateway forwards the transaction to the mempool via `mempool_client.add_tx`.

At block-building time:
- The deploy_account (nonce=0) executes first; the account is deployed.
- The attacker's invoke (nonce=1) executes; `__validate__` is now called with the invalid signature; the transaction **reverts**.
- The fee (gas consumed by `__validate__`) is charged to the **victim's** account.
- The victim's nonce=1 slot was consumed; the victim cannot submit their own first invoke until the attacker's transaction is committed and the nonce advances.

**Corrupted value:** The gateway's admission decision — an invalid (unsigned) transaction is accepted as if it were valid.

### Likelihood Explanation

The attack requires only:
- Observing the public mempool for deploy_account transactions (trivially automatable).
- Submitting a single crafted invoke with a random signature.

No privileged access, no special knowledge, no resource beyond a small transaction fee (paid by the attacker for their own submission, not the victim's). Any account that uses the deploy_account + invoke UX flow is a target during the window between deploy_account submission and block commitment.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the sender address is present in the mempool. Add a dedicated mempool query such as `deploy_account_in_pool(sender_address) -> bool` that inspects only `InternalRpcTransactionWithoutTxHash::DeployAccount` entries. The skip should only fire when a deploy_account for the exact sender address is pending, not when any transaction from that address exists.

### Proof of Concept

```
// Precondition: victim's deploy_account (nonce=0) is in the mempool.
// Attacker constructs:
let attacker_invoke = RpcInvokeTransactionV3 {
    sender_address: victim_address,   // victim's address, publicly known from mempool
    nonce: Nonce(Felt::ONE),          // nonce=1 triggers the skip condition
    calldata: Calldata(vec![].into()),
    signature: TransactionSignature(vec![Felt::from(0xdeadbeef_u64)].into()), // garbage
    resource_bounds: AllResourceBounds { l2_gas: NON_EMPTY_RESOURCE_BOUNDS, .. },
    // all other fields: defaults / valid values
};

// Gateway flow:
// 1. stateless_tx_validator.validate(&tx) -> Ok(())   [valid resource bounds, size, DA modes]
// 2. convert_rpc_tx_to_internal_and_executable_txs -> Ok(internal_tx, executable_tx, None)
// 3. extract_state_nonce_and_run_validations:
//      account_nonce = get_nonce_from_state(victim_address) = Nonce(0)
//      run_pre_validation_checks:
//          validate_nonce: 0 <= 1 <= max_gap  -> Ok
//          validate_by_mempool: no duplicate  -> Ok
//          skip_stateful_validations:
//              tx_nonce==1 && account_nonce==0 -> true
//              account_tx_in_pool_or_recent_block(victim_address) -> true (deploy_account is there)
//              returns true  (SKIP)
//      run_validate_entry_point(skip_validate=true):
//          execution_flags.validate = false
//          __validate__ NOT called
//          -> Ok(())
// 4. mempool_client.add_tx(attacker_invoke) -> Ok(())
//
// Result: attacker's unsigned invoke is in the mempool.
// At execution: __validate__ runs, fails, tx reverts, victim pays fee.
``` [2](#0-1) [4](#0-3) [3](#0-2)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-315)
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
