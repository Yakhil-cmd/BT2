### Title
Gateway Bypasses `__validate__` Signature Check for Nonce-1 Invoke Transactions When Any Mempool Entry Exists for the Sender — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call for any invoke transaction with `nonce=1` when the on-chain account nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true` for the sender address. Because that mempool check only verifies that *some* transaction from the address exists in the pool — not that the submitter is the legitimate key-holder — an attacker who observes a victim's `deploy_account` transaction in the mempool can submit a malicious invoke with `nonce=1` from the victim's address carrying an arbitrary (invalid) signature. The gateway admits the transaction without ever calling `__validate__`, bypassing the account's signature verification entirely.

---

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When this returns `true`, `run_validate_entry_point` is called with `validate: false`: [2](#0-1) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

The `__validate__` entry point — which is the account contract's signature check — is never invoked.

**The mempool check is insufficient**

`account_tx_in_pool_or_recent_block` returns `true` if *any* transaction from the address is in the pool or a recent block: [3](#0-2) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It does not verify that the *submitter* of the current invoke is the same party who submitted the `deploy_account`. Any observer of the mempool can trigger the skip for any address.

**Nonce check passes for nonce=1 when account_nonce=0** [4](#0-3) 

With `account_nonce=0` and `max_allowed_nonce_gap=200` (default), `nonce=1` satisfies `0 ≤ 1 ≤ 200`, so `validate_nonce` passes.

**Gateway flow that admits the transaction** [5](#0-4) 

The sequence is: get on-chain nonce → `run_pre_validation_checks` (nonce + resource bounds + mempool validate) → `run_validate_entry_point` with `validate=false` → transaction forwarded to mempool.

**At execution time the signature IS checked — but nonce slot is already consumed**

When the batcher executes the block, `AccountTransaction::execute` calls `perform_pre_validation_stage` and then the `__validate__` entry point with `validate=true`. The malicious invoke fails and is reverted. However, the victim's `nonce=1` slot has been consumed; any legitimate `nonce=1` invoke the victim submitted is now a duplicate and is rejected from the mempool.

---

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

An attacker can inject an unauthorized invoke transaction (carrying an arbitrary signature) into the mempool for any address that has a pending `deploy_account`. The transaction bypasses the account's `__validate__` at the gateway stage. Although it reverts at execution time, the victim's `nonce=1` slot is permanently consumed in that block, and any legitimate `nonce=1` transaction the victim submitted is evicted from the mempool as a duplicate nonce. This is a targeted, low-cost griefing attack against any user performing the deploy-account + invoke UX flow.

---

### Likelihood Explanation

The mempool is observable (P2P propagation, RPC `starknet_pendingTransactions`). Any attacker watching for `deploy_account` transactions can immediately race to submit a malicious invoke. The attack window is the time between the victim's `deploy_account` entering the mempool and being committed to a block — typically several seconds to minutes. No special privilege or on-chain state is required beyond knowing the victim's address.

---

### Recommendation

1. **Do not skip `__validate__` entirely.** Instead, perform a lightweight off-chain ECDSA/Stark signature pre-check against the account's expected public key before admitting the transaction, even when the account is not yet deployed.

2. **Scope the skip more tightly.** Verify that the mempool entry for the sender address is specifically a `deploy_account` transaction (not just any transaction), and that the `contract_address` in that `deploy_account` matches the `sender_address` of the incoming invoke.

3. **Alternatively**, require the `deploy_account` and the paired invoke to arrive together in a single atomic submission (e.g., a bundle), so the gateway can verify both signatures before admitting either.

---

### Proof of Concept

```
1. Victim submits RpcDeployAccountTransaction for address A (nonce=0) → enters mempool.

2. Attacker observes A in mempool via RPC/P2P.

3. Attacker submits RpcInvokeTransaction:
     sender_address = A
     nonce          = 1
     signature      = [0xdead, 0xbeef]   // arbitrary, invalid

4. Gateway stateless validation: passes (valid format, nonce=1 within max_l2_gas_amount, etc.)

5. Gateway stateful validation:
   a. get_nonce_from_state(A) → Nonce(0)          // account not deployed
   b. validate_nonce: 0 ≤ 1 ≤ 200 → OK
   c. validate_by_mempool: no duplicate → OK
   d. skip_stateful_validations:
        tx.nonce() == 1  ✓
        account_nonce == 0  ✓
        account_tx_in_pool_or_recent_block(A) → true (victim's deploy_account is in pool)  ✓
        → returns true (SKIP __validate__)
   e. run_validate_entry_point called with validate=false → __validate__ NOT called

6. Malicious invoke admitted to mempool.

7. Batcher builds block:
   - Executes deploy_account (nonce=0) → account A deployed with victim's public key.
   - Executes malicious invoke (nonce=1) → __validate__ called → signature invalid → REVERTED.

8. Result:
   - Victim's nonce=1 consumed.
   - Victim's legitimate nonce=1 invoke (if submitted) rejected from mempool as DuplicateNonce.
   - Attacker pays fees for the reverted transaction.
``` [6](#0-5) [7](#0-6) [1](#0-0)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-330)
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

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );
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
