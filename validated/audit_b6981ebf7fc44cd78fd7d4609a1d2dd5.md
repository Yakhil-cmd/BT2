### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Admission of Invalid Invoke Transactions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's deploy-account + invoke UX shortcut (`skip_stateful_validations`) unconditionally skips the account's `__validate__` entry-point (signature check) for any invoke transaction with nonce=1 sent to an address that has *any* transaction in the mempool or a recent block. An unprivileged attacker who observes a victim's pending `deploy_account` transaction can submit a crafted invoke with nonce=1 for that address carrying an arbitrary/invalid signature, and the gateway will admit it to the mempool without ever verifying the signature.

---

### Finding Description

In `stateful_transaction_validator.rs`, `run_pre_validation_checks` calls three sub-checks in sequence: [1](#0-0) 

The third sub-check, `skip_stateful_validations`, returns `true` (skip) when:

1. The transaction is an `Invoke`,
2. The invoke's nonce equals `Nonce(Felt::ONE)`, and
3. The account's on-chain nonce equals `Nonce(Felt::ZERO)`, and
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [2](#0-1) 

When `skip_validate = true`, `run_validate_entry_point` constructs `ExecutionFlags` with `validate: false`, meaning the account's `__validate__` entry point — the only place the signature is cryptographically checked — is never called: [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check is the sole guard. It verifies only that *some* transaction for the sender address exists in the mempool or a recent block — it does **not** verify that the pending transaction is a `deploy_account`, nor does it verify the invoke's signature in any way. Because the mempool is observable (transactions are broadcast), any attacker can identify a victim address with a pending `deploy_account` and exploit this gap.

---

### Impact Explanation

An attacker submits an `Invoke V3` transaction with:
- `sender_address` = victim's not-yet-deployed address (observed from the mempool),
- `nonce = 1`,
- an arbitrary or invalid `signature`.

The gateway's `validate_state_preconditions` passes (nonce=1 is within the allowed gap from account_nonce=0), `validate_by_mempool` passes (mempool-level nonce ordering is satisfied), and `skip_stateful_validations` returns `true` because the victim's `deploy_account` is in the mempool. The invoke is admitted to the mempool **without any signature verification**.

This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."**

The admitted invalid transaction:
- Consumes mempool slots and processing resources.
- Can be used to flood the mempool with invalid invokes targeting every address that has a pending `deploy_account`, constituting a targeted DoS against the deploy-account + invoke UX path.
- During batcher execution, `new_for_sequencing` sets `validate: true` (line 151), so the batcher will eventually reject the transaction — but only after it has already been admitted and processed by the mempool. [4](#0-3) 

---

### Likelihood Explanation

- The mempool is public; pending `deploy_account` transactions are observable by anyone.
- The attacker needs only to craft an `Invoke V3` with nonce=1 for the target address — no privileged access, no special knowledge beyond what is visible on-chain/in-mempool.
- The condition `nonce == 1 && account_nonce == 0` is a narrow but well-known window that exists for every new account deployment.

---

### Recommendation

1. **Restrict the skip condition to `deploy_account` transactions only.** `account_tx_in_pool_or_recent_block` should be replaced with a check that specifically confirms a `deploy_account` transaction for the sender address is pending in the mempool, not just any transaction.

2. **Verify the invoke's signature even when skipping the on-chain `__validate__` call.** A lightweight off-chain ECDSA check against the account's expected public key (derivable from the pending `deploy_account`'s class hash and constructor calldata) would close the gap without requiring the account to be deployed.

3. **Rate-limit or cap the number of nonce=1 invokes admitted per undeployed address** to bound the DoS surface.

---

### Proof of Concept

```
1. Alice broadcasts: DeployAccount { sender_address: X, nonce: 0, ... }
   → Mempool now contains a tx for address X.

2. Attacker observes the mempool, sees address X has a pending deploy_account.

3. Attacker broadcasts: Invoke { sender_address: X, nonce: 1,
                                  signature: [0xdead, 0xbeef], ... }

4. Gateway stateful validator:
   - account_nonce(X) = 0  ✓
   - invoke.nonce = 1       ✓
   - account_tx_in_pool_or_recent_block(X) = true  ✓
   → skip_validate = true
   → __validate__ is NOT called
   → Transaction admitted to mempool with invalid signature.

5. Batcher later picks up the invalid invoke, calls __validate__ with
   validate: true, signature check fails → transaction rejected.
   But the invalid tx was already in the mempool.

6. Attacker repeats for every address with a pending deploy_account,
   flooding the mempool with signature-unverified transactions.
``` [2](#0-1) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-356)
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

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
    }
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
