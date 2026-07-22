### Title
Signature Verification Bypass via Validation Skip for Undeployed Accounts Allows Injection of Unsigned Invoke Transactions - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (which performs signature verification) for invoke transactions with `nonce=1` when the account's on-chain nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. Because `account_tx_in_pool_or_recent_block` returns `true` whenever **any** transaction for the sender address exists in the mempool — not specifically a deploy-account transaction — an attacker who observes a victim's pending `deploy_account` in the mempool can immediately submit an invoke transaction from the victim's address with `nonce=1` and an invalid or empty signature. The gateway accepts this transaction without calling `__validate__`, inserting it into the mempool and blocking the victim's legitimate first invoke.

### Finding Description

The gateway's stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    let account_address = tx.sender_address();
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

When this returns `true`, `run_validate_entry_point` is called with `skip_validate=true`, setting `execution_flags.validate = false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:310-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations`, when `validate=false` for an Invoke, the function returns `Ok(())` before calling `__validate__`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:79-81
if !tx.execution_flags.validate {
    return Ok(());
}
```

The `account_tx_in_pool_or_recent_block` check is:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` if the address has **any** transaction in the pool or recent committed state — not specifically a `deploy_account`. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this reasoning is circular: those future-nonce transactions may themselves have had validation skipped.

**Attack steps:**

1. Victim submits a `deploy_account` for `victim_address`. This places `victim_address` in the mempool pool, so `account_tx_in_pool_or_recent_block(victim_address)` returns `true`.
2. Attacker submits an `Invoke` with `sender_address=victim_address`, `nonce=1`, arbitrary calldata (e.g., ERC-20 transfer to attacker), and an invalid/empty signature.
3. Gateway stateless validator checks only signature **length** (not validity).
4. `validate_nonce`: `tx_nonce=1 >= account_nonce=0`, within `max_allowed_nonce_gap=200` — passes.
5. `validate_by_mempool` (`mempool.validate_tx`): checks nonce not too old and fee escalation — passes.
6. `skip_stateful_validations`: `tx_nonce=1`, `account_nonce=0`, `account_tx_in_pool_or_recent_block(victim_address)=true` → returns `true`.
7. `run_validate_entry_point` with `skip_validate=true` → `__validate__` **not called** → invalid signature accepted.
8. Gateway calls `mempool_client.add_tx(...)` — attacker's unsigned invoke is now in the mempool.
9. Victim's legitimate `nonce=1` invoke is rejected with `DuplicateNonce`.
10. Attacker's tx fails at batcher execution time (when `__validate__` is called with full execution flags), but the attacker immediately resubmits step 2, creating a persistent DoS.

### Impact Explanation

The gateway admits an invalid transaction — one whose signature has never been verified by the account contract — into the mempool. This breaks the invariant that only the account owner can submit transactions from their address. Concretely:

- The victim's first post-deployment invoke is permanently blocked as long as the attacker keeps front-running with unsigned invokes.
- The attacker's transaction occupies the `nonce=1` slot, preventing the victim from submitting their own transaction (rejected with `DuplicateNonce`).
- The attacker's transaction eventually fails at execution time (batcher calls `__validate__` with `validate=true`), but the attacker can immediately repeat the attack.
- For accounts whose `__validate__` is permissive or absent, the attacker's arbitrary calldata could execute successfully.

This matches the **High** impact category: *Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

### Likelihood Explanation

The deploy-account + invoke UX pattern (submitting both transactions simultaneously) is explicitly the intended use case this skip was designed to support, as documented in the code comments. Any user following this standard pattern is vulnerable. The attacker only needs to monitor the public mempool for `deploy_account` transactions and immediately submit a competing `nonce=1` invoke. No privileged access is required.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the address. The mempool should expose a dedicated `has_pending_deploy_account(address)` query that inspects the transaction type, not just address presence. Alternatively, the gateway should verify that the transaction in the mempool for the address is specifically a `deploy_account` before skipping `__validate__`.

### Proof of Concept

```
# Precondition: victim_address has a pending deploy_account in the mempool.

POST /gateway/add_transaction
{
  "type": "INVOKE",
  "version": "0x3",
  "sender_address": "<victim_address>",
  "nonce": "0x1",
  "calldata": ["<transfer_selector>", "<attacker_address>", "<amount>", "0x0"],
  "signature": [],                  # empty / invalid signature
  "resource_bounds": { ... },       # valid resource bounds
  "tip": "0x0",
  "paymaster_data": [],
  "account_deployment_data": [],
  "nonce_data_availability_mode": 0,
  "fee_data_availability_mode": 0
}

# Expected (correct) behavior: rejected with ValidateFailure
# Actual behavior: accepted into mempool, victim's nonce=1 invoke blocked
```

The gateway accepts this transaction because:
- `validate_nonce`: `1 >= 0` ✓
- `validate_by_mempool`: nonce not too old ✓
- `skip_stateful_validations`: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block==true` → skip ✓
- `run_validate_entry_point`: `validate=false` → `__validate__` not called ✓ [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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
