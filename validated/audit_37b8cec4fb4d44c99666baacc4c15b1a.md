### Title
`skip_stateful_validations` Bypasses `__validate__` Entry Point Based on Stale Non-Deploy-Account Mempool Presence - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry point for an invoke transaction with nonce=1 only when a corresponding `deploy_account` transaction exists in the mempool. However, the predicate it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction type associated with the account, not exclusively `deploy_account` transactions. After a `deploy_account` is evicted from the mempool (e.g., TTL expiry), a residual invoke(nonce=1) left in the pool causes the predicate to remain `true`, allowing a subsequent invoke(nonce=1) — including one with an invalid or attacker-controlled signature — to be admitted to the mempool without running the account's `__validate__` entry point.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

The skip condition is:

```
tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)
```

and the guard is:

```rust
return mempool_client
    .account_tx_in_pool_or_recent_block(tx.sender_address())
    .await
``` [2](#0-1) 

The comment explicitly acknowledges the assumption:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."

The implementation of `account_tx_in_pool_or_recent_block` is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

And `state.contains_account` checks staged and committed maps for **any** address, regardless of transaction type: [4](#0-3) 

The assumption breaks in the following sequence:

1. Account A (on-chain nonce = 0, not deployed) submits `deploy_account(nonce=0)` → admitted to pool.
2. Account A submits `invoke(nonce=1)` → `skip_stateful_validations` returns `true` (deploy_account in pool) → `__validate__` skipped → admitted.
3. `deploy_account` TTL expires → removed from pool by the TTL cleanup path.
4. Only `invoke(nonce=1)` remains in the pool. `account_tx_in_pool_or_recent_block(A)` still returns `true` because `tx_pool.contains_account(A)` is true.
5. Attacker submits a new `invoke(nonce=1)` for Account A with an arbitrary/invalid signature → `skip_stateful_validations` returns `true` (old invoke in pool) → `__validate__` skipped → admitted via fee escalation.

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate tx hash, nonce-too-old, and fee escalation: [5](#0-4) 

It does not verify the signature. The only signature check is inside `run_validate_entry_point`, which is gated on `!skip_validate`: [6](#0-5) 

The analog to the external report is exact: just as ZetaChain's `GetPendingCCTXInTransit` removes a cctx from the "in-transit" set when it is added to the `OutTxTracker` (broadcasted but not yet executed), the Sequencer's `skip_stateful_validations` removes the validation requirement when the account appears in the mempool — but the mempool entry that triggers the skip may be a non-deploy-account transaction left over after the actual `deploy_account` was evicted, not evidence that a valid `deploy_account` is in transit.

The TTL eviction path that enables this is confirmed by the test: [7](#0-6) 

The production default TTL and the `max_nonce_for_validation_skip = Nonce(Felt::ONE)` are set in: [8](#0-7) 

### Impact Explanation

An attacker can submit an `invoke(nonce=1)` transaction for any account whose `deploy_account` has been evicted from the mempool but whose prior `invoke(nonce=1)` remains. The gateway admits the transaction without running the account's `__validate__` entry point, bypassing the account's signature verification at the admission layer. The transaction will fail at batcher execution time (no deployed account contract), but it is admitted to the mempool as a valid pending transaction, consuming mempool capacity and potentially displacing legitimate transactions via fee escalation. This matches the **High** impact category: "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

### Likelihood Explanation

The window requires: (a) a `deploy_account` to have been admitted and then evicted by TTL, and (b) the paired `invoke(nonce=1)` to still be present. The default TTL is configurable and finite. Any account that submitted the deploy+invoke UX pair and whose `deploy_account` was not executed before TTL expiry is permanently vulnerable to this bypass for nonce=1 invokes. This is a realistic operational condition, not a theoretical edge case.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` predicate with a check that specifically verifies the presence of a `deploy_account` transaction for the sender address. The mempool should expose a dedicated `deploy_account_in_pool_or_recent_block(address)` query that inspects transaction types, or the pool should maintain a separate index of deploy-account addresses. Alternatively, the skip should only be granted when the mempool can confirm the specific `deploy_account` nonce (nonce=0) is present for the account.

### Proof of Concept

```
1. Account address A is freshly generated (on-chain nonce = 0).

2. Submit deploy_account(sender=A, nonce=0, valid_sig) → gateway admits it.
   Mempool pool: { A: [deploy_account(nonce=0)] }

3. Submit invoke(sender=A, nonce=1, valid_sig) →
   skip_stateful_validations: nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
   → __validate__ skipped → admitted.
   Mempool pool: { A: [deploy_account(nonce=0), invoke(nonce=1)] }

4. Wait for deploy_account TTL to expire (or replace it with a lower-fee version
   that gets evicted). deploy_account is removed.
   Mempool pool: { A: [invoke(nonce=1)] }
   account_tx_in_pool_or_recent_block(A) == true  ← stale, no deploy_account

5. Attacker submits invoke(sender=A, nonce=1, tip=higher, sig=GARBAGE) →
   validate_by_mempool: nonce 1 >= resolved_nonce 0 → OK; fee escalation → replaces old invoke
   skip_stateful_validations: nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
   → __validate__ SKIPPED → admitted with invalid signature.

Result: Attacker's invoke(nonce=1) with invalid signature is in the mempool.
        Gateway never verified the signature.
        Batcher will attempt execution and fail, but the slot was consumed.
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

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

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L1131-1175)
```rust
#[rstest]
fn add_tx_old_transactions_cleanup() {
    // Create a mempool with a fake clock.
    let fake_clock = Arc::new(FakeClock::default());
    let mut mempool = Mempool::new(
        MempoolConfig {
            dynamic_config: MempoolDynamicConfig { transaction_ttl: Duration::from_secs(60) },
            ..Default::default()
        },
        fake_clock.clone(),
    );

    // Add a new transaction to the mempool.
    let first_tx =
        add_tx_input!(tx_hash: 1, address: "0x0", tx_nonce: 0, account_nonce: 0, tip: 100);
    add_tx(&mut mempool, &first_tx);

    // Advance the clock and add another transaction.
    fake_clock.advance(mempool.config.dynamic_config.transaction_ttl / 2);
    let second_tx =
        add_tx_input!(tx_hash: 2, address: "0x1", tx_nonce: 0, account_nonce: 0, tip: 50);
    add_tx(&mut mempool, &second_tx);

    // Verify that both transactions are in the mempool.
    let expected_txs = [&first_tx.tx, &second_tx.tx];
    let expected_mempool_content = MempoolTestContentBuilder::new()
        .with_pool(expected_txs.map(|tx| tx.clone()))
        .with_priority_queue(expected_txs.map(TransactionReference::new))
        .build();
    expected_mempool_content.assert_eq(&mempool.content());

    // Advance the clock and add a new transaction.
    fake_clock.advance(mempool.config.dynamic_config.transaction_ttl / 2 + Duration::from_secs(5));
    let third_tx =
        add_tx_input!(tx_hash: 3, address: "0x2", tx_nonce: 0, account_nonce: 0, tip: 10);
    add_tx(&mut mempool, &third_tx);

    // The first transaction should be removed from the mempool.
    let expected_txs = [&second_tx.tx, &third_tx.tx];
    let expected_mempool_content = MempoolTestContentBuilder::new()
        .with_pool(expected_txs.map(|tx| tx.clone()))
        .with_priority_queue(expected_txs.map(TransactionReference::new))
        .build();
    expected_mempool_content.assert_eq(&mempool.content());
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
