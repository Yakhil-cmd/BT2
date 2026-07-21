### Title
Gateway `skip_stateful_validations` admits invoke transactions with unverified signatures via self-referential `account_tx_in_pool_or_recent_block` check after deploy_account TTL expiry - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (i.e., signature verification) for an invoke transaction with nonce=1 from an undeployed account, provided `account_tx_in_pool_or_recent_block` returns `true`. That check returns `true` for **any** transaction in the pool for the address — not specifically a deploy_account. Once a deploy_account expires from the mempool (TTL), the invoke(nonce=1) that was admitted via skip_validate remains in the pool. Its own presence then satisfies the `account_tx_in_pool_or_recent_block` check for subsequent invokes, creating a self-referential loop that allows the gateway to permanently admit invoke transactions with unverified (or invalid) signatures for that address.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function fires when `tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO)` and delegates the skip decision entirely to:

```rust
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await
```

The comment asserts this is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." The second branch of that disjunction is the flaw: an invoke(nonce=1) admitted via skip_validate did **not** pass `__validate__`; it was admitted precisely because validation was skipped.

**`account_tx_in_pool_or_recent_block` is type-agnostic:** [2](#0-1) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`tx_pool.contains_account` checks `AccountTransactionIndex::contains`, which is a plain `HashMap::contains_key` on the address — it does not distinguish deploy_account from invoke: [3](#0-2) 

**`skip_validate=true` suppresses `__validate__` at the gateway:** [4](#0-3) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

When `skip_validate=true`, `validate=false`, so `StatefulValidator::perform_validations` returns immediately without calling `__validate__`: [5](#0-4) 

**TTL expiry removes the deploy_account but not the invoke:** [6](#0-5) 

`remove_expired_txs` removes transactions older than `transaction_ttl` (default 300 s in production): [7](#0-6) 

After the deploy_account is removed, the invoke(nonce=1) that was admitted via skip_validate remains in the pool. `tx_pool.contains_account(A)` is still `true`, so the next invoke(nonce=1) for A also gets `skip_validate=true`.

**Self-referential loop confirmed by test:**

The test `mempool_state_retains_address_across_api_calls` explicitly documents that `account_tx_in_pool_or_recent_block` returns `true` as long as any transaction for the address is in the pool: [8](#0-7) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway permanently admits invoke transactions with unverified (or deliberately invalid) signatures for any address that once had a deploy_account in the mempool. The `__validate__` entry point — the account's sole signature-verification gate at the gateway — is bypassed. The admitted transactions carry no verified authorization from the account owner.

At execution time the batcher will call `__validate__` and the transaction will revert. However:

1. The reverted transaction is still included in the block and consumes batcher/block resources.
2. If the account was never deployed (deploy_account expired), the account contract does not exist; the execution fails before fee transfer, so the **sequencer absorbs the cost** — the attacker pays nothing after the initial (expired, unexecuted) deploy_account submission.
3. The attacker can continuously replace the pooled invoke with a higher-fee version (fee escalation is enabled by default) before it is batched, keeping a "zombie" invalid invoke in the mempool indefinitely at zero net cost.
4. With multiple addresses the attacker can fill the mempool with signature-unverified invokes, degrading admission quality for legitimate users.

---

### Likelihood Explanation

Any unprivileged user can trigger this:

- Submit a deploy_account for a fresh address (no fee charged until executed; it will expire).
- Submit an invoke(nonce=1) with an arbitrary/invalid signature while the deploy_account is still in the pool.
- Wait for the deploy_account TTL (300 s in production) to expire.
- The invoke remains; the self-referential loop is now active.

No special privileges, no privileged keys, no peer access required. The only cost is the deploy_account submission (which is never executed and never charged).

---

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check in `skip_stateful_validations` with a check that specifically verifies a **deploy_account** transaction for the address is currently in the pool. For example, expose a `has_deploy_account_in_pool(address)` query on the mempool that inspects the transaction type, and use that instead of the generic presence check.

Alternatively, track at admission time whether an invoke was admitted via skip_validate, and re-validate it (or evict it) if the corresponding deploy_account is later removed from the pool.

---

### Proof of Concept

```
Step 1. Attacker generates a fresh address A (not deployed on-chain; account_nonce = 0).

Step 2. Attacker submits deploy_account(A) to the gateway.
        → Gateway: stateless OK, stateful nonce OK (nonce=0, account_nonce=0).
        → Mempool: deploy_account(A) admitted. tx_pool.contains_account(A) = true.

Step 3. Attacker submits invoke(sender=A, nonce=1, signature=GARBAGE) to the gateway.
        → Gateway stateful validator:
            account_nonce = get_nonce_from_state(A) = 0  (A not deployed)
            validate_nonce: 0 <= 1 <= max_gap  → OK
            skip_stateful_validations:
                nonce==1 && account_nonce==0  → true
                account_tx_in_pool_or_recent_block(A) = true  (deploy_account is in pool)
                → skip_validate = true
            run_validate_entry_point: validate=false → __validate__ NOT called
        → Mempool: invoke(A, nonce=1, GARBAGE) admitted.

Step 4. Wait 300 seconds (transaction_ttl).
        → remove_expired_txs() removes deploy_account(A) from the pool.
        → invoke(A, nonce=1, GARBAGE) remains in the pool.
        → tx_pool.contains_account(A) = true  (the invoke is still there).

Step 5. Attacker submits invoke(sender=A, nonce=1, signature=GARBAGE2, higher_fee) to the gateway.
        → skip_stateful_validations:
            account_tx_in_pool_or_recent_block(A) = true  ← satisfied by the INVOKE from step 3
            → skip_validate = true
            → __validate__ NOT called
        → Mempool: fee escalation replaces the previous invoke; GARBAGE2 invoke admitted.

Step 6. Repeat step 5 indefinitely. Each iteration:
        - The previous invalid invoke justifies the next one.
        - No deploy_account is present; the loop is self-sustaining.
        - The account is never deployed; when the batcher eventually executes an invoke,
          the account contract does not exist, execution fails, fee transfer fails,
          and the sequencer absorbs the cost.
```

**Key code locations:**

- `skip_stateful_validations` (self-referential check): [1](#0-0) 
- `account_tx_in_pool_or_recent_block` (type-agnostic): [2](#0-1) 
- `run_validate_entry_point` (skip path): [9](#0-8) 
- TTL expiry removes deploy_account but not invoke: [6](#0-5) 
- Production TTL = 300 s: [10](#0-9)

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

**File:** crates/apollo_mempool/src/mempool.rs (L849-866)
```rust
    fn remove_expired_txs(&mut self) -> AddressToNonce {
        let removed_txs = self
            .tx_pool
            .remove_txs_older_than(self.config.dynamic_config.transaction_ttl, &self.state.staged);

        for tx_ref in &removed_txs {
            self.decrement_stuck_txs_if_gap_account(tx_ref.address, 1);
        }

        let queued_txs = self.tx_queue.remove_txs(&removed_txs);

        self.log_and_count_expired_txs(&removed_txs);
        self.update_state_metrics();
        queued_txs
            .into_iter()
            .map(|tx| (tx.address, self.state.resolve_nonce(tx.address, tx.nonce)))
            .collect::<AddressToNonce>()
    }
```

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
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

**File:** crates/apollo_mempool/src/mempool_flow_tests.rs (L318-344)
```rust
/// Test that the API function [Mempool::account_tx_in_pool_or_recent_block] behaves as expected
/// under various conditions.
#[rstest]
fn mempool_state_retains_address_across_api_calls(mut mempool: Mempool) {
    // Setup.
    let address = "0x1";
    let input_address_1 = add_tx_input!(address: address);
    let account_address = contract_address!(address);

    // Test.
    add_tx(&mut mempool, &input_address_1);
    // Assert: Mempool state includes the address of the added transaction.
    assert!(mempool.account_tx_in_pool_or_recent_block(account_address));

    // Test.
    mempool.get_txs(1).unwrap();
    // Assert: The Mempool state still contains the address, even after it was sent to the batcher.
    assert!(mempool.account_tx_in_pool_or_recent_block(account_address));

    // Test.
    let nonces = [(address, 1)];
    commit_block(&mut mempool, nonces, []);
    // Assert: Mempool state still contains the address, even though the transaction was committed.
    // Note that in the future, the Mempool's state may be periodically cleared from records of old
    // committed transactions. Mirroring this behavior may require a modification of this test.
    assert!(mempool.account_tx_in_pool_or_recent_block(account_address));
}
```
