### Title
Signature Verification Bypass via `skip_stateful_validations` Allows Invalid Invoke Transactions into Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (signature verification) for any invoke transaction with `nonce == 1` when the sender address has **any** transaction in the mempool or recent block. An attacker who observes a victim's `deploy_account` transaction in the mempool can race-submit an invoke with `nonce=1` and an arbitrary/invalid signature. The gateway accepts it without signature verification. The invalid invoke occupies the victim's `nonce=1` slot; the victim's legitimate invoke is then rejected as `DuplicateNonce`. The attacker's invalid invoke is later rejected by the batcher with no fee charged, so the attack costs the attacker nothing and can be repeated indefinitely.

### Finding Description

In `extract_state_nonce_and_run_validations`, the gateway calls `run_pre_validation_checks`, which calls `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-461
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
```

When this returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, completely skipping the `__validate__` call:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

The guard `account_tx_in_pool_or_recent_block` is implemented as:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` if the address has **any** transaction in the pool — not specifically a `deploy_account`. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." However, the first condition is not enforced: the check does not distinguish between a `deploy_account` and any other transaction type.

**Attack path:**

1. Victim submits `deploy_account` for address `A`. It enters the mempool. `tx_pool.contains_account(A)` → `true`.
2. Attacker observes the `deploy_account` in the mempool and submits `Invoke(sender=A, nonce=1, signature=<garbage>)`.
3. Gateway evaluates: `tx.nonce() == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(A)` → `true` ✓.
4. `skip_stateful_validations` returns `true`; `__validate__` is **not called**. The invalid invoke is accepted into the mempool.
5. Victim submits their legitimate `Invoke(sender=A, nonce=1, signature=<valid>)`. The mempool's `validate_tx` returns `DuplicateNonce` (the attacker's tx already holds nonce=1 for address `A`). The victim's tx is rejected at the gateway.
6. Batcher picks up the attacker's invalid invoke. `__validate__` fails. In Starknet, a failed `__validate__` means the transaction is **rejected** — not reverted — so **no fee is charged** to the attacker.
7. Attacker repeats from step 2 at zero cost.

### Impact Explanation

The gateway admits a transaction with an invalid (attacker-controlled) signature into the mempool. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concretely:
- The victim's legitimate first invoke after account deployment is blocked indefinitely.
- The attacker pays no fees (failed `__validate__` = no fee charged in Starknet).
- The attack is repeatable at zero marginal cost per iteration.

### Likelihood Explanation

The `deploy_account + invoke` UX pattern is explicitly documented and tested as a supported flow. Any attacker monitoring the public mempool can observe `deploy_account` transactions and race-submit an invalid invoke. The race window is the time between the victim's `deploy_account` entering the mempool and the victim's legitimate invoke being accepted. Because the victim typically submits both in rapid succession, the attacker must be fast, but the gateway processes each transaction independently and asynchronously, making the race exploitable in practice.

### Recommendation

The check must verify that the account's **deploy_account** transaction specifically is in the mempool, not just any transaction. Options:

1. **Type-check the mempool entry**: Add a `deploy_account_in_pool(address)` query to the mempool that returns `true` only if a `DeployAccount` transaction for that address is present, rather than any transaction.
2. **Bind the invoke to the deploy_account hash**: Require the invoke to carry the `deploy_account` tx hash and verify it matches a pending `DeployAccount` in the mempool before skipping validation.
3. **Partial signature pre-check**: Even without the deployed contract, the expected class hash is known from the `deploy_account` tx in the mempool. Instantiate the class and run `__validate__` against it before the account is deployed.

### Proof of Concept

```
// Step 1: Victim submits deploy_account for address A.
// deploy_account enters mempool; tx_pool.contains_account(A) = true.

// Step 2: Attacker submits:
//   Invoke { sender_address: A, nonce: 1, signature: [0xdeadbeef, ...] }
// Gateway evaluation:
//   account_nonce = 0  (A not yet deployed on-chain)
//   tx.nonce() == 1    ✓
//   account_nonce == 0 ✓
//   account_tx_in_pool_or_recent_block(A) = true  ✓  (deploy_account is in pool)
//   → skip_stateful_validations returns true
//   → __validate__ NOT called
//   → Invalid invoke accepted into mempool

// Step 3: Victim submits:
//   Invoke { sender_address: A, nonce: 1, signature: <valid ECDSA sig> }
// validate_by_mempool → MempoolError::DuplicateNonce  → REJECTED at gateway

// Step 4: Batcher executes deploy_account → A deployed with nonce 1.
// Batcher executes attacker's invoke → __validate__ fails → REJECTED, no fee charged.

// Step 5: Attacker repeats step 2. Cost per iteration: 0 STRK.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 
<cite repo="Camomtat/sequencer--021" path="crates/apollo_gateway/src/stat

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
