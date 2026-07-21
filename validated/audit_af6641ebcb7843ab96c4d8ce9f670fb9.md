### Title
`skip_stateful_validations` Bypasses Signature Verification for Invoke Transactions via Overly Broad `account_tx_in_pool_or_recent_block` Check - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account's deploy_account is still pending. The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** account that has **any** transaction in the mempool or recent committed state, not specifically a deploy_account transaction. An attacker who observes a victim's deploy_account entering the mempool can immediately submit an invoke(nonce=1) for the victim's address with an **arbitrary signature**, and the gateway will accept it without calling `__validate__`. This violates the invariant that every admitted transaction must carry a valid account signature.

---

### Finding Description

**Vulnerable function** — `skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` lines 429–461:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                // ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`, so the blockifier's `StatefulValidator` skips the `__validate__` call entirely:

```rust
let strict_nonce_check = false;
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

**The flawed guard** — `account_tx_in_pool_or_recent_block` in `crates/apollo_mempool/src/mempool.rs` lines 697–700:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`state.contains_account` checks only whether the address appears in the mempool's `staged` or `committed` nonce maps:

```rust
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
``` [4](#0-3) 

`tx_pool.contains_account` checks whether any transaction (of any type) for that address is in the pool:

```rust
pub fn contains_account(&self, address: ContractAddress) -> bool {
    self.txs_by_account.contains(address)
}
``` [5](#0-4) 

Neither check distinguishes a deploy_account transaction from an invoke transaction. The code comment in `skip_stateful_validations` acknowledges this imprecision:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**." [6](#0-5) 

The second branch of that disjunction is the vulnerability: a prior attacker-submitted invoke(nonce=1) that itself skipped validation (because the victim's deploy_account was already in the pool) is sufficient to make `account_tx_in_pool_or_recent_block` return `true` for all subsequent invoke(nonce=1) submissions for that address.

**Attack flow:**

1. Victim (Alice) submits `deploy_account` for address A. The gateway fully validates it (deploy_account goes through `self.execute(tx)` path in `StatefulValidator::perform_validations`). Alice's deploy_account enters the mempool pool.
2. Attacker observes Alice's deploy_account in the mempool. Attacker submits `invoke(nonce=1, sender=A, signature=<garbage>, tip=T+1)`.
3. Gateway stateful validator:
   - `get_nonce_from_state(A)` → `0` (A not yet on-chain).
   - `validate_nonce`: `0 ≤ 1 ≤ 0 + max_gap` → passes.
   - `validate_by_mempool`: no existing nonce-1 tx for A → passes.
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true` (Alice's deploy_account is in the pool) → returns `true`.
   - `run_validate_entry_point` with `validate=false` → `__validate__` is **not called**.
4. Attacker's invoke(nonce=1) with garbage signature is forwarded to the mempool via `mempool_client.add_tx`.
5. If Alice had already submitted her own invoke(nonce=1), the attacker's higher-tip tx replaces it via fee escalation in `add_tx_validations`. Alice's legitimate tx is evicted.
6. Batcher later executes the block: `deploy_account(A)` succeeds, then `invoke(nonce=1, sig=garbage)` is executed — `__validate__` is called by the blockifier during execution, the signature check fails, and the tx **reverts**. Alice's invoke is gone. [7](#0-6) 

---

### Impact Explanation

The gateway admits an invoke transaction with an **invalid (attacker-chosen) signature** to the mempool. This violates the admission invariant that every transaction must carry a valid account signature before sequencing. Concretely:

- Alice's legitimate invoke(nonce=1) is displaced from the mempool by the attacker's invalid tx via fee escalation.
- The attacker's tx reverts on-chain (no state corruption), but Alice's tx is permanently lost from the mempool and must be resubmitted.
- The attacker can repeat this indefinitely (each time paying a marginally higher tip) to prevent Alice's first post-deploy invoke from ever being sequenced.

Impact category: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- Requires the victim to have submitted a deploy_account transaction (common for new account onboarding).
- The attacker must monitor the mempool for pending deploy_account transactions (publicly observable).
- The attacker must pay a higher tip than the victim's invoke to displace it; this has a small but non-zero economic cost.
- No privileged access is required; any unprivileged user can submit an RPC transaction.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction is pending for the address. Options:

1. Add a dedicated `deploy_account_in_pool(address)` query to the mempool that inspects `InternalRpcTransactionWithoutTxHash::DeployAccount` entries in the pool.
2. Maintain a separate set of addresses for which a deploy_account is currently pending, updated on `add_tx` / `commit_block`.

Either approach ensures that the `__validate__` skip is only granted when the account's own deploy_account is genuinely pending, not when any arbitrary transaction for that address happens to be in the pool.

---

### Proof of Concept

```
// Step 1: Alice submits deploy_account for address A (fully validated).
POST /add_transaction  { type: deploy_account, sender: A, sig: <valid>, nonce: 0 }
// → accepted; A enters tx_pool

// Step 2: Attacker submits invoke with garbage signature and tip > Alice's invoke tip.
POST /add_transaction  { type: invoke, sender: A, sig: [0xdead, 0xbeef], nonce: 1, tip: 9999 }
// Gateway:
//   account_nonce(A) = 0  ✓
//   tx.nonce() = 1        ✓
//   account_tx_in_pool_or_recent_block(A) = true  (Alice's deploy_account is in pool)
//   → skip_validate = true → __validate__ NOT called
// → accepted; attacker's invoke enters mempool

// Step 3: Alice submits her legitimate invoke(nonce=1, tip=100).
POST /add_transaction  { type: invoke, sender: A, sig: <valid>, nonce: 1, tip: 100 }
// Mempool: attacker's tip (9999) > Alice's tip (100) → DuplicateNonce / fee escalation fails
// → Alice's tx REJECTED

// Step 4: Batcher executes block:
//   deploy_account(A)  → OK, A deployed
//   invoke(A, nonce=1, sig=[0xdead,0xbeef])  → __validate__ called → REVERT
// Alice's invoke is lost.
```

### Citations

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

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
    }
```

**File:** crates/apollo_gateway/src/gateway.rs (L263-276)
```rust
        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
```
