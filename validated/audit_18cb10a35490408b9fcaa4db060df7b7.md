### Title
Overly Broad `account_tx_in_pool_or_recent_block` Check Allows Signature-Validation Bypass for Any Account with Nonce=0 and a Pending Transaction - (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is intended to skip the `__validate__` entry-point call only when a `deploy_account` transaction is pending in the mempool for a not-yet-deployed account. However, the guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** account that has **any** transaction in the mempool or recent committed block, not specifically a `deploy_account`. An attacker can exploit this to inject an invoke transaction (nonce=1) for a victim account whose on-chain nonce is 0 and that has any pending transaction, bypassing the `__validate__` signature check entirely at the gateway admission layer.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` decides whether to skip the `__validate__` entry-point call:

```rust
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

The code comment claims:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is incorrect. `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

And `MempoolState::contains_account` checks:

```rust
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
``` [3](#0-2) 

This returns `true` for **any** account that has been staged, committed, or has a transaction in the pool — regardless of whether that transaction is a `deploy_account`. The `staged` map is populated whenever any transaction for an account is given to the batcher for block building.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

And `StatefulValidator::perform_validations` then short-circuits before calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [5](#0-4) 

### Impact Explanation

An attacker can inject an invoke transaction bearing an arbitrary (invalid) signature for any victim account that satisfies:
1. On-chain nonce = 0 (account not yet deployed, or a pre-deployed genesis account with nonce=0)
2. Any transaction for that account is currently staged in the batcher, in the mempool pool, or recorded in a recent committed block

The attacker's transaction passes all gateway checks — nonce range validation, `validate_by_mempool`, and `skip_stateful_validations` — and is admitted to the mempool **without any signature verification**. This matches the "High. Mempool/gateway/RPC admission accepts invalid transactions" impact category.

The most common reachable scenario is: a user submits a `deploy_account` (nonce=0) + legitimate invoke (nonce=1) pair. While the `deploy_account` is in the mempool, an attacker submits a malicious invoke (nonce=1) for the same address with an invalid signature. The attacker's transaction is admitted, occupying the nonce=1 slot and potentially displacing or racing against the victim's legitimate invoke.

### Likelihood Explanation

The trigger condition — an account with on-chain nonce=0 having any transaction in the mempool — is the **normal, intended state** for every user who uses the deploy_account + invoke UX flow (documented and tested in the integration tests). This is not a rare edge case; it is the primary use case the skip feature was built for. Any attacker watching the mempool can observe a `deploy_account` submission and immediately submit a malicious invoke for the same address.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the account. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that only returns `true` when the pending transaction for that address is of type `DeployAccount`. The skip logic should be:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .deploy_account_tx_in_pool(tx.sender_address())  // type-specific check
        .await
        ...
}
```

This mirrors the fix recommended in the Astaria report: separate the authorization conditions so that each is checked independently and precisely, rather than relying on a single overly permissive predicate.

### Proof of Concept

**Setup:**
- Victim (address `V`) submits a `deploy_account` transaction (nonce=0). It enters the mempool. `tx_pool.contains_account(V)` = `true`.
- On-chain state: `get_nonce(V)` = 0 (account not yet deployed).

**Attack:**
1. Attacker observes the `deploy_account` for `V` in the mempool.
2. Attacker constructs an `Invoke` transaction: `sender_address = V`, `nonce = 1`, `calldata = <malicious>`, `signature = <attacker's arbitrary bytes>`.
3. Attacker submits this transaction to the gateway.
4. Gateway calls `extract_state_nonce_and_run_validations`:
   - `account_nonce` = 0 ✓
   - `validate_state_preconditions`: nonce=1 is within `[0, max_gap]` ✓
   - `validate_by_mempool`: no duplicate, nonce ordering OK ✓
   - `skip_stateful_validations`: `tx.nonce() == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(V)` = `true` (deploy_account is in pool) ✓ → returns `true`
5. `run_validate_entry_point` is called with `skip_validate = true` → `execution_flags.validate = false` → `__validate__` is **never called**.
6. The attacker's transaction with an invalid signature is admitted to the mempool.

**Result:** The attacker's malicious invoke occupies nonce=1 for victim `V` in the mempool without any signature check, matching the Astaria pattern where setting `receiver = holder` caused the entire authorization condition to short-circuit. [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-177)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
