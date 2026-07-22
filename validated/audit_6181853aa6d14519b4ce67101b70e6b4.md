### Title
`skip_stateful_validations` bypasses `__validate__` signature check for factory-deployed accounts with nonce=0 in state — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is intended to skip the `__validate__` entry-point call only when a `deploy_account` transaction is pending in the mempool (UX feature: deploy + invoke in one shot). Its guard condition is `tx.nonce() == 1 && account_nonce == 0 && account_tx_in_pool_or_recent_block(sender)`. However, `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction in the pool or any committed address in the mempool state — not exclusively for a `deploy_account`. An account deployed via a factory contract (`deploy` syscall) has nonce=0 in state and a class hash at its address. If such an account has a valid nonce=0 invoke already in the mempool, a subsequent nonce=1 invoke with a **forged/invalid signature** will pass all gateway checks and be admitted to the mempool with its signature never verified.

---

### Finding Description

**Broken invariant:** Every invoke transaction admitted to the mempool must have its account's `__validate__` entry point executed to verify the signature.

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function skips the blockifier `validate` call when:
1. The transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0`
3. `account_tx_in_pool_or_recent_block(sender)` returns `true`

The comment claims this is safe because the account being in the mempool implies it has a `deploy_account` or future-nonce transactions that already passed validation. This reasoning is wrong.

**`account_tx_in_pool_or_recent_block` checks any transaction, not deploy_account:** [2](#0-1) 

It returns `true` if `self.state.contains_account(address) || self.tx_pool.contains_account(address)`. The pool check is satisfied by **any** transaction type (invoke, declare, deploy_account).

**`MempoolState::contains_account` is equally broad:** [3](#0-2) 

**The skip flag is wired directly into `ExecutionFlags::validate`:** [4](#0-3) 

When `skip_validate=true`, `validate: false` is set, so the blockifier never calls `__validate__` and the signature is never checked.

**Attack path:**

1. Attacker controls account `A` deployed via a factory contract (`deploy` syscall). Account `A` has a class hash at its address and nonce=0 in state (no `deploy_account` was ever sent).
2. Attacker submits a **valid** invoke with nonce=0 from `A`. This passes `validate_nonce` (nonce=0 == account_nonce=0), passes `validate_by_mempool`, and passes `run_validate_entry_point` (account exists, signature is valid). The nonce=0 invoke enters the mempool.
3. Attacker submits a **forged** invoke with nonce=1 from `A` (arbitrary/invalid signature):
   - `validate_nonce`: account_nonce=0, tx_nonce=1, within `max_allowed_nonce_gap=200` → **PASSES** [5](#0-4) 
   - `validate_by_mempool`: different nonce, no duplicate → **PASSES**
   - `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block` returns `true` (nonce=0 invoke is in pool) → returns `true` (skip validation) [6](#0-5) 
   - `run_validate_entry_point` is called with `skip_validate=true` → `__validate__` is **never called**, signature is **never checked**
   - Forged transaction is admitted to the mempool.

**Note:** The `StatefulTransactionValidatorConfig` has a `max_nonce_for_validation_skip` field, but it is **not used** in `skip_stateful_validations` (only in `PyValidator::should_run_stateful_validations`). The gateway hardcodes `nonce == 1`. [7](#0-6) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

A transaction with an invalid/forged signature is admitted to the mempool. The blockifier will reject it during block building (since execution uses `validate=true`), but the gateway's admission invariant is broken: an unauthenticated transaction from any account deployed via a factory contract can be injected into the mempool. This can be used to:
- Spam the mempool with zero-cost forged transactions (no valid signature required)
- Displace legitimate transactions via fee escalation with forged high-tip transactions
- Cause the batcher to waste execution resources on transactions that will always fail validation

---

### Likelihood Explanation

Factory-deployed accounts (deployed via `deploy` syscall from a factory contract) are common in Starknet (e.g., multisig factories, account abstraction frameworks). Any such account with nonce=0 in state and at least one pending nonce=0 invoke in the mempool is vulnerable. The attacker only needs to know the account address and submit two transactions in sequence — no privileged access required.

---

### Recommendation

In `skip_stateful_validations`, replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the sender address. Alternatively, check that no class hash exists at the sender address in state (i.e., the account is truly not yet deployed), which is the actual precondition that makes skipping safe.

```rust
// Instead of:
return mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await ...

// Use something like:
return mempool_client.has_pending_deploy_account(tx.sender_address()).await ...
// where has_pending_deploy_account checks specifically for a DeployAccount tx in the pool
```

---

### Proof of Concept

```
State:
  Account A: class_hash = 0xABC (deployed via factory), nonce = 0

Step 1: Submit valid invoke (nonce=0, valid signature) from A
  → validate_nonce: 0 == 0 ✓
  → run_validate_entry_point: __validate__ runs, signature OK ✓
  → Mempool: A has nonce=0 invoke in pool

Step 2: Submit forged invoke (nonce=1, INVALID signature) from A
  → validate_nonce: 0 <= 1 <= 200 ✓
  → validate_by_mempool: nonce=1 != nonce=0 (no duplicate) ✓
  → skip_stateful_validations:
      tx.nonce() == 1 ✓
      account_nonce == 0 ✓
      account_tx_in_pool_or_recent_block(A) == true (nonce=0 invoke in pool) ✓
      → returns true (SKIP VALIDATION)
  → run_validate_entry_point: validate=false, __validate__ NEVER CALLED
  → Forged transaction admitted to mempool ✓
```

### Citations

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L276-299)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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
