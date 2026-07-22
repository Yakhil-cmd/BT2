### Title
Gateway Admits Invoke Transactions with Invalid Signatures via Overly Broad `skip_stateful_validations` Mempool Check — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account's deploy_account has not yet been committed (UX improvement). The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction from the sender, not only a `DeployAccount`. An attacker who already has a deployed account can exploit this: submit a valid invoke(nonce=0) to seed the mempool, then immediately submit an invoke(nonce=1) carrying an **invalid signature**. The gateway skips `__validate__` for the second transaction and admits it to the mempool, violating the invariant that every queued invoke has passed account-level signature verification.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions are simultaneously true:

1. The incoming transaction is an `Invoke`.
2. The transaction nonce is exactly `1`.
3. The on-chain account nonce is `0`. [1](#0-0) 

When all three hold, the function calls `account_tx_in_pool_or_recent_block(tx.sender_address())` and returns its result as the `skip_validate` flag. [2](#0-1) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`contains_account` checks whether the address appears in the committed/staged nonce map **or** the transaction pool — it is completely agnostic to transaction type. [4](#0-3) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`, and the blockifier's `StatefulValidator` returns immediately without calling `__validate__`: [5](#0-4) [6](#0-5) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks for duplicate hashes and nonce ordering — it never inspects the signature: [7](#0-6) 

**Attack path (unprivileged, no special role required):**

| Step | Action | Gateway outcome |
|------|--------|-----------------|
| 1 | Attacker owns deployed account `A`, on-chain nonce = 0 | — |
| 2 | Submit `Invoke(nonce=0, valid_sig)` from `A` | Passes all checks; enters `tx_pool` |
| 3 | Submit `Invoke(nonce=1, INVALID_sig)` from `A` | `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → `skip_validate=true` → `__validate__` **skipped** → admitted to mempool |

The nonce=1 transaction carries an attacker-chosen, cryptographically invalid signature and is accepted by the gateway without any account-contract verification.

---

### Impact Explanation

The broken invariant is: *every invoke transaction admitted to the mempool has passed the account's `__validate__` entry point at the gateway*. After this exploit the mempool contains an invoke with an unverified (and invalid) signature. This matches:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concrete consequences:
- The invalid transaction consumes a mempool slot and network bandwidth.
- When the batcher eventually executes it, `__validate__` fails and the transaction reverts; the attacker loses the fee for the nonce=1 tx but the nonce=0 tx fee is also consumed, making the cost of the attack bounded but non-zero.
- At scale, an attacker can continuously rotate accounts (each freshly deployed, nonce=0) to flood the mempool with signature-invalid transactions at the cost of one valid nonce=0 invoke per account.

---

### Likelihood Explanation

- The attacker needs only a deployed account with on-chain nonce=0 — trivially achievable by deploying a fresh account.
- Both transactions must be submitted before the nonce=0 tx is committed to a block. Given typical block times and the mempool's nonce-gap allowance (`max_allowed_nonce_gap = 200`), this window is wide.
- No privileged access, no special contract, no off-chain infrastructure required.

---

### Recommendation

Replace the generic `account_tx_in_pool_or_recent_block` check with one that is specific to `DeployAccount` transactions. The mempool should expose a `deploy_account_tx_in_pool(address)` query, or the gateway should inspect the transaction type of the pending nonce=0 entry before granting the skip. Alternatively, restrict the skip to the case where `account_nonce == 0` **and** the account contract does not yet exist on-chain (class hash == zero), which is the only situation where `__validate__` would genuinely fail.

---

### Proof of Concept

```
# Prerequisites
# - Account A is deployed on-chain, nonce = 0
# - Gateway is running with default config (allow_client_side_proving=true, max_allowed_nonce_gap=200)

# Step 1: seed the mempool with a valid nonce=0 invoke
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<A>",
  "nonce": "0x0",
  "signature": ["<valid_r>", "<valid_s>"],   # valid ECDSA over tx_hash
  ...resource_bounds...
}
# → accepted, tx enters tx_pool for address A

# Step 2: immediately submit nonce=1 invoke with garbage signature
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<A>",
  "nonce": "0x1",
  "signature": ["0xdeadbeef", "0xdeadbeef"],  # invalid signature
  ...resource_bounds...
}
# Gateway evaluation:
#   validate_nonce:                  0 <= 1 <= 200  → OK
#   validate_by_mempool:             no duplicate, nonce valid → OK
#   skip_stateful_validations:
#     tx.nonce() == 1               → true
#     account_nonce == 0            → true (not yet committed)
#     account_tx_in_pool_or_recent_block(A) → true (nonce=0 tx is in pool)
#     returns true  →  skip_validate = true
#   run_validate_entry_point:        SKIPPED
# → transaction ADMITTED to mempool with invalid signature
```

The root cause is at: [8](#0-7) 

with the overly broad membership test delegated to: [3](#0-2)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
