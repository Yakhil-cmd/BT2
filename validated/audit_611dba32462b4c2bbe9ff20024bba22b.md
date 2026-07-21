### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Admission for Undeployed Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function skips the `__validate__` entry-point check for invoke transactions with `nonce == 1` from undeployed accounts when `account_tx_in_pool_or_recent_block` returns `true`. That check is too broad: it returns `true` for **any** transaction from the account in the pool, not specifically a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool can immediately submit an invoke with `nonce=1` from the victim's address, carrying arbitrary calldata and an invalid signature, and the gateway will accept it without ever calling `__validate__`.

---

### Finding Description

In `skip_stateful_validations`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    ...
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

When this returns `true`, the caller sets `validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

And `perform_validations` returns immediately without calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The mempool's `account_tx_in_pool_or_recent_block` checks for **any** transaction from the account:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The code comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* [5](#0-4) 

This reasoning is **circular**. The attacker's own invoke with `nonce=1` skips validation because the victim's `deploy_account` is in the pool. Once the attacker's invoke is admitted, `account_tx_in_pool_or_recent_block` returns `true` for the attacker's own transaction too, not just the victim's `deploy_account`. There is no type-level guard ensuring the pooled transaction is a `deploy_account`.

The gateway nonce check allows `nonce=1` when `account_nonce=0` as long as `max_allowed_nonce_gap >= 1`, which is required for the deploy+invoke UX to function at all:

```rust
let max_allowed_nonce =
    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
``` [6](#0-5) 

---

### Impact Explanation

**Critical** — matches "Invalid or unauthorized Starknet transaction accepted through account validation, signature, nonce, chain id, fee/resource bound, paymaster, or account-deployment logic."

An attacker can submit an invoke transaction from any victim's undeployed address, with arbitrary calldata and an invalid/forged signature, and the gateway will accept it into the mempool without signature verification. Concrete consequences:

1. **Nonce squatting / DoS**: The attacker's invoke occupies `nonce=1` in the mempool. The victim's legitimate invoke is rejected as `DuplicateNonce`. When the batcher executes the block, the attacker's invoke fails at `__validate__` (invalid signature), the nonce is **not** incremented, and the victim's account is left deployed at `nonce=0`. The attacker can repeat this indefinitely.

2. **Free DoS**: Because a failed `__validate__` in Starknet means the transaction is rejected (not reverted), no fee is charged to the attacker. The attacker can block the victim's first invoke at zero cost.

3. **Fee-escalation replacement** (when `enable_fee_escalation=true`): The attacker can replace the victim's already-queued invoke by paying a higher fee, substituting malicious calldata for the victim's intended calldata. The malicious invoke would still fail at `__validate__` at execution time, but the victim's legitimate invoke is permanently displaced.

---

### Likelihood Explanation

**High** — the attack requires only:
1. Observing the public mempool for a `deploy_account` transaction (trivially observable).
2. Crafting an invoke with `nonce=1`, `sender_address=victim`, arbitrary calldata, and any signature.
3. Submitting it to the gateway before the victim's invoke is processed.

No privileged access, no special contract, no cryptographic capability is required.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific check that verifies a `deploy_account` transaction exists in the pool for the sender address. The mempool should expose a method such as `deploy_account_in_pool(address)` that inspects the transaction type, not merely the account's presence. This closes the circular reasoning: only a genuine `deploy_account` (which itself cannot skip `__validate__` — deploy accounts are fully executed at the gateway) should qualify as evidence that the account will exist.

---

### Proof of Concept

```
1. Victim submits RpcDeployAccountTransaction for address A (nonce=0).
   → Gateway fully executes deploy_account (constructor runs), adds to mempool.

2. Attacker observes A's deploy_account in the mempool.

3. Attacker crafts RpcInvokeTransaction:
     sender_address = A
     nonce          = 1
     calldata       = [malicious payload]
     signature      = [0x0, 0x0]   ← arbitrary, never checked

4. Gateway processes attacker's invoke:
   a. StatelessTransactionValidator::validate → passes (nonce DA mode L1, resource bounds OK)
   b. extract_state_nonce_and_run_validations:
      - get_nonce_from_state(A) → Nonce(0)
      - validate_state_preconditions: 0 ≤ 1 ≤ 0+max_allowed_nonce_gap → passes
      - validate_by_mempool: no duplicate nonce yet → passes
      - skip_stateful_validations:
            tx.nonce()==1 && account_nonce==0 → true
            account_tx_in_pool_or_recent_block(A) → true (victim's deploy_account is pooled)
            returns true  ← __validate__ SKIPPED
   c. run_validate_entry_point: validate=false → returns Ok immediately

5. Attacker's invoke (invalid signature) is added to the mempool at nonce=1 for address A.

6. Victim submits their legitimate invoke (nonce=1):
   → validate_by_mempool → MempoolError::DuplicateNonce → REJECTED
   (or replaced by attacker if fee escalation enabled and attacker pays more)

7. Batcher builds block:
   - deploy_account executes → A deployed at nonce=0
   - attacker's invoke executes → __validate__ fails (bad signature) → rejected, nonce stays 0

8. Victim's account is deployed but their first invoke was never executed.
   Attacker repeats from step 3 at zero cost (no fee for failed __validate__).
``` [7](#0-6) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L288-295)
```rust
                let max_allowed_nonce =
                    Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
                if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
                    return Err(create_error(format!(
                        "Invalid transaction nonce. Expected: {account_nonce} <= nonce <= \
                         {max_allowed_nonce}, got: {incoming_tx_nonce}."
                    )));
                }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L310-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
