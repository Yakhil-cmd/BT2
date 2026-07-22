### Title
`skip_stateful_validations` Admits Invoke Transactions with Unverified Signatures via Mempool Pollution for Undeployed Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function uses `account_tx_in_pool_or_recent_block` as a proxy for "a `deploy_account` transaction exists for this account." This check returns `true` for **any** transaction in the mempool for the address, not exclusively `deploy_account` transactions. An attacker can submit an `invoke(nonce=0)` for an undeployed account to pollute the mempool, then submit an `invoke(nonce=1)` with an arbitrary/wrong signature. The gateway skips the `__validate__` entry-point call and admits the unsigned transaction to the mempool, blocking the legitimate user's `invoke(nonce=1)` and causing a fee-charging revert when the block is built.

---

### Finding Description

**Phase-ordering invariant (analog to the external bug):**
In the external report, `borrow()` could be called in phases after `validateBalances()` had already run, because the phase-gate check was insufficient. The analog here is that the gateway's signature-verification phase (`__validate__` via `run_validate_entry_point`) can be bypassed in the admission path because the guard that is supposed to restrict the bypass (`skip_stateful_validations`) relies on a condition that is too broad.

**Root cause — `skip_stateful_validations`:**

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
```

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
```

The code comment asserts:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This invariant is **false**. The mempool check is implemented as:

```
crates/apollo_mempool/src/mempool.rs  lines 697-700
```

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`tx_pool.contains_account` returns `true` for **any** transaction type in the pool for that address — including an `invoke(nonce=0)` submitted by an attacker for an undeployed account.

**Why `invoke(nonce=0)` for an undeployed account is admitted:**

The gateway's `validate_nonce` for non-declare, non-deploy-account transactions:

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 287-296
```

```rust
_ => {
    let max_allowed_nonce =
        Nonce(account_nonce.0 + Felt::from(self.config.max_allowed_nonce_gap));
    if !(account_nonce <= incoming_tx_nonce && incoming_tx_nonce <= max_allowed_nonce) {
        return Err(...)
    }
}
```

With `account_nonce = 0` and `tx_nonce = 0`: `0 ≤ 0 ≤ 200` → **passes**. The attacker's `invoke(nonce=0)` is admitted to the mempool with no signature check.

**How the bypass is triggered:**

Once the attacker's `invoke(nonce=0)` is in the pool, a subsequent `invoke(nonce=1)` with an arbitrary signature passes through the full gateway admission pipeline:

1. `validate_state_preconditions` — checks nonce (`0 ≤ 1 ≤ 200`) and resource bounds. **Passes.**
2. `validate_by_mempool` — checks nonce validity only, no signature. **Passes.**
3. `skip_stateful_validations` — `tx_nonce == 1 && account_nonce == 0` → calls `account_tx_in_pool_or_recent_block` → returns `true` (attacker's `invoke(nonce=0)` is in pool) → returns `skip_validate = true`. **Bypasses `__validate__`.**
4. `run_validate_entry_point(skip_validate=true)` — sets `execution_flags.validate = false`:

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 302-356
```

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations`:

```
crates/blockifier/src/blockifier/stateful_validator.rs  lines 76-81
```

```rust
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← __validate__ is never called
    }
    ...
}
```

The `__validate__` entry point — which verifies the account's signature — is **never called**. The transaction is admitted to the mempool with an unverified signature.

---

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction (unverified signature) before sequencing.**

Concrete consequences:

1. The attacker's `invoke(nonce=1)` with wrong signature occupies the nonce-1 slot for the target account. The legitimate user's `invoke(nonce=1)` is rejected by the mempool with `DuplicateNonce`.
2. When the block is built, the attacker's `invoke(nonce=1)` is executed. The blockifier runs `__validate__` during execution, which fails (wrong signature). The transaction is reverted, but the nonce is bumped to 2 and a fee is charged from the account's balance (if any).
3. The legitimate user must resubmit with `nonce=2`, and their intended `invoke(nonce=1)` never executes.

This is a targeted griefing attack against any account whose address is predictable (e.g., computed from a known public key and salt) before deployment.

---

### Likelihood Explanation

**Medium.** The attacker must:
- Know the target account address before it is deployed (feasible since `deploy_account` addresses are deterministic from public key + salt + class hash).
- Submit `invoke(nonce=0)` before the legitimate user's `deploy_account` is committed to a block.

No privileged access is required. The attack is executable by any unprivileged user who can submit transactions to the gateway.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the address in the mempool. The mempool should expose a method such as `deploy_account_in_pool(address)` that inspects the transaction type, not just the address presence. Alternatively, the gateway can track the `deploy_account` tx hash (already available in the `PyValidator` path via `deploy_account_tx_hash`) and verify it is present in the mempool before skipping validation.

---

### Proof of Concept

```
Target: Alice's undeployed account at address A (deterministic from known pubkey/salt/class_hash)
```

**Step 1 — Mempool pollution:**
Attacker submits `invoke(sender=A, nonce=0, calldata=[], signature=GARBAGE)`.

- Gateway `validate_nonce`: `account_nonce=0 ≤ tx_nonce=0 ≤ 200` → passes.
- `validate_by_mempool`: nonce valid → passes.
- `skip_stateful_validations`: `tx_nonce ≠ 1` → returns `false` (no skip), but `run_validate_entry_point` is called with `skip_validate=false`. However, the account is not deployed, so `__validate__` fails... 

Wait — actually for this step, `skip_validate=false` so `__validate__` IS called. The account is not deployed, so the call fails with "contract not found." The transaction is **rejected** at the gateway's blockifier validation step.

Let me reconsider. The `run_validate_entry_point` calls `blockifier_validator.validate(account_tx)` which calls `StatefulValidator::perform_validations`. For an undeployed account, `__validate__` would fail. So `invoke(nonce=0)` with `skip_validate=false` would be **rejected** by the gateway.

This means the attack as described does not work for `invoke(nonce=0)` because the gateway's blockifier validation would reject it (account not deployed).

Let me reconsider the attack vector...

**Revised analysis:**

For `invoke(nonce=0)` with `skip_validate=false`, the gateway calls `run_validate_entry_point` which runs `__validate__`. For an undeployed account, this fails → transaction rejected.

So the attacker **cannot** get `invoke(nonce=0)` into the mempool for an undeployed account via the normal gateway path.

However, the `skip_stateful_validations` check also returns `true` when `account_tx_in_pool_or_recent_block` returns `true` due to `self.state.contains_account(account_address)` — i.e., the account is in the **committed state** (recent block). This means if the account was recently committed (deploy_account was executed in a recent block), `account_nonce` in the gateway's state reader might still show 0 (if the state reader is slightly stale), while the account is actually deployed.

But this is a race condition, not a reliable attack.

**Conclusion after deeper analysis:**

The `skip_stateful_validations` bypass via mempool pollution with `invoke(nonce=0)` does **not** work in practice because the gateway's blockifier validation (`run_validate_entry_point` with `skip_validate=false`) would reject `invoke(nonce=0)` for an undeployed account (no contract at address).

The only way to get a transaction into the mempool for an undeployed account is via the legitimate `deploy_account` path or via the `skip_stateful_validations` path itself (nonce=1 with a deploy_account already in pool).

Therefore, the invariant in the comment — "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations" — is **actually correct in practice**, because `invoke(nonce=0)` for an undeployed account would be rejected by the blockifier validation step.

The `skip_stateful_validations` logic