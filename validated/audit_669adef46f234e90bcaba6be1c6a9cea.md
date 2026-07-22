Looking at the external report's core invariant — **state settlement should be atomic with ownership transfer** — I need to find where the sequencer admits a transaction without completing all required validation steps atomically.

The analog maps to: **signature verification (`__validate__`) should be atomic with mempool admission**. Let me trace the exact code path.

The `skip_stateful_validations` function in `crates/apollo_gateway/src/stateful_transaction_validator.rs` explicitly skips the `__validate__` entry point for invoke transactions with nonce=1 when the account is not yet deployed. When `skip_validate=true` is returned, `run_validate_entry_point` sets `execution_flags.validate = false`, and `StatefulValidator::perform_validations` returns after `perform_pre_validation_stage` without ever calling `__validate__`. The signature is never verified at admission time.

The `account_tx_in_pool_or_recent_block` check only verifies that *any* transaction exists in the pool for that address — it does not verify that the transaction is a deploy_account, nor that it was submitted by the same party as the incoming invoke. Combined with the mempool's fee-escalation logic (which allows a higher-fee transaction to replace an existing same-nonce transaction), an attacker can submit a bad-signature invoke for any address that has a pending deploy_account, replacing the legitimate user's invoke.

---

### Title
Gateway Admits Invoke Transactions with Unverified Signatures via `skip_stateful_validations` UX Bypass — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
The `skip_stateful_validations` function skips the `__validate__` entry point (signature verification) for invoke transactions with nonce=1 when the account is not yet deployed and any transaction for that address exists in the mempool. An unprivileged attacker can exploit this to inject an invoke with an invalid signature for any not-yet-deployed account that has a pending deploy_account, bypassing the gateway's only signature-verification gate and enabling fee-escalation griefing against legitimate users.

### Finding Description

`extract_state_nonce_and_run_validations` orchestrates the gateway's stateful validation in three steps:

```
account_nonce = get_nonce_from_state(...)
skip_validate = run_pre_validation_checks(...)   // includes skip_stateful_validations
run_validate_entry_point(..., skip_validate)
```

`skip_stateful_validations` returns `true` (skip) when all three conditions hold:

1. The transaction is an `Invoke` with `tx.nonce() == Nonce(Felt::ONE)`
2. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:437
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
```

When `skip_validate = true`, `run_validate_entry_point` constructs `ExecutionFlags` with `validate: false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations`, when `validate = false`, execution returns immediately after `perform_pre_validation_stage` — the `__validate__` entry point is never called:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:78-81
tx.perform_pre_validation_stage(self.state(), &tx_context)?;
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call — NEVER REACHED when skip_validate=true
```

`perform_pre_validation_stage` only checks nonce, fee bounds, and proof facts — it does **not** verify the signature. The signature is exclusively verified inside `__validate__`, which is skipped.

The `account_tx_in_pool_or_recent_block` check is:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` for **any** transaction in the pool for that address — not specifically a deploy_account submitted by the same party. The code comment claims this implies a deploy_account exists, but this is not enforced.

The `validate_by_mempool` call (which runs before `skip_stateful_validations`) only checks for duplicate hashes and fee escalation — it does not verify signatures:

```rust
// crates/apollo_mempool/src/mempool.rs:402-408
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
```

**Attack scenario:**

1. Alice submits `deploy_account` (nonce=0) + `invoke` (nonce=1) for her new account address X.
2. Attacker observes Alice's `deploy_account` in the mempool.
3. Attacker submits `invoke(nonce=1)` for address X with an invalid signature and a fee slightly higher than Alice's invoke.
4. Gateway's `validate_by_mempool` passes (fee escalation allowed).
5. `skip_stateful_validations` returns `true` (nonce=1, account_nonce=0, deploy_account in pool).
6. `run_validate_entry_point` is called with `skip_validate=true` — `__validate__` is **never called**.
7. Attacker's bad-signature invoke is admitted to the mempool, replacing Alice's invoke via fee escalation.
8. Batcher processes the block: `deploy_account` succeeds; attacker's invoke reaches `__validate__` on the now-deployed account, fails signature verification, and is reverted.
9. Alice's invoke was evicted from the mempool; she must resubmit.
10. Attacker repeats steps 3–9 indefinitely, preventing Alice's invoke from ever being sequenced.

### Impact Explanation

The gateway admits an invalid transaction (invoke with unverified signature) to the mempool. This directly satisfies: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

The concrete harm is a persistent griefing/DoS attack against any user using the deploy_account + invoke UX flow. The attacker can evict the legitimate user's invoke from the mempool on every block, indefinitely, at the cost of only the reverted-transaction fee per block.

### Likelihood Explanation

The preconditions are trivially observable and achievable:
- A pending `deploy_account` in the mempool is publicly visible.
- The attacker only needs to set a fee marginally higher than the victim's invoke.
- No privileged access, special keys, or insider knowledge is required.
- The attack window lasts from when the `deploy_account` enters the mempool until it is executed (potentially many blocks).

### Recommendation

1. **Restrict fee escalation for the skip-validate path**: When `skip_validate=true`, disallow fee escalation so the first admitted invoke(nonce=1) cannot be replaced by a higher-fee invoke that bypasses `__validate__`.
2. **Tighten the skip condition**: Instead of checking `account_tx_in_pool_or_recent_block` (any tx), verify that a `deploy_account` specifically exists in the pool for that address, reducing the attack surface.
3. **Bind the skip to the submitter**: Track that the invoke and the deploy_account were submitted in the same gateway request (e.g., same connection or batch), so third-party invokes cannot exploit the skip.

### Proof of Concept

```
// Precondition: Alice has submitted deploy_account for address X (nonce=0).
// Mempool state: { X: [deploy_account(nonce=0)] }

// Attacker submits:
invoke_tx =