### Title
Gateway Skips `__validate__` Signature Verification for Nonce-1 Invoke Transactions When Deploy-Account Is Pending in Mempool - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally skips the `__validate__` entry point — the account's own signature-verification logic — for any invoke transaction with `nonce == 1` when the account's on-chain nonce is `0` and the account address appears in the mempool. An unprivileged attacker who pre-funds an address and submits a valid `deploy_account` transaction can immediately follow with an invoke transaction carrying a completely invalid (or absent) signature, and the gateway will admit it to the mempool without ever verifying the signature.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`:

```
skip_stateful_validations (lines 429-461)
  if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
      return mempool_client
          .account_tx_in_pool_or_recent_block(tx.sender_address())
          ...
  }
```

When this returns `true`, `run_validate_entry_point` sets `execution_flags.validate = !skip_validate = false`:

```
execution_flags = ExecutionFlags { ..., validate: !skip_validate, ... };  // line 312
```

Inside `StatefulValidator::perform_validations` (blockifier, `stateful_validator.rs` lines 68-96), for an invoke transaction the code path is:

```rust
tx.perform_pre_validation_stage(self.state(), &tx_context)?;  // nonce + fee + balance
if !tx.execution_flags.validate {
    return Ok(());   // ← returns here; __validate__ is never called
}
// `__validate__` call.  ← never reached
```

`perform_pre_validation_stage` checks nonce, fee bounds, and balance, but **not** the account's `__validate__` entry point. The signature field of the transaction is never inspected at the gateway level.

`account_tx_in_pool_or_recent_block` (mempool, line 697-700) returns `true` whenever the address appears in either the live tx pool or the committed-block state:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

A valid `deploy_account` transaction for address A is sufficient to satisfy this check, because submitting it places A in the mempool's tx pool.

### Impact Explanation

The gateway admits an invoke transaction with an **arbitrary, attacker-controlled signature** to the mempool. This directly violates the admission invariant that every transaction in the mempool has passed signature/`__validate__` verification. The transaction will revert at execution time (when `__validate__` is finally called with `strict_nonce_check = true`), but it is sequenced into a block, consumes block bouncer capacity, and forces the protocol to include a reverted transaction. An attacker can repeat this for every new `deploy_account` they submit, scaling the attack across many freshly-funded addresses.

Impact: **High — Mempool/gateway admission accepts an invalid transaction (invalid signature) before sequencing.**

### Likelihood Explanation

The trigger is fully unprivileged:
1. Compute a fresh contract address (deterministic from salt + class hash).
2. Transfer STRK to that address (standard ERC-20 transfer, no permissions needed).
3. Submit a valid `deploy_account` transaction — this places the address in the mempool.
4. Immediately submit an invoke transaction with `nonce = 1` and a garbage signature.

No special role, no governance access, no privileged key is required.

### Recommendation

The skip-validation path should not bypass signature verification entirely. Two options:

1. **Cryptographic pre-check**: Before skipping `__validate__`, perform a lightweight off-chain ECDSA/Stark-curve signature check against the transaction hash using the public key embedded in the `constructor_calldata` of the pending `deploy_account` transaction. This is feasible because the account class and constructor arguments are already known from the mempool entry.

2. **Defer, don't skip**: Instead of skipping `__validate__` at the gateway, defer the invoke transaction's admission until the `deploy_account` transaction has been executed (i.e., the account exists on-chain). This removes the UX shortcut but eliminates the admission bypass entirely.

### Proof of Concept

```
1. Attacker picks salt S, class_hash C → derives address A = calculate_contract_address(S, C, ...)
2. Attacker sends 1 STRK to address A (standard transfer, no permissions needed)
3. Attacker submits RpcDeployAccountTransactionV3 for address A with valid signature
   → gateway admits it; mempool.tx_pool now contains_account(A) == true
4. Attacker submits RpcInvokeTransactionV3 for address A:
     nonce = 1
     signature = [0xDEAD, 0xBEEF]   ← completely invalid
     resource_bounds.l2_gas.max_price_per_unit ≥ previous_block_l2_gas_price  (passes stateless check)
5. Gateway stateful path:
   a. get_nonce_from_state(A) → Nonce(0)          (account not yet deployed)
   b. validate_state_preconditions:
        validate_resource_bounds → passes (gas price ≥ threshold)
        validate_nonce: 0 ≤ 1 ≤ 0+max_gap → passes
   c. validate_by_mempool → passes (no duplicate, nonce gap OK)
   d. skip_stateful_validations:
        tx.nonce()==1 && account_nonce==0 → true
        account_tx_in_pool_or_recent_block(A) → true (deploy_account is in pool)
        returns true  ← SKIP __validate__