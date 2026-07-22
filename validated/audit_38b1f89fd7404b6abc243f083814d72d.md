### Title
Gateway `skip_stateful_validations` Bypasses Account Signature Verification for Invoke Transactions with Nonce=1 — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point (the signature-verification step) for any Invoke transaction with `nonce=1` sent from an address that has **any** transaction present in the mempool. An attacker who observes a victim's pending `deploy_account` transaction can immediately submit an Invoke with `nonce=1` and an arbitrary/forged signature from the victim's address. The gateway accepts it without ever calling `__validate__`, injecting an invalid transaction into the mempool and displacing the victim's legitimate Invoke.

---

### Finding Description

**Step 1 — The skip condition.**

`skip_stateful_validations` (lines 429–461) returns `true` when all three hold:

```
tx is Invoke  AND  tx.nonce() == 1  AND  account_nonce == 0
AND  account_tx_in_pool_or_recent_block(sender) == true
``` [1](#0-0) 

**Step 2 — The pool check is not type-specific.**

`account_tx_in_pool_or_recent_block` returns `true` if the address has **any** transaction in the pool or any committed block — it does not verify that the pooled transaction is specifically a `deploy_account`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

As soon as a victim's `deploy_account` (nonce=0) lands in the pool, `tx_pool.contains_account(victim_address)` becomes `true`.

**Step 3 — Skipping validation disables `__validate__`.**

When `skip_validate=true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside `StatefulValidator::perform_validations`, the `__validate__` call is gated on this flag:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [4](#0-3) 

`__validate__` is the account contract's only mechanism for verifying the transaction signature. When it is not called, the signature field is never checked.

**Step 4 — Nonce and fee checks still pass for the attacker.**

`validate_state_preconditions` runs before the skip decision. With `account_nonce=0` and `tx_nonce=1`, the nonce range check `account_nonce <= tx_nonce <= account_nonce + max_allowed_nonce_gap` passes for any `max_allowed_nonce_gap >= 1`: [5](#0-4) 

The attacker only needs to supply resource bounds that satisfy the stateless and stateful fee threshold checks — no valid signature is required.

**Step 5 — The attacker's transaction is admitted to the mempool.**

After `skip_stateful_validations` returns `true`, `run_validate_entry_point` succeeds (no `__validate__` call), and the gateway proceeds to call `mempool_client.add_tx`. The attacker's Invoke with a forged signature is now in the mempool at `(victim_address, nonce=1)`. [6](#0-5) 

**Step 6 — Victim's legitimate Invoke is displaced.**

The mempool enforces one transaction per `(address, nonce)`. The victim's own Invoke (nonce=1, valid signature) either:
- Is rejected as a duplicate if the attacker's transaction arrived first, or
- Must fee-escalate past the attacker's transaction to replace it.

The attacker's transaction will fail during block execution (the batcher calls `__validate__` with `validate=true`), but by then the victim's transaction has been evicted from the mempool.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions.**

Any Invoke transaction with `nonce=1` from an undeployed account whose `deploy_account` is pending in the mempool is admitted without signature verification. The attacker can:

1. Displace the victim's legitimate Invoke from the mempool.
2. Force the victim to resubmit with a higher fee (fee escalation) to reclaim their nonce slot.
3. Repeat the attack indefinitely at low cost (the attacker's transaction fails during execution, but the mempool slot is already occupied).

The broken invariant is: **the gateway must not admit an Invoke transaction whose account signature has not been verified**.

---

### Likelihood Explanation

**Likelihood: Medium-High.**

- The attack requires only that the victim has submitted a `deploy_account` transaction (a common, observable mempool event).
- The attacker needs no privileged access — only the ability to submit transactions to the public gateway endpoint.
- The attack window is the time between the victim's `deploy_account` entering the mempool and the victim's Invoke being submitted.
- The `deploy_account + invoke` UX pattern is explicitly supported and documented, making it a predictable target.

---

### Recommendation

1. **Restrict the pool check to `deploy_account` transactions only.** The `account_tx_in_pool_or_recent_block` check should be replaced with a dedicated `has_pending_deploy_account(address)` query that only returns `true` when a `deploy_account` transaction (not just any transaction) is present in the pool for that address.

2. **Alternatively, verify the signature even when skipping the entry point.** The gateway could perform a lightweight off-chain ECDSA/Stark signature check against the account's expected public key before skipping `__validate__`, ensuring the transaction is at least signed by the correct key.

3. **Limit the skip to nonce=1 only when a `deploy_account` with the matching contract address is in the pool.** The `InternalRpcDeployAccountTransaction` already carries the computed `contract_address`; the mempool can expose a typed query.

---

### Proof of Concept

```
1. Victim generates a new keypair and computes their account address A.
2. Victim submits deploy_account(class_hash=C, salt=S, ...) → accepted into mempool.
   Now: mempool.tx_pool.contains_account(A) == true.

3. Attacker submits:
     Invoke {
       sender_address: A,
       nonce: 1,
       calldata: [<arbitrary>],
       signature: [0x0, 0x0],   // forged / empty
       resource_bounds: <valid bounds>,
     }

4. Gateway stateful validation:
   - get_nonce_from_state(A) → 0  (account not deployed)
   - validate_state_preconditions: nonce 1 in [0, 0+gap] ✓, fee bounds ✓
   - validate_by_mempool: no duplicate, fee escalation OK ✓
   - skip_stateful_validations:
       tx.nonce()==1 ✓, account_nonce==0 ✓
       account_tx_in_pool_or_recent_block(A) → true (deploy_account is pooled) ✓
       → returns true (skip)
   - run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator::perform_validations → returns Ok() without calling __validate__

5. Attacker's Invoke (forged signature) is added to mempool at (A, nonce=1).

6. Victim submits their own Invoke (nonce=1, valid signature):
   - mempool rejects as DuplicateNonce, or requires fee escalation to replace.

7. Attacker's transaction is eventually picked up by the batcher, __validate__ is
   called with validate=true, fails (invalid signature), transaction is rejected.
   Victim's transaction is no longer in the mempool.
``` [7](#0-6) [2](#0-1) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-84)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```
