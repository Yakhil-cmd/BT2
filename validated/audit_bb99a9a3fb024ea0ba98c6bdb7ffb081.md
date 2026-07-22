### Title
Signature Verification Unconditionally Skipped for Invoke(nonce=1) When Any Account Transaction Exists in Mempool — Gateway Admits Unauthorized Transactions - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the Apollo gateway's stateful transaction validator skips the `__validate__` entry point (the account's signature-verification logic) for any Invoke transaction with `nonce=1` whenever `account_tx_in_pool_or_recent_block` returns `true` for the sender address. Because this check only confirms that *some* transaction for that address exists in the mempool — not that the *incoming* invoke is authorized — an unprivileged attacker can submit a signature-forged Invoke(nonce=1) for any account that has a pending `deploy_account` transaction, bypassing gateway-level signature verification entirely. The forged transaction enters the mempool, and the victim's legitimate Invoke(nonce=1) is subsequently rejected with `DuplicateNonce`.

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function fires when three conditions are simultaneously true:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (hardcoded to exactly 1).
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).

When all three hold, it calls `account_tx_in_pool_or_recent_block` and, if that returns `true`, returns `skip = true`. [2](#0-1) 

**What `account_tx_in_pool_or_recent_block` actually checks** [3](#0-2) 

It returns `true` if the address appears in either the live `tx_pool` or the mempool's `MempoolState` (staged/committed nonces). It does **not** verify that the existing transaction is a `deploy_account`, nor does it verify anything about the *incoming* transaction's authorization.

**Effect of `skip = true`**

When `skip_validate = true`, `run_validate_entry_point` sets `ExecutionFlags { validate: false, … }`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, the `validate` flag is checked before calling `__validate__`: [5](#0-4) 

So the account's `__validate__` entry point — which is the sole mechanism for signature verification — is never called at the gateway.

**Why the mempool's own checks do not block the attack**

`validate_by_mempool` is called *before* `skip_stateful_validations`: [6](#0-5) 

The mempool's `validate_tx` only checks for `DuplicateTransaction` (same tx hash) and `NonceTooOld`/`DuplicateNonce` (same address+nonce already in pool): [7](#0-6) 

The victim's `deploy_account` has `nonce=0`; the attacker's forged invoke has `nonce=1`. These are different nonces, so `DuplicateNonce` is not triggered. The attacker's transaction passes all mempool checks.

**The flawed comment**

The inline comment claims:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is wrong. The check confirms that *some* transaction for the address is in the mempool, but it says nothing about whether the *incoming* Invoke(nonce=1) is signed by the account owner. The nonce gap (`max_allowed_nonce_gap = 200`) allows Invoke(nonce=1) to pass the gateway's nonce check even for an undeployed account, so the attacker's forged invoke reaches `skip_stateful_validations` with all preconditions satisfied. [8](#0-7) 

**Contrast with the legacy path**

The legacy `py_validator.rs` path requires the *caller* to supply the `deploy_account_tx_hash` explicitly: [9](#0-8) 

Only if `deploy_account_tx_hash.is_some()` does the skip trigger. The new gateway path replaced this explicit hash with the weaker `account_tx_in_pool_or_recent_block` check, removing the binding between the skip decision and a specific, caller-verified deploy_account transaction.

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

An attacker can submit a signature-forged Invoke(nonce=1) for any account that has a pending `deploy_account` in the mempool. The forged transaction:

- Passes all gateway stateful checks (nonce range, mempool duplicate checks).
- Bypasses `__validate__` (signature verification) entirely at the gateway.
- Enters the mempool as a live transaction.
- Causes the victim's legitimate Invoke(nonce=1) to be rejected with `DuplicateNonce` when the victim submits it.

The victim's first post-deploy invoke is blocked for the duration of one block. The attacker can repeat this every block, creating a sustained denial-of-service against any newly deployed account.

### Likelihood Explanation

**Likelihood: High.**

- The mempool is public; any observer can detect a pending `deploy_account` for a target address.
- The attack requires no privileged access, no special contract, and no funds.
- The only precondition is that the victim has submitted a `deploy_account` that has not yet been committed to a block.
- The attacker needs only to submit a single Invoke transaction with an arbitrary signature before the victim submits their own Invoke(nonce=1).

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` heuristic with an explicit binding to a specific `deploy_account` transaction hash, mirroring the legacy `py_validator.rs` approach:

```rust
// Instead of:
return mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await ...

// Require the caller to supply the deploy_account tx hash and verify it exists:
// deploy_account_tx_hash.is_some() && mempool_client.tx_in_pool(deploy_account_tx_hash).await
```

Alternatively, the mempool's `account_tx_in_pool_or_recent_block` should be replaced with a type-specific check that confirms a `deploy_account` transaction (not just any transaction) exists for the address.

### Proof of Concept

```
1. Victim submits deploy_account(sender=V, nonce=0, valid_sig)
   → Enters mempool. tx_pool.contains_account(V) = true.

2. Attacker submits invoke(sender=V, nonce=1, calldata=X, sig=ATTACKER_SIG)
   to the gateway.

3. Gateway stateful validation:
   a. get_nonce_from_state(V) → 0  (V not yet deployed)
   b. validate_nonce: 0 <= 1 <= 200 → OK
   c. validate_by_mempool:
      - DuplicateTransaction? No (different hash from deploy_account)
      - NonceTooOld? No (1 >= 0)
      - DuplicateNonce? No (deploy_account has nonce=0, attacker's invoke has nonce=1)
      → OK
   d. skip_stateful_validations:
      - tx is Invoke ✓
      - tx.nonce() == 1 ✓
      - account_nonce == 0 ✓
      - account_tx_in_pool_or_recent_block(V) = true ✓
      → skip = true
   e. run_validate_entry_point(skip=true):
      - ExecutionFlags { validate: false }
      - StatefulValidator::perform_validations: validate=false → return Ok() immediately
      - __validate__ is NEVER called
   → Attacker's forged invoke enters the mempool.

4. Victim submits invoke(sender=V, nonce=1, calldata=Y, sig=VICTIM_SIG)
   → validate_by_mempool: DuplicateNonce (attacker's invoke already at nonce=1 for V)
   → REJECTED. Victim's legitimate invoke is blocked.

5. Block is produced:
   - deploy_account(V) executes → V deployed, nonce → 1
   - attacker's invoke(nonce=1) executes → __validate__ called → fails (wrong sig) → rejected
   - commit_block: attacker's invoke removed from mempool

6. Victim resubmits invoke(nonce=1) → now accepted (mempool slot freed).
   Attacker repeats from step 2 for the next block.
``` [1](#0-0) [3](#0-2) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L405-409)
```rust
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

        Ok(())
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

**File:** crates/apollo_gateway_config/src/config.rs (L293-293)
```rust
            max_allowed_nonce_gap: 200,
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-110)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
```
