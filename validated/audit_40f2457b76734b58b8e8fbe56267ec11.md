### Title
`skip_stateful_validations` Admits Invoke Transactions With Arbitrary Signatures by Checking Any Mempool Presence Instead of a Specific `deploy_account` - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to skip the `validate` entry-point call for an invoke transaction with nonce=1 when the account is not yet deployed on-chain, as a UX convenience for the deploy_account + invoke pair. However, the guard condition uses `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction belonging to that account in the mempool — not exclusively a `deploy_account` transaction. An attacker who has placed any valid transaction for an account into the mempool can then submit a second invoke transaction with nonce=1 carrying an **arbitrary or invalid signature**, and the gateway will skip signature validation entirely and admit it to the mempool.

---

### Finding Description

The relevant code path is:

**`run_pre_validation_checks`** calls `skip_stateful_validations` after nonce/resource-bound checks:

```rust
// stateful_transaction_validator.rs lines 399-410
async fn run_pre_validation_checks(...) -> ... {
    self.validate_state_preconditions(executable_tx, account_nonce).await?;
    validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
    let skip_validate =
        skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
    Ok(skip_validate)
}
```

**`skip_stateful_validations`** (lines 429–461) returns `true` — meaning "skip the validate entry point" — whenever:
1. The incoming transaction is an `Invoke` with `nonce == 1`, AND
2. The account's on-chain nonce is `0` (not yet deployed), AND
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

```rust
// stateful_transaction_validator.rs lines 434-457
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    ...
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The comment in the code itself acknowledges the over-broad check: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."*

The second branch of that disjunction is the problem. The function does not verify that the mempool entry is specifically a `deploy_account` transaction. Any transaction for that sender — including a prior invoke with a future nonce — satisfies the condition.

**`run_validate_entry_point`** then uses the returned flag to suppress the validate entry point:

```rust
// stateful_transaction_validator.rs lines 311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

When `skip_validate = true`, `validate = false`, so `StatefulValidator::validate` is called with the validate entry point disabled. The account's `__validate__` function — which checks the transaction signature — is never executed during gateway admission.

**Attack scenario:**

1. Attacker controls account `A` (or simply knows its address and class hash). They submit a valid `deploy_account` transaction for `A` (nonce=0). This passes all validations and enters the mempool.
2. Attacker immediately submits an `Invoke` transaction for `A` with nonce=1 and a **completely invalid/forged signature**.
3. Gateway checks: nonce=1 ✓, on-chain nonce=0 ✓, `account_tx_in_pool_or_recent_block(A)` = `true` (the deploy_account is there) ✓ → `skip_validate = true`.
4. The `validate` entry point is not called. The invalid invoke is admitted to the mempool.

During block execution the batcher constructs the transaction via `new_for_sequencing` with `validate: true` (the default), so the validate entry point will be called and the transaction will revert. However, the gateway invariant — *every admitted invoke must have passed signature validation* — is broken at the admission layer.

---

### Impact Explanation

The gateway's stateful validation is the primary admission gate for the mempool. Bypassing the `validate` entry point at this stage means:

- **Invalid (unsigned or arbitrarily signed) invoke transactions are admitted to the mempool**, violating the admission invariant.
- The mempool can be flooded with signature-invalid transactions that consume queue capacity and displace legitimate transactions.
- Each such transaction will be picked up by the batcher, executed, revert during the validate phase, and be included in a block as a failed transaction — consuming block bouncer capacity and L2 gas budget.
- If the attacker can sustain a stream of deploy_account + invalid-invoke pairs, they can continuously degrade sequencer throughput with zero valid economic cost (the deploy_account itself can be a minimal-fee transaction; the invalid invoke never pays fees because it reverts before fee transfer).

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

The trigger is entirely unprivileged. Any user can:
- Compute a counterfactual account address (no on-chain state required).
- Submit a `deploy_account` transaction (standard operation).
- Immediately submit an invoke with nonce=1 and a garbage signature.

No special access, no privileged role, no race condition against the sequencer itself is required. The window is open for as long as the `deploy_account` remains in the mempool (i.e., until it is included in a block and the on-chain nonce advances to 1, at which point the condition `account_nonce == 0` no longer holds). The attacker can repeat the cycle with a fresh account address.

---

### Recommendation

Replace the over-broad `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **`deploy_account` transaction** for the sender is present in the mempool. The mempool client interface should expose a dedicated query such as `deploy_account_tx_in_pool(sender_address) -> bool`. Only when that returns `true` should the validate entry point be skipped for the nonce=1 invoke.

If the mempool cannot distinguish transaction types, the alternative is to never skip the validate entry point at the gateway layer and instead rely on the blockifier's `strict_nonce_check = false` path to handle the ordering — accepting that the validate call will fail for the invoke if the deploy_account has not yet been executed, and letting the mempool re-validate once the deploy_account is committed.

---

### Proof of Concept

```
1. Compute counterfactual address A for class_hash C, salt S, constructor_calldata D.

2. Submit deploy_account tx:
     type:       DEPLOY_ACCOUNT_V3
     sender:     A
     nonce:      0
     class_hash: C
     signature:  <valid ECDSA over the deploy_account tx hash>
   → Gateway: passes all checks, enters mempool.

3. Submit invoke tx:
     type:       INVOKE_V3
     sender:     A
     nonce:      1
     calldata:   <arbitrary>
     signature:  [0x41, 0x41, 0x41]   ← garbage, not a valid ECDSA signature

4. Gateway stateful validation for the invoke:
     account_nonce = 0  (A not yet on-chain)
     tx.nonce()    = 1
     → skip_stateful_validations queries account_tx_in_pool_or_recent_block(A)
     → returns true  (deploy_account from step 2 is in the mempool)
     → skip_validate = true
     → run_validate_entry_point called with validate=false
     → __validate__ is NEVER called
     → invoke admitted to mempool with garbage signature

5. Batcher picks up both transactions. deploy_account executes successfully.
   Invoke executes with validate=true; __validate__ is called; signature check
   fails; transaction reverts. Block includes a reverted invoke consuming
   bouncer capacity.

6. Repeat from step 1 with a fresh address to sustain the attack.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-315)
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

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-411)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
    }
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```
