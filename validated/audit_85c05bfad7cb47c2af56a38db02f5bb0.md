After thorough analysis of the gateway validation pipeline, I found a real analog to the broken-voting pattern in the `skip_stateful_validations` function.

---

### Title
`skip_stateful_validations` Bypasses Signature Verification for Any Invoke Targeting an Account with a Pending Deploy-Account — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (account signature check) for any invoke transaction with `nonce == 1` sent to an account whose committed nonce is `0`, as long as `account_tx_in_pool_or_recent_block` returns `true`. The check does not verify that the invoke originates from the same key-holder as the pending deploy-account. Any third party who knows a target account's address can submit an invoke with an arbitrary/invalid signature and have it admitted to the mempool without signature verification.

### Finding Description

In `run_pre_validation_checks`, the gateway calls three sub-checks in sequence:

1. `validate_state_preconditions` — checks resource bounds and nonce range
2. `validate_by_mempool` — checks mempool-specific rules (nonce gaps, fee escalation)
3. `skip_stateful_validations` — decides whether `__validate__` should be skipped [1](#0-0) 

`skip_stateful_validations` returns `true` (skip) when:

```
tx.nonce() == Nonce(Felt::ONE)  &&  account_nonce == Nonce(Felt::ZERO)
    &&  account_tx_in_pool_or_recent_block(sender_address) == true
``` [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`, so `__validate__` is never executed: [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check is the broken invariant. The code comment acknowledges the looseness: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* The check does not distinguish between a deploy-account submitted by the account owner and any other transaction. Any caller who knows the target address can trigger the skip.

Additionally, the `StatefulTransactionValidatorConfig` exposes a `max_nonce_for_validation_skip` field intended to bound this skip, but `skip_stateful_validations` is a free function that never receives `self.config` — it hardcodes `Nonce(Felt::ONE)` directly. The config field is dead code in this path. [4](#0-3) 

Compare with the legacy `PyValidator::should_run_stateful_validations`, which correctly reads `self.max_nonce_for_validation_skip`: [5](#0-4) 

The new gateway path ignores this bound entirely.

### Impact Explanation

An attacker can submit an invoke transaction with a completely invalid/arbitrary signature for any account that has a pending deploy-account in the mempool. Steps 1–2 of `run_pre_validation_checks` pass (nonce=1 is within the allowed gap, resource bounds are valid). Step 3 returns `true` (skip). The `__validate__` entry point is never called. The invalid transaction is admitted to the mempool.

- The attacker can use a higher fee to displace the legitimate owner's nonce=1 invoke via fee escalation.
- When the block executes, the attacker's invoke fails at `__validate__` (invalid signature), consuming block space and evicting the owner's transaction from the mempool.
- The account owner's first post-deployment invoke is silently lost; they must detect and resubmit.
- An operator who sets `max_nonce_for_validation_skip: Nonce(Felt::ZERO)` to disable this feature entirely finds the config has no effect — the skip still fires.

**Impact category**: High — Mempool/gateway admission accepts invalid (unauthorized) transactions before sequencing.

### Likelihood Explanation

- Every account that submits a deploy-account transaction is a target.
- The account address is deterministic and publicly observable in the mempool.
- No special privilege is required; any network participant can submit the malicious invoke.
- The attack window is the entire time the deploy-account sits in the mempool (potentially many blocks).

### Recommendation

1. **Restrict the skip to the submitter's own pair**: Record the deploy-account's sender address when it enters the mempool and only skip `__validate__` for invokes whose `sender_address` matches that recorded entry, not for any account present in the pool.
2. **Wire `max_nonce_for_validation_skip` into `skip_stateful_validations`**: Pass `self.config.max_nonce_for_validation_skip` to the function and replace the hardcoded `Nonce(Felt::ONE)` comparison with `tx.nonce() <= max_nonce_for_validation_skip`, so operators can disable or tighten the skip.
3. **Narrow `account_tx_in_pool_or_recent_block`**: Add a variant that checks specifically for a pending deploy-account (not any transaction) for the given address.

### Proof of Concept

```
1. Alice submits DeployAccount for address A (nonce=0) → enters mempool.
   account_tx_in_pool_or_recent_block(A) now returns true.

2. Attacker submits Invoke(sender=A, nonce=1, signature=<garbage>, fee=HIGH).

3. Gateway stateful validation:
   a. validate_state_preconditions: account_nonce=0, tx_nonce=1 → 0 ≤ 1 ≤ 200 → OK
   b. validate_by_mempool: no prior nonce-1 tx for A → OK
   c. skip_stateful_validations:
        tx.nonce() == 1  ✓
        account_nonce == 0  ✓
        account_tx_in_pool_or_recent_block(A) == true  ✓
      → returns true (skip __validate__)
   d. run_validate_entry_point called with validate=false → __validate__ NOT called.

4. Attacker's invoke (invalid signature) enters mempool.
   If fee > Alice's legitimate nonce-1 invoke, it displaces Alice's tx.

5. Block executes:
   - DeployAccount(A) succeeds, A is deployed.
   - Attacker's Invoke(A, nonce=1) runs → __validate__ fails → tx reverts.
   - Alice's legitimate invoke is gone from the mempool; she must resubmit.
``` [6](#0-5)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
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

**File:** crates/apollo_gateway_config/src/config.rs (L276-300)
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
}
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-120)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
```
