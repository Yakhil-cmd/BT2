### Title
Gateway `skip_stateful_validations` admits invoke transactions with arbitrary signatures when a deploy_account is pending in the mempool - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validation path skips the blockifier `__validate__` entry point (account signature verification) for invoke transactions with nonce=1 when `account_tx_in_pool_or_recent_block` returns `true`. The check is too broad: it returns `true` for **any** transaction from the account in the mempool, not specifically a deploy_account. An unprivileged attacker who observes a victim's pending deploy_account can front-run with an invoke carrying a garbage signature, which is admitted to the mempool without signature verification.

---

### Finding Description

In `extract_state_nonce_and_run_validations`, the gateway calls `run_pre_validation_checks` which calls `skip_stateful_validations`: [1](#0-0) 

`skip_stateful_validations` returns `true` (skip `__validate__`) when all three conditions hold: [2](#0-1) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`, so the account's `__validate__` entry point — the only place the signature is cryptographically verified — is never called: [3](#0-2) 

The third condition uses `account_tx_in_pool_or_recent_block`, which returns `true` if **any** transaction from the account is in the pool or was in a recent committed block: [4](#0-3) 

The code comment claims this is sufficient because it implies a deploy_account or a future-nonce invoke that "passed validations" is present. However, the check does not distinguish between a legitimate deploy_account submitted by the account owner and the presence of the account in the mempool for any other reason. Crucially, `validate_by_mempool` — called **before** `skip_stateful_validations` — does not verify the signature; it only checks nonce validity and fee escalation: [5](#0-4) 

**Attack path:**

1. Victim submits `deploy_account(address=X)` → admitted to mempool; `account_tx_in_pool_or_recent_block(X)` now returns `true`.
2. Attacker submits `invoke(sender=X, nonce=1, calldata=<arbitrary>, signature=<garbage>)` before the victim's own invoke.
3. Gateway stateless validation passes (signature length check only, not cryptographic verification).
4. `validate_by_mempool` passes: no duplicate nonce exists yet, nonce=1 ≥ account_nonce=0.
5. `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool=true` → returns `true`.
6. `run_validate_entry_point` is called with `validate=false` → `__validate__` is **never called**.
7. Attacker's invoke is admitted to the mempool with an unverified signature.
8. Victim subsequently submits `invoke(sender=X, nonce=1, valid_signature)` → rejected as `DuplicateNonce` (or requires fee escalation to displace the attacker's transaction).
9. At block execution time: deploy_account runs, then the attacker's invoke runs with `__validate__` called → fails (garbage signature). The victim's legitimate invoke is absent from the mempool.

The `max_nonce_for_validation_skip` field exists in `StatefulTransactionValidatorConfig` but is **not used** in the gateway's `skip_stateful_validations`; the nonce=1 bound is hardcoded: [6](#0-5) 

---

### Impact Explanation

An unprivileged attacker can cause the gateway to admit an invoke transaction with an arbitrary (garbage) signature into the mempool, bypassing the account's `__validate__` entry point. This transaction occupies the nonce=1 slot for the victim's account. The victim's legitimate first invoke is either rejected outright (duplicate nonce) or requires paying a higher tip to displace the attacker's transaction. The attacker's transaction fails at execution time (signature check in blockifier), but the victim's first post-deploy invoke is lost from the mempool and must be resubmitted. This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- The victim's deploy_account transaction is publicly visible in the mempool.
- The attacker needs only to submit an invoke with nonce=1 for the same address before the victim's own invoke arrives — a straightforward front-run requiring no privileged access.
- The attack is cheap: the attacker pays only the transaction fee for a transaction that will revert.
- The window is the time between the victim's deploy_account being admitted and the block being committed (potentially many seconds).

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the target address is pending in the mempool. Add a dedicated mempool query such as `deploy_account_tx_in_pool(address)` that only returns `true` when a deploy_account (nonce=0) transaction for that address is present. Additionally, use the existing `max_nonce_for_validation_skip` configuration field (currently unused in this path) to bound the nonce range for which validation may be skipped.

---

### Proof of Concept

```
// State: account X has nonce=0 in committed state (not deployed).

// Step 1: Victim submits deploy_account for address X.
// → mempool.account_tx_in_pool_or_recent_block(X) == true

// Step 2: Attacker submits (before victim's invoke):
//   invoke { sender=X, nonce=1, calldata=[drain_tokens], signature=[0xDEAD, 0xBEEF] }

// Step 3: Gateway stateless validation passes (signature length ≤ max_signature_length).

// Step 4: validate_by_mempool passes:
//   - No duplicate tx_hash.
//   - state.validate_incoming_tx: nonce=1 >= account_nonce=0 → OK.
//   - validate_fee_escalation: no existing tx at (X, nonce=1) → Ok(None).

// Step 5: skip_stateful_validations:
//   tx.nonce() == Nonce(1) && account_nonce == Nonce(0) → check mempool
//   account_tx_in_pool_or_recent_block(X) == true (victim's deploy_account)
//   → returns true (skip __validate__)

// Step 6: run_validate_entry_point called with validate=false → __validate__ NOT called.
// Attacker's invoke admitted to mempool.

// Step 7: Victim submits invoke { sender=X, nonce=1, valid_signature }
// → validate_by_mempool: DuplicateNonce error (or fee escalation required).
// Victim's invoke is blocked.

// Step 8: Block execution:
//   deploy_account(X) executes → X deployed.
//   attacker's invoke executes → __validate__ called → FAILS (garbage signature).
//   Victim's invoke: not in mempool, not executed.
```

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
