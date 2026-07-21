### Title
Signature-Bypass via `skip_stateful_validations`: Attacker Can Inject Unsigned Invoke into Mempool for Any Undeployed Account - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `skip_stateful_validations` UX feature, designed to let a user submit a `deploy_account` + `invoke` pair atomically, does not verify that the invoke originates from the same party as the deploy_account. Any third party who observes a `deploy_account` transaction in the mempool can immediately submit an `invoke` with `nonce=1` for that address carrying an arbitrary (invalid) signature. The gateway skips `__validate__` for this invoke, admits it into the mempool, and the victim's own legitimate first post-deploy invoke is then rejected with `DuplicateNonce`. The attacker's transaction fails during batcher execution (no fee charged), but the victim's transaction is blocked for the duration of that block and must be resubmitted.

### Finding Description

**Broken invariant:** Every transaction admitted to the mempool must have either passed `__validate__` (signature verification) or have a cryptographically sound reason to skip it. The skip is only sound when the submitter of the invoke is the same party who controls the account being deployed.

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

The only guard is `account_tx_in_pool_or_recent_block(sender_address)`. This returns `true` whenever **any** transaction from that address is in the pool — including the victim's own `deploy_account`. There is no check that the invoke's submitter is the same entity that submitted the `deploy_account`.

**Execution path that admits the invalid transaction:**

`extract_state_nonce_and_run_validations` →
`run_pre_validation_checks` →
  1. `validate_state_preconditions` → `validate_nonce`: nonce=1 ≥ account_nonce=0, passes (default `max_allowed_nonce_gap = 200`)
  2. `validate_by_mempool` → `validate_fee_escalation`: no existing nonce=1 tx for this address, passes
  3. `skip_stateful_validations`: returns `true` (skip)
→ `run_validate_entry_point(skip_validate=true)` → `execution_flags.validate = false` → `__validate__` is **never called**

The transaction is forwarded to the mempool with an arbitrary signature.

**Mempool blocks the victim:**

When the victim subsequently submits their own legitimate invoke with nonce=1, `validate_fee_escalation` finds the attacker's transaction already occupying `(address, nonce=1)` and returns `MempoolError::DuplicateNonce` (when `enable_fee_escalation = false`) or demands a fee premium (when enabled). Since the attacker pays zero fees when `__validate__` fails at execution time, the attacker can always outbid the victim in a fee-escalation war at no cost.

**Batcher execution:**

When the batcher executes the attacker's invoke, `__validate__` is called with `execution_flags.validate = true` (the default). It fails, the transaction is rejected, no fee is charged, and the nonce is not incremented. The victim must resubmit their invoke in the next block.

### Impact Explanation

This matches: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

- The gateway admits a transaction with an invalid (attacker-controlled) signature into the mempool.
- The victim's valid first post-deploy invoke is rejected (`DuplicateNonce`) or priced out via fee escalation.
- The attacker bears zero cost (no fee charged on `__validate__` failure), so the attack can be repeated every time the victim deploys a new account.
- The victim's first post-deploy transaction is delayed by at least one block per attack iteration.

### Likelihood Explanation

- Requires no privileged access; any unprivileged network participant can submit transactions to the gateway.
- The attacker only needs to observe a `deploy_account` transaction in the mempool (publicly visible) and race to submit an invoke with nonce=1 before the victim does.
- The default `max_allowed_nonce_gap = 200` ensures nonce=1 always passes the gateway nonce check.
- The default `max_nonce_for_validation_skip = Nonce(Felt::ONE)` confirms the skip window is active in production.

### Recommendation

The `skip_stateful_validations` check must be tightened so that the skip is only granted when the **same sender** submitted the `deploy_account`. Concretely, the mempool's `account_tx_in_pool_or_recent_block` query should be replaced (or supplemented) with a query that specifically checks for a `deploy_account` transaction from the same address, not just any transaction. Alternatively, the gateway can require the invoke to carry a valid signature even when the account is not yet deployed, by running `__validate__` against the class hash declared in the pending `deploy_account` (as the account contract is known at that point).

### Proof of Concept

```
// Precondition: victim submits deploy_account for address A (nonce=0).
// This passes full validation and lands in the mempool.

// Step 1 – attacker observes the deploy_account in the mempool.

// Step 2 – attacker submits:
//   RpcInvokeTransactionV3 {
//     sender_address: A,          // victim's address
//     nonce: 1,                   // post-deploy nonce
//     signature: [0xdead, 0xbeef],// arbitrary garbage
//     calldata: [...],            // arbitrary
//     resource_bounds: { l2_gas: { max_amount: X, max_price_per_unit: Y } },
//     ...
//   }
//
// Gateway flow:
//   validate_nonce(nonce=1, account_nonce=0, max_gap=200) → OK
//   validate_by_mempool → no nonce=1 tx for A yet → OK
//   skip_stateful_validations:
//     nonce==1 && account_nonce==0 → check account_tx_in_pool_or_recent_block(A)
//     → true (deploy_account is in pool) → returns true (skip)
//   run_validate_entry_point(skip_validate=true) → __validate__ NOT called
//   → transaction admitted to mempool with garbage signature ✓

// Step 3 – victim submits their own invoke (nonce=1, valid signature):
//   validate_by_mempool → validate_fee_escalation → DuplicateNonce → REJECTED ✗

// Step 4 – batcher executes attacker's invoke:
//   __validate__ called → fails (invalid signature) → tx rejected, no fee charged
//   commit_block removes attacker's tx from mempool

// Step 5 – victim must resubmit; attacker can repeat from Step 2.
```

**Key code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
    }
```
