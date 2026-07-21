### Title
Signature Validation Bypass for Invoke Transactions via `skip_stateful_validations` Allows Admission of Unauthorized Transactions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally bypasses the account's `__validate__` entry point (the sole signature-verification step) for any invoke transaction with nonce=1 when `account_tx_in_pool_or_recent_block` returns `true` for the sender address. Because that check returns `true` for **any** address that has **any** transaction in the pool — not specifically a deploy_account transaction belonging to the same signer — an unprivileged attacker can inject an invoke transaction carrying an arbitrary (invalid) signature for a victim address that has a pending deploy_account transaction, and the gateway will admit it to the mempool without ever verifying the signature.

---

### Finding Description

**Invariant broken:** Every transaction admitted to the mempool must carry a signature that is authorized by the account at the sender address.

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function fires when three conditions are simultaneously true:

1. The incoming invoke transaction has `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

When all three hold, the function returns `true`, which propagates as `skip_validate = true` into `run_validate_entry_point`: [2](#0-1) 

With `validate: false` in `ExecutionFlags`, the blockifier's `StatefulValidator::validate` call skips the `__validate__` entry point entirely. No other code path in the gateway independently verifies the transaction signature.

**The flawed assumption in `account_tx_in_pool_or_recent_block`:** [3](#0-2) 

The code comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is incorrect. The check returns `true` if the address has **any** transaction in the pool — including a deploy_account transaction submitted by a completely different party (the legitimate account owner). An attacker who observes a victim's deploy_account transaction in the mempool can immediately satisfy condition 3 for the victim's address without possessing the victim's private key.

**No other guard catches the invalid signature:**

- `validate_state_preconditions` checks resource bounds and nonce only. [4](#0-3) 
- `validate_by_mempool` checks for duplicate tx hash and nonce ordering against mempool state — no signature check. [5](#0-4) 
- `perform_pre_validation_stage` checks nonce, fee bounds, and proof facts — no signature check. [6](#0-5) 

---

### Impact Explanation

**Allowed impact category:** *High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

An attacker can inject invoke transactions carrying arbitrary signatures for any victim address that has a pending deploy_account transaction. Concrete consequences:

1. **Nonce slot squatting:** The attacker's invalid nonce=1 transaction occupies the victim's nonce=1 slot in the mempool. When the victim submits their legitimate first invoke transaction, the mempool sees a duplicate nonce and either rejects it or requires fee escalation. The attacker can keep front-running with higher fees, indefinitely delaying the victim's first post-deployment transaction.
2. **Mempool pollution / sequencer resource waste:** Invalid transactions are executed by the batcher, fail at the `__validate__` entry point, and are then removed via `commit_block`'s `rejected_tx_hashes` path — wasting execution resources.
3. **Targeted griefing at scale:** Because deploy_account transactions are publicly visible in the mempool, an attacker can automate this against every new account deployment.

---

### Likelihood Explanation

- **Unprivileged trigger:** No special role or access is required. Any party can submit an RPC transaction.
- **Observable precondition:** The victim's deploy_account transaction is visible in the public mempool.
- **Narrow nonce window:** The attack is limited to nonce=1 by the `max_nonce_for_validation_skip` default of `Nonce(Felt::ONE)`. [7](#0-6) 
- **Timing:** The window is open from the moment the victim's deploy_account transaction enters the pool until it is committed and the on-chain nonce advances past 0.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction for the sender address is pending in the pool. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool` that inspects the transaction type, not merely the address presence. This preserves the UX intent (allowing deploy_account + invoke to be submitted together) while closing the window for unauthorized nonce=1 injection.

Alternatively, perform an independent cryptographic signature check at the gateway layer before deciding to skip the `__validate__` entry point, so that even when the entry point is skipped, the signature is still verified against the transaction hash.

---

### Proof of Concept

```
1. Alice submits deploy_account tx for address X (nonce=0, valid signature).
   → tx_pool.contains_account(X) = true

2. Attacker observes Alice's deploy_account tx in the mempool.

3. Attacker constructs an invoke tx:
     sender_address = X
     nonce          = 1
     signature      = [0xdeadbeef]   ← arbitrary, invalid

4. Gateway stateful validation for attacker's tx:
     account_nonce = get_nonce_from_state(X) = 0          ✓ condition 2
     tx.nonce()    = 1                                     ✓ condition 1
     account_tx_in_pool_or_recent_block(X) = true          ✓ condition 3
     → skip_validate = true
     → __validate__ entry point NOT called
     → invalid tx admitted to mempool

5. Alice submits her legitimate invoke tx (nonce=1, valid signature).
   → Mempool sees duplicate nonce=1 for address X.
   → Alice's tx is rejected or requires fee escalation.

6. Batcher picks up attacker's tx, calls __validate__, fails with ValidateFailure.
   → Attacker's tx removed via commit_block(rejected_tx_hashes=[...]).
   → Alice's tx has been delayed; attacker repeats from step 3.
```

The key files involved:

- `crates/apollo_gateway/src/stateful_transaction_validator.rs` — `skip_stateful_validations` (lines 429–461), `run_validate_entry_point` (lines 302–356)
- `crates/apollo_mempool/src/mempool.rs` — `account_tx_in_pool_or_recent_block` (lines 697–700)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L213-221)
```rust
    async fn validate_state_preconditions(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        self.validate_resource_bounds(executable_tx).await?;
        self.validate_nonce(executable_tx, account_nonce)?;
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-314)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
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
