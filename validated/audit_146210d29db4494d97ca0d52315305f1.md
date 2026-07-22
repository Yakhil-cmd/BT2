### Title
Gateway Admission Bypass: Invalid Invoke Transactions with Nonce=1 Skip Signature Validation via `skip_stateful_validations` - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the account's `__validate__` entry point for any invoke transaction with `nonce=1` when the account has any transaction in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can submit an invoke with `nonce=1` and an arbitrary/invalid signature for the victim's account. The gateway admits this transaction without signature verification. When the batcher later executes it, `__validate__` fails, the transaction is reverted, nonce=1 is consumed, and fees are charged to the victim's account — permanently blocking the victim's first post-deployment invoke.

### Finding Description

`skip_stateful_validations` returns `true` (skip validation) when all three conditions hold:

1. The transaction is an `Invoke` with `nonce == Nonce(Felt::ONE)`
2. The account's on-chain nonce is `Nonce(Felt::ZERO)` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` is called with `validate: !skip_validate = false`, meaning the account's `__validate__` entry point — which performs signature verification — is never invoked at the gateway level: [2](#0-1) 

The comment in the code states the intent: "it is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." However, `account_tx_in_pool_or_recent_block` checks `state.contains_account || tx_pool.contains_account` — it returns `true` for any account with any pending transaction, not specifically a `deploy_account`: [3](#0-2) 

The critical invariant broken: the gateway admits an invoke transaction whose signature has never been verified against the (not-yet-deployed) account contract. The analog to the external bug is exact — just as `receiveTokenOrETH` accepts `msg.value > amount` without enforcing `msg.value == amount`, `skip_stateful_validations` accepts an invoke without enforcing that the signature is valid, because the condition `account_tx_in_pool_or_recent_block` is too permissive (analogous to `msg.value < amount` instead of `msg.value != amount`).

The `max_nonce_for_validation_skip` config field exists in `StatefulTransactionValidatorConfig` and is used in the Python-binding path (`PyValidator::should_run_stateful_validations`), but the Rust gateway's `skip_stateful_validations` hardcodes the nonce check to `== Nonce(Felt::ONE)` and does not consult this config: [4](#0-3) [5](#0-4) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can:
1. Observe any victim's `deploy_account` transaction in the mempool.
2. Submit an invoke with `nonce=1`, `sender=victim_address`, and an arbitrary/invalid signature.
3. The gateway admits the transaction (signature check skipped).
4. The batcher executes `deploy_account` first (deploying the account), then executes the attacker's invalid invoke.
5. The batcher calls `__validate__` (with `validate: true` in normal execution flags), which fails due to the invalid signature — the transaction is reverted.
6. The reverted transaction still consumes `nonce=1` and charges fees to the victim's account.
7. The victim's legitimate invoke with `nonce=1` is now rejected (nonce already used).

The victim suffers: (a) loss of fees charged for the attacker's reverted transaction, and (b) their first post-deployment invoke is permanently griefed, requiring resubmission with `nonce=2`.

### Likelihood Explanation

**Medium.** The attack requires only that the attacker observe a `deploy_account` transaction in the public mempool — a trivially observable event. No privileged access, special keys, or contract deployment is required. The attacker only needs to submit a single transaction before the victim's invoke is processed.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the account (not just any transaction). Additionally, even when skipping the blockifier `__validate__` entry point, the gateway should perform a lightweight signature format check or require the invoke to carry a proof-of-knowledge of the deployer key. Alternatively, align the Rust gateway with the Python validator by consulting `max_nonce_for_validation_skip` from config rather than hardcoding `Nonce(Felt::ONE)`.

### Proof of Concept

```
1. Victim submits: deploy_account { class_hash=X, salt=Y, sig=valid_sig, nonce=0 }
   → Mempool: account_tx_in_pool_or_recent_block(victim_addr) = true

2. Attacker submits: invoke { sender=victim_addr, nonce=1, calldata=[drain_funds], sig=0xDEAD }
   → Gateway stateful validation:
       validate_nonce: nonce=1 >= account_nonce=0 ✓ (within max_allowed_nonce_gap=200)
       skip_stateful_validations:
           tx.nonce() == Nonce(ONE) ✓
           account_nonce == Nonce(ZERO) ✓
           account_tx_in_pool_or_recent_block(victim_addr) = true ✓
       → skip_validate = true
       run_validate_entry_point(validate=false) → __validate__ NOT called
   → Invalid invoke admitted to mempool ✓

3. Batcher executes block:
   - deploy_account executed → victim_addr deployed, nonce becomes 1
   - attacker's invoke executed with validate=true:
       __validate__ called → sig=0xDEAD fails → REVERTED
       nonce incremented to 2, fees charged to victim_addr

4. Victim submits: invoke { sender=victim_addr, nonce=1, sig=valid_sig }
   → Rejected: nonce=1 < account_nonce=2
``` [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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

**File:** crates/native_blockifier/src/py_validator.rs (L112-118)
```rust
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
