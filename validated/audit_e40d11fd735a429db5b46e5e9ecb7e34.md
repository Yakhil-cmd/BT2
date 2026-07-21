### Title
Gateway Skips `__validate__` for Nonce-1 Invoke When Any Account Transaction Exists in Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (the account's signature check) for any invoke transaction with `nonce=1` whenever the sender address has **any** transaction in the mempool — not exclusively a `deploy_account` transaction. An attacker who controls an account deployed via the `deploy` syscall (which leaves `nonce=0` in state) can first submit a valid `nonce=0` invoke to seed the mempool, then submit a `nonce=1` invoke with an **invalid or forged signature** that bypasses gateway signature validation and is admitted to the mempool.

This is the sequencer-native analog of the external "split-to-exploit" pattern: just as the DEX bug allows splitting one large swap into many small ones to repeatedly access the best passive order, here an attacker splits their account activity into two transactions — a valid `nonce=0` invoke that "unlocks" the skip path, and an invalid `nonce=1` invoke that exploits it — to bypass the invariant that every admitted transaction must pass its account's `__validate__` entry point.

---

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` is intended to improve UX for the `deploy_account + invoke` pattern: [1](#0-0) 

The skip condition fires when:
1. The transaction is an `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` (from on-chain state)
4. `account_tx_in_pool_or_recent_block(sender)` returns `true`

The comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is incorrect. `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction type from that address: [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false`, meaning the `__validate__` entry point is never called: [3](#0-2) 

**Concrete attack path using an account deployed via `deploy` syscall:**

Accounts deployed via the `deploy` syscall (not `deploy_account`) have code but `nonce=0` in state. The `validate_nonce` check for invoke transactions allows `account_nonce=0, tx_nonce=0`: [4](#0-3) 

1. Attacker controls an account deployed via `deploy` syscall — `nonce=0` in state, code present.
2. Attacker submits a valid `Invoke` with `nonce=0`. This goes through full validation including `__validate__` (since `skip_stateful_validations` only fires for `nonce=1`). It is admitted to the mempool.
3. Attacker submits an `Invoke` with `nonce=1` and an **arbitrary/invalid signature**.
   - `validate_nonce`: `0 ≤ 1 ≤ 200` → passes.
   - `validate_resource_bounds`: gas price check only → passes.
   - `skip_stateful_validations`: `nonce==1` ✓, `account_nonce==0` ✓, `account_tx_in_pool_or_recent_block` → `true` (nonce=0 invoke is in pool) ✓ → returns `true`.
   - `run_validate_entry_point` called with `validate: false` → `__validate__` is **never called**.
4. The `nonce=1` invoke with invalid signature is admitted to the mempool.

The `StatefulTransactionValidatorConfig` default confirms `max_nonce_for_validation_skip = Nonce(Felt::ONE)`, and the gateway's hardcoded `nonce == ONE` check matches this window exactly: [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway's core admission invariant is that every accepted transaction must pass its account's `__validate__` entry point. This invariant is broken for `nonce=1` invoke transactions when the sender has any prior transaction in the mempool. Transactions with invalid signatures are admitted, consuming mempool capacity. They will fail during block execution (the blockifier runs `__validate__` with `validate: true`), but the gateway has already accepted them, enabling mempool pollution and resource exhaustion attacks.

---

### Likelihood Explanation

**Medium.** The precondition — an account with `nonce=0` in state and deployed code — is satisfied by any account deployed via the `deploy` syscall (a common pattern for factory-deployed wallets and contracts). The attacker only needs to submit two sequential transactions: one valid `nonce=0` invoke to seed the mempool, and one `nonce=1` invoke with an invalid signature. No privileged access is required.

---

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is pending for the sender. Add a dedicated mempool query such as `has_pending_deploy_account(address)` that inspects transaction types, rather than relying on the presence of any transaction. Alternatively, restrict the skip to cases where the account does **not** exist in on-chain state (i.e., `get_class_hash_at(address) == ClassHash::default()`), which is the true precondition for the UX feature.

---

### Proof of Concept

```
// Precondition: account at ADDRESS deployed via `deploy` syscall, nonce=0 in state.

// Step 1: Submit valid nonce=0 invoke (passes __validate__)
gateway.add_tx(RpcInvokeTransaction {
    sender_address: ADDRESS,
    nonce: 0,
    signature: VALID_SIGNATURE,
    ...
});
// → admitted to mempool; account_tx_in_pool_or_recent_block(ADDRESS) now returns true

// Step 2: Submit nonce=1 invoke with INVALID signature
gateway.add_tx(RpcInvokeTransaction {
    sender_address: ADDRESS,
    nonce: 1,
    signature: [0x41, 0x41, 0x41],  // garbage
    ...
});
// → skip_stateful_validations returns true (nonce==1, account_nonce==0, pool contains nonce=0 tx)
// → run_validate_entry_point called with validate=false
// → __validate__ is NEVER called
// → invalid transaction admitted to mempool
``` [6](#0-5) [7](#0-6)

### Citations

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
