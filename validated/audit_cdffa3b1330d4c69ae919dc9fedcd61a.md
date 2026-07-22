### Title
Gateway Skips `__validate__` for Invoke Nonce=1 When Any Prior Transaction Exists in Pool, Not Just `deploy_account` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function is designed to skip the `__validate__` entry-point call at the gateway for an invoke with `nonce=1` when a `deploy_account` is pending (UX feature). However, the guard `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from the sender address, not exclusively a `deploy_account`. An attacker who controls an account can place a valid `nonce=0` invoke in the pool, then submit a `nonce=1` invoke with an arbitrary/invalid signature; the gateway skips `__validate__` and admits the second transaction to the mempool without signature verification.

---

### Finding Description

`skip_stateful_validations` fires when three conditions hold simultaneously:

```
tx.nonce() == Nonce(Felt::ONE)   // incoming invoke has nonce 1
account_nonce == Nonce(Felt::ZERO) // on-chain nonce is 0 (account not yet deployed)
account_tx_in_pool_or_recent_block(sender) == true
``` [1](#0-0) 

When all three hold, `skip_validate = true` is returned, and `run_validate_entry_point` sets `execution_flags.validate = false`, meaning the blockifier's `StatefulValidator` returns `Ok(())` without ever calling `__validate__`: [2](#0-1) [3](#0-2) 

The third condition is evaluated by:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

`tx_pool.contains_account` returns `true` if the address has **any** transaction in the pool: [5](#0-4) 

The code comment asserts: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* [6](#0-5) 

This assertion is **incorrect**. A regular `Invoke` with `nonce=0` from an undeployed account also satisfies the condition. The gateway's `validate_nonce` for invoke transactions accepts `nonce=0` when `account_nonce=0`: [7](#0-6) 

**Attack path:**

1. Attacker controls address `A` (has private key). On-chain nonce of `A` is `0`.
2. Attacker submits `Invoke(nonce=0, valid_signature)` → passes all gateway checks including `__validate__` → enters `tx_pool`.
3. Attacker submits `Invoke(nonce=1, invalid_or_arbitrary_signature)`:
   - `validate_state_preconditions`: nonce `1 >= 0`, passes.
   - `validate_by_mempool`: checks nonce ordering only, no signature check.
   - `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `tx_pool.contains_account(A)==true` → returns `true`.
   - `run_validate_entry_point` sets `validate=false` → `__validate__` is **never called**.
4. The `nonce=1` invoke with unverified signature is admitted to the mempool.

`validate_by_mempool` only checks nonce ordering and fee escalation, not the signature: [8](#0-7) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction.**

A transaction whose `__validate__` entry point would reject it (e.g., wrong signature, failed account-level authorization) is admitted to the mempool without that check being run. The invariant that every transaction entering the mempool has passed its account's `__validate__` is broken for `nonce=1` invoke transactions whenever the sender has any prior transaction in the pool.

During batcher execution `new_for_sequencing` always sets `validate: true`, so `__validate__` is eventually called and the transaction reverts — but the admission decision (mempool acceptance) is already wrong. [9](#0-8) 

---

### Likelihood Explanation

**Medium.** The attacker must control the account (to produce a valid `nonce=0` transaction that seeds the pool). Any account owner can then submit a `nonce=1` invoke that bypasses `__validate__`. No privileged access or special network position is required beyond normal gateway access.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific query that confirms a **`deploy_account`** transaction (not any transaction) is pending for the sender address. Alternatively, expose a `deploy_account_in_pool(address)` predicate on the mempool that inspects transaction type before granting the validation skip.

---

### Proof of Concept

```
// Setup: account A, on-chain nonce = 0, not deployed.

// Step 1 – seed the pool with a valid nonce-0 invoke.
gateway.add_tx(RpcInvokeV3 {
    sender_address: A,
    nonce: 0,
    signature: valid_sig_for_nonce_0,
    ...
}).await; // passes __validate__, enters tx_pool

// Step 2 – submit nonce-1 invoke with garbage signature.
gateway.add_tx(RpcInvokeV3 {
    sender_address: A,
    nonce: 1,
    signature: [0xdeadbeef],   // invalid / arbitrary
    ...
}).await;
// skip_stateful_validations returns true because tx_pool.contains_account(A) == true
// __validate__ is NOT called at the gateway
// Transaction is admitted to the mempool ← broken invariant
```

The relevant test case `should_skip_validation` in the test suite confirms the skip fires for exactly this nonce configuration when `contains_tx = true`: [10](#0-9)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/transaction_pool.rs (L201-203)
```rust
    pub fn contains_account(&self, address: ContractAddress) -> bool {
        self.txs_by_account.contains(address)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L151-157)
```rust
#[rstest]
#[case::should_skip_validation(
    executable_invoke_tx(invoke_tx_args!(nonce: nonce!(1))),
    nonce!(0),
    true,
    false
)]
```
