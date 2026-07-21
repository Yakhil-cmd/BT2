### Title
`skip_stateful_validations` bypasses `__validate__` for nonce=1 invoke when any prior transaction exists in mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is intended to support the UX pattern of sending a `deploy_account` and an `invoke` simultaneously. It skips the account's `__validate__` entry point for nonce=1 invoke transactions when `account_tx_in_pool_or_recent_block` returns `true`. However, that helper returns `true` for **any** transaction from the account in the pool — not specifically a `deploy_account` transaction. An attacker with a deployed account (on-chain nonce=0) can seed the pool with a valid nonce=0 invoke, then submit a nonce=1 invoke carrying an arbitrary/invalid signature that bypasses `__validate__` at the gateway and is admitted to the mempool.

### Finding Description

`skip_stateful_validations` fires when three conditions hold simultaneously:

```
tx.nonce() == Nonce(Felt::ONE)
account_nonce == Nonce(Felt::ZERO)          // from on-chain state
account_tx_in_pool_or_recent_block(addr)    // returns true
``` [1](#0-0) 

When it returns `true`, `run_validate_entry_point` is called with `validate: false`, so the blockifier never executes the account's `__validate__` entry point during gateway admission: [2](#0-1) 

The predicate `account_tx_in_pool_or_recent_block` checks whether the account has **any** transaction in the pool or any staged/committed nonce in the mempool state: [3](#0-2) 

The code comment asserts this is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." That reasoning is broken: a valid nonce=0 **invoke** (not a `deploy_account`) satisfies the predicate, yet it provides no guarantee that a subsequent nonce=1 invoke from the same account carries a valid signature.

The `validate_by_mempool` step that runs before `skip_stateful_validations` only checks nonce ordering and fee escalation — it never inspects the signature: [4](#0-3) [5](#0-4) 

**Attack sequence:**

1. Attacker controls a deployed account at address `A` with on-chain nonce=0.
2. Attacker submits `invoke(nonce=0, valid_sig)` → passes all gateway checks including `__validate__`, enters mempool.
3. Attacker submits `invoke(nonce=1, invalid_sig)`:
   - `validate_state_preconditions`: nonce=1 ≥ account_nonce=0 → passes.
   - `validate_by_mempool`: nonce=1 ≥ account_nonce=0, no fee escalation conflict → passes.
   - `skip_stateful_validations`: nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block(A)` == `true` (nonce=0 invoke is in pool) → returns `true`.
   - `run_validate_entry_point` executes with `validate: false` → `__validate__` is never called.
   - Transaction is accepted into the mempool with an invalid signature. [6](#0-5) 

### Impact Explanation

The gateway's admission control is bypassed: a transaction carrying an invalid (or attacker-crafted) signature for a deployed account is accepted into the mempool. This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concrete consequences:
- **Mempool pollution**: the invalid nonce=1 transaction occupies a pool slot.
- **Legitimate transaction blocking**: a valid nonce=1 invoke from the same account is rejected with `DuplicateNonce` until the attacker's transaction is evicted or replaced via fee escalation.
- **Wasted batcher resources**: the batcher dequeues and attempts to execute the transaction; the blockifier runs `__validate__` with `validate: true` (default flags), the signature check fails, and the transaction is discarded — consuming execution budget without producing useful work.

The transaction does not execute successfully because the batcher uses `ExecutionFlags::default()` (`validate: true`), so no funds are stolen. The impact is admission-level, not execution-level. [7](#0-6) 

### Likelihood Explanation

- Requires only a deployed account with on-chain nonce=0 — a common state for any account that has just been deployed and has not yet sent any transaction.
- The attacker pays fees only for the nonce=0 invoke; the nonce=1 invoke with invalid signature is admitted for free.
- No privileged access, no special contract, no off-chain coordination required.
- The window is permanent for any account at nonce=0 until the nonce=0 invoke is committed on-chain.

### Recommendation

In `skip_stateful_validations`, replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific check that verifies a `deploy_account` transaction (and only a `deploy_account` transaction) exists in the pool for the sender address. Alternatively, expose a `deploy_account_in_pool(address)` predicate on the mempool that inspects the transaction type stored in `tx_pool`, and use that instead. [1](#0-0) 

### Proof of Concept

```
// Precondition: account A is deployed on-chain, nonce = 0.

// Step 1 – seed the pool with a valid nonce=0 invoke.
gateway.add_tx(RpcInvokeV3 {
    sender_address: A,
    nonce: 0,
    signature: valid_sig_for_nonce_0,
    ...
}).await?;
// account_tx_in_pool_or_recent_block(A) now returns true.

// Step 2 – submit nonce=1 invoke with an invalid/arbitrary signature.
gateway.add_tx(RpcInvokeV3 {
    sender_address: A,
    nonce: 1,
    signature: [0xdead, 0xbeef],   // invalid
    ...
}).await?;
// skip_stateful_validations returns true:
//   tx.nonce() == 1  ✓
//   account_nonce == 0  ✓
//   account_tx_in_pool_or_recent_block(A) == true  ✓
// run_validate_entry_point called with validate=false → __validate__ skipped.
// Transaction admitted to mempool without signature verification.

// Step 3 – legitimate nonce=1 invoke from A is now rejected:
gateway.add_tx(RpcInvokeV3 {
    sender_address: A,
    nonce: 1,
    signature: real_valid_sig,
    ...
}).await;
// → MempoolError::DuplicateNonce (unless attacker's tx is replaced via fee escalation)
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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L59-70)
```rust
impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
        }
    }
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L98-102)
```rust
impl Default for ExecutionFlags {
    fn default() -> Self {
        Self { only_query: false, charge_fee: true, validate: true, strict_nonce_check: true }
    }
}
```
