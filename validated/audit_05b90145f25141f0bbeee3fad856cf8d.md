### Title
Signature Validation Bypass via Overly Broad `account_tx_in_pool_or_recent_block` Check in `skip_stateful_validations` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function is intended to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the corresponding `deploy_account` transaction is still pending in the mempool (UX improvement). However, the mempool predicate it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction type from that address (invoke, declare, or a previously committed non-deploy-account transaction), not exclusively for a `deploy_account` transaction. An attacker who controls a pre-existing address (one that already has any committed transaction, or any non-deploy-account transaction in the mempool) can submit an invoke with nonce=1 and an arbitrary/invalid signature and have the gateway accept it without running `__validate__`, causing an unauthorized transaction to be admitted to the mempool and sequenced.

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `skip_stateful_validations` to decide whether to skip the blockifier `__validate__` call:

```
skip_stateful_validations(executable_tx, account_nonce, mempool_client)
```

Inside `skip_stateful_validations`:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
```

The condition triggers when:
1. The incoming invoke transaction has nonce = 1
2. The on-chain account nonce is 0 (account not yet deployed on-chain)

When both conditions hold, the code calls `account_tx_in_pool_or_recent_block(sender_address)`, which is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`MempoolState::contains_account` returns `true` if the address appears in `staged` or `committed` maps — populated by **any** transaction type from that address, not only `deploy_account`. The code comment says:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is flawed. An address can appear in `committed` because it previously had an invoke or declare transaction committed in a recent block. In that case, `account_nonce` would be 0 only if the account was somehow reset, but more critically: the `tx_pool.contains_account` branch returns `true` if the address has **any** pending transaction in the pool — including an invoke with nonce=0 that was submitted by the attacker themselves in a prior step.

**Concrete attack scenario:**

1. Attacker controls address `A` which has never been deployed on-chain (on-chain nonce = 0).
2. Attacker submits a valid invoke with nonce=0 (passes `__validate__` normally). This places address `A` in `tx_pool`.
3. Before the nonce=0 tx is committed, attacker submits a second invoke with nonce=1 and a **completely invalid/arbitrary signature**.
4. Gateway checks: `tx.nonce() == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(A)` → `true` (because the nonce=0 invoke is still in the pool).
5. `skip_stateful_validations` returns `true`, so `run_validate_entry_point` is called with `skip_validate = true`, meaning `execution_flags.validate = false`.
6. The blockifier's `StatefulValidator::perform_validations` skips `__validate__` entirely for the invoke.
7. The nonce=1 invoke with invalid signature is admitted to the mempool and will be sequenced.

The nonce=0 invoke does not need to be a `deploy_account` — it just needs to be any transaction that places the address in the mempool pool. The invariant "account exists in mempool ⟹ it has a deploy_account" is broken.

### Impact Explanation

**Critical / High.** An attacker can submit an invoke transaction with an arbitrary signature (bypassing `__validate__`) that gets admitted to the mempool and sequenced. This maps to:

- **Mempool/gateway admission accepts invalid transactions** (High): a transaction with an invalid signature bypasses the `__validate__` entry point and is accepted.
- **Invalid or unauthorized Starknet transaction accepted through account validation / signature logic** (Critical): the signature check is the account's `__validate__` entry point; bypassing it means an unauthorized transaction is accepted.

The sequenced transaction will still fail at execution time if the account contract enforces authorization in `__execute__`, but many account contracts do not — and even if they do, the transaction consumes block resources and fees are charged from the account balance (which may be zero, causing a revert with fee charge).

### Likelihood Explanation

**Medium.** The attacker needs:
1. An address with on-chain nonce = 0 (undeployed account) — trivially achievable by generating a fresh key pair.
2. The ability to submit two transactions to the gateway in sequence — any unprivileged user can do this.
3. The first transaction (nonce=0) must pass normal validation — requires a valid signature for nonce=0 only.

No privileged access is required. The window is open as long as the nonce=0 transaction remains in the mempool (before being committed), which is the normal operating window.

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** exists for the sender address. The mempool should expose a dedicated predicate such as `deploy_account_tx_in_pool_or_recent_block(address) -> bool` that only returns `true` when the address has a pending or recently committed `deploy_account` transaction.

Alternatively, the gateway should track the `deploy_account` transaction hash (as the `native_blockifier` `PyValidator` does via `deploy_account_tx_hash: Option<TransactionHash>`) and use that as the skip condition rather than the address-presence check.

### Proof of Concept

```
1. Generate fresh keypair → address A (on-chain nonce = 0, never deployed)

2. Submit invoke_v3 from A, nonce=0, valid_signature:
   POST /gateway/add_transaction
   { type: INVOKE, sender_address: A, nonce: 0, signature: <valid> }
   → Accepted. A is now in mempool tx_pool.

3. Immediately submit invoke_v3 from A, nonce=1, INVALID signature:
   POST /gateway/add_transaction
   { type: INVOKE, sender_address: A, nonce: 1, signature: [0xdeadbeef] }

4. Gateway stateful validation:
   - account_nonce = get_nonce_from_state(A) = 0  ✓
   - validate_nonce: 0 <= 1 <= 0+200  ✓
   - skip_stateful_validations:
       tx.nonce() == 1  ✓
       account_nonce == 0  ✓
       account_tx_in_pool_or_recent_block(A):
           tx_pool.contains_account(A) = true  (nonce=0 invoke still pending)
       → returns true (skip validation)
   - run_validate_entry_point called with skip_validate=true
   - __validate__ is NOT called
   → Transaction accepted into mempool with invalid signature

5. Batcher picks up nonce=1 invoke and sequences it without signature verification.
```

**Key code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
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
