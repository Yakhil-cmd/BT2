### Title
Unauthenticated Invoke Transaction Bypasses `__validate__` Signature Check via `skip_stateful_validations` Existence-Only Guard — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator decides whether to skip the `__validate__` entry-point (the on-chain signature check) for an incoming invoke transaction. Its authorization guard — `account_tx_in_pool_or_recent_block(sender_address)` — only checks that **any** transaction from the claimed sender address exists in the mempool. It does not verify that the submitter of the new invoke transaction is the authorized signer for that account. Any unprivileged attacker who observes a victim's pending `deploy_account` transaction in the mempool can inject an invoke transaction bearing the victim's `sender_address` and an arbitrary garbage signature, and the gateway will accept it into the mempool without ever calling `__validate__`.

This is the direct Sequencer analog of the VestedZeroNFT `split()` bug: just as `_requireOwned(tokenId)` only checks that the token is not burned (existence) rather than that `msg.sender` is the owner (authorization), `account_tx_in_pool_or_recent_block` only checks that the account has a transaction in the mempool (existence) rather than that the submitter is the authorized signer (authorization).

---

### Finding Description

**The vulnerable guard:** [1](#0-0) 

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())  // ← existence only
                .await
                ...
        }
    }
    Ok(false)
}
```

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

With `validate = false`, `validate_tx` returns immediately without executing `__validate__`: [3](#0-2) 

```rust
fn validate_tx(...) -> ... {
    if !self.execution_flags.validate {
        return Ok(None);   // ← signature never checked
    }
    ...
}
```

**What `account_tx_in_pool_or_recent_block` actually checks:** [4](#0-3) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

```rust
fn contains_account(&self, address: ContractAddress) -> bool {
    self.staged.contains_key(&address) || self.committed.contains_key(&address)
}
```

This returns `true` for **any** address that has ever had a transaction in the mempool — it carries no information about who submitted the current invoke transaction.

**Attack path:**

1. Victim Alice pre-funds her counterfactual address and submits a `deploy_account` transaction (nonce=0). It enters the mempool; `account_tx_in_pool_or_recent_block(alice_address)` now returns `true`.
2. Attacker Bob submits `Invoke { sender_address: alice_address, nonce: 1, calldata: <arbitrary>, signature: <garbage> }`.
3. Gateway stateful validation:
   - `validate_nonce`: `account_nonce=0 ≤ tx_nonce=1 ≤ max_allowed_nonce_gap` → passes.
   - `validate_by_mempool`: no duplicate nonce=1 for Alice yet → passes.
   - `skip_stateful_validations`: Invoke, nonce==1, account_nonce==0, `account_tx_in_pool_or_recent_block(alice)=true` → returns `true`.
   - `run_validate_entry_point(skip_validate=true)` → `__validate__` **never called**, garbage signature never verified.
4. Bob's transaction is accepted into the mempool under Alice's address.
5. Alice's legitimate nonce=1 invoke (submitted alongside her deploy_account) is now rejected as `DuplicateNonce` or must pay fee escalation to displace Bob's transaction.

The `account_tx_in_pool_or_recent_block` check is documented with the comment: [6](#0-5) 

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."

The comment itself acknowledges the check is a proxy, not an authorization proof. The proxy is exploitable because it does not bind the submitter of the new invoke transaction to the authorized signer of the account.

---

### Impact Explanation

An unprivileged attacker can inject an invoke transaction bearing any victim's `sender_address` and a garbage signature into the mempool without signature verification, as long as the victim has a pending `deploy_account` in the mempool. This satisfies the impact criterion:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concrete consequences:
- The victim's legitimate nonce=1 invoke transaction (submitted alongside `deploy_account` for the UX feature) is blocked by the attacker's garbage transaction occupying the same nonce slot.
- The victim must resubmit after the attacker's transaction fails execution, introducing latency and potential fee loss.
- The attacker can target any account currently in the process of being deployed — a common, observable on-chain event.

---

### Likelihood Explanation

- **Trigger is unprivileged**: any external caller can submit an RPC transaction.
- **Precondition is observable**: a pending `deploy_account` transaction is visible in the mempool/pending state.
- **No special knowledge required**: the victim's address is the `contract_address` field of the `deploy_account` transaction.
- **Nonce constraint is narrow but predictable**: only nonce=1 is affected (hardcoded in `skip_stateful_validations`), but this is exactly the nonce of the first post-deploy invoke, which is the most common use of the UX feature.

---

### Recommendation

Replace the existence-only proxy with a type-specific check. `account_tx_in_pool_or_recent_block` should be replaced (or supplemented) with a check that verifies a `deploy_account` transaction specifically exists for the claimed `sender_address` in the mempool, e.g., by exposing a `deploy_account_in_pool(address)` query on the mempool that inspects transaction type. Alternatively, the skip-validate path should be restricted to transactions whose `sender_address` matches the `contract_address` computed from the `deploy_account` transaction already in the mempool, binding the two transactions together cryptographically rather than by address existence alone.

---

### Proof of Concept

```
// State: Alice has submitted deploy_account(nonce=0) → in mempool.
// account_tx_in_pool_or_recent_block(alice_address) == true.

// Attacker submits via RPC:
starknet_addInvokeTransaction({
  sender_address: alice_address,   // victim's address
  nonce: 1,
  calldata: [<arbitrary malicious calldata>],
  signature: [0x1, 0x2],           // garbage — never verified
  resource_bounds: { ... }
})

// Gateway path:
// 1. stateless_tx_validator.validate() → passes (signature length OK)
// 2. convert_rpc_tx_to_internal() → passes
// 3. extract_state_nonce_and_run_validations():
//    - account_nonce = 0 (alice not deployed)
//    - validate_nonce: 0 <= 1 <= max_gap → OK
//    - validate_by_mempool: no dup nonce=1 → OK
//    - skip_stateful_validations:
//        nonce==1 && account_nonce==0 && account_tx_in_pool(alice)==true
//        → returns true (SKIP __validate__)
//    - run_validate_entry_point(skip_validate=true):
//        execution_flags.validate = false
//        validate_tx() returns Ok(None) immediately
//        __validate__ NEVER CALLED, garbage signature NEVER VERIFIED
// 4. mempool.add_tx() → attacker's tx accepted under alice_address, nonce=1

// Alice's legitimate nonce=1 invoke is now rejected as DuplicateNonce.
``` [1](#0-0) [2](#0-1) [4](#0-3)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L993-1001)
```rust
    fn validate_tx(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut GasCounter,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !self.execution_flags.validate {
            return Ok(None);
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
