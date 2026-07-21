### Title
Signature Verification Bypass via Front-Running the `skip_stateful_validations` Deploy-Account UX Path — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's UX shortcut that skips `__validate__` for an invoke transaction with nonce=1 when a deploy-account is pending relies on a mempool presence check (`account_tx_in_pool_or_recent_block`) that does **not** verify the existing mempool entry is a valid deploy-account transaction. An unprivileged attacker who observes a victim's pending deploy-account transaction can front-run the victim's nonce-1 invoke by submitting their own invoke for the same address with an arbitrary (invalid) signature, which the gateway accepts without running `__validate__`. The forged transaction enters the mempool, occupies the nonce-1 slot, and can block or force fee-escalation on the victim's legitimate invoke.

---

### Finding Description

**The UX skip path**

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet on-chain).
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`, which suppresses the call to the account's `__validate__` entry point — the only place the signature is verified at gateway time. [2](#0-1) 

**The broken invariant**

The comment in the code states:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This assumption is false. `account_tx_in_pool_or_recent_block` checks only whether the address appears in `tx_pool` or `state` — it does not verify that the existing entry is a deploy-account transaction or that it carries a valid signature. [3](#0-2) [4](#0-3) 

**The attack path**

1. Victim Alice broadcasts a `DeployAccount` transaction for address `A`. This transaction passes `__validate_deploy__` (Alice's signature is valid) and enters the mempool. `tx_pool.contains_account(A)` is now `true`.
2. Attacker observes Alice's deploy-account in the mempool (public P2P/RPC), extracts address `A`.
3. Attacker submits an `Invoke` transaction: `sender_address=A`, `nonce=1`, arbitrary calldata, **forged/random signature**.
4. Gateway stateless validation passes (no signature check there).
5. `extract_state_nonce_and_run_validations` reads `account_nonce=0` from state.
6. `validate_by_mempool` passes: no duplicate tx_hash, nonce 1 ≥ 0.
7. `skip_stateful_validations`: `tx_nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
8. `run_validate_entry_point` sets `validate=false` → `__validate__` is **never called**. The forged signature is never checked.
9. The attacker's transaction is stored in the mempool at `(A, nonce=1)`. [5](#0-4) 

**Effect on Alice**

When Alice subsequently submits her legitimate invoke (nonce=1), the mempool already holds a transaction at `(A, nonce=1)`. Alice's transaction is either rejected outright or must pass fee-escalation against the attacker's slot-holder. The attacker can keep refreshing the slot with new forged transactions (each with a different tx_hash) to maintain the blockade indefinitely.

The forged transaction will fail during batcher execution (blockifier calls `__validate__` with `validate=true` by default), but it has already been admitted and occupies the nonce slot.

---

### Impact Explanation

**Admission of invalid transactions**: The gateway accepts an invoke transaction whose signature has never been verified. This violates the invariant that every admitted transaction has passed account-level authorization.

**Denial of service on nonce-1 slot**: The attacker can permanently occupy the `(address, nonce=1)` slot for any account whose deploy-account transaction is visible in the mempool, preventing the legitimate owner from submitting their first post-deploy invoke without paying escalating fees.

**Wasted block space**: The forged transaction will be included in a block and reverted, consuming L2 gas and block capacity.

This matches the impact category: **High — Mempool/gateway admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

- The attack requires no privileged access. Any observer of the public mempool (P2P or RPC) can extract pending deploy-account addresses.
- The condition `nonce==1 && account_nonce==0` is the normal state for every new account during the deploy+invoke UX flow, making every new account deployment a target window.
- The attacker needs only to submit a well-formed invoke transaction with a random signature; no cryptographic capability is required.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy-account** transaction for the address is pending. For example, expose a `deploy_account_in_pool(address)` query from the mempool that only returns `true` when the pending transaction for that address is of type `DeployAccount`. This closes the gap between the intended invariant ("a deploy-account is pending") and the actual check ("any transaction is pending").

Alternatively, restrict the skip to cases where the gateway itself accepted the deploy-account transaction in the same request batch (e.g., by passing a flag through the gateway flow rather than querying the mempool).

---

### Proof of Concept

```
1. Alice submits DeployAccount(class_hash=C, salt=S, constructor_calldata=D)
   → contract_address A = pedersen(C, S, D, ...)
   → passes __validate_deploy__, enters mempool

2. Attacker queries mempool (RPC starknet_pendingTransactions or P2P gossip)
   → extracts address A from Alice's deploy-account tx

3. Attacker submits:
   Invoke {
     sender_address: A,
     nonce: 1,
     calldata: [<arbitrary>],
     signature: [0x1337, 0xdead],   // forged, not Alice's key
     resource_bounds: <valid>,
   }

4. Gateway flow:
   stateless_validate → OK (no sig check)
   account_nonce = state.get_nonce(A) = 0
   validate_by_mempool → OK (nonce 1 >= 0, no dup hash)
   skip_stateful_validations:
     nonce==1 ✓, account_nonce==0 ✓
     account_tx_in_pool_or_recent_block(A) = true ✓  ← Alice's deploy-account
     → returns true (skip __validate__)
   run_validate_entry_point: validate=false → __validate__ NOT called
   → tx accepted into mempool

5. Alice submits her legitimate Invoke(A, nonce=1, valid_sig)
   → mempool already has (A, nonce=1) from attacker
   → rejected with DuplicateNonce / requires fee escalation

6. Attacker repeats step 3 with new tx_hash (different calldata)
   → Alice's slot remains blocked
``` [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
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

**File:** crates/apollo_mempool/src/mempool.rs (L702-711)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        if self.tx_pool.get_by_tx_hash(tx_reference.tx_hash).is_ok() {
            return Err(MempoolError::DuplicateTransaction { tx_hash: tx_reference.tx_hash });
        }
        self.state.validate_incoming_tx(tx_reference, incoming_account_nonce)
    }
```
