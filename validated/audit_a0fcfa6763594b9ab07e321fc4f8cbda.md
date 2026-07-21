### Title
Gateway Skips `__validate__` for Invoke Transactions Based on Undifferentiated Mempool Presence Check, Allowing Unauthenticated Nonce-1 Admission - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` in the gateway's stateful validator skips the `__validate__` entry-point call (i.e., signature verification) for any Invoke transaction with nonce=1 sent to an account whose on-chain nonce is 0, whenever `account_tx_in_pool_or_recent_block` returns `true`. The mempool-side check returns `true` for **any** transaction present for that address — not specifically a `DeployAccount`. An unprivileged attacker who observes that a victim's `DeployAccount` is pending can immediately submit a crafted Invoke(nonce=1) with an arbitrary or empty signature; the gateway accepts it without running `__validate__`, inserts it into the mempool at nonce=1, and thereby blocks the victim's legitimate first Invoke from that slot.

### Finding Description

**Broken invariant:** Every transaction admitted to the mempool must have passed the account's `__validate__` entry point (signature check). The UX exception — skipping `__validate__` for the first post-deploy Invoke — is gated only on whether *any* transaction for the address exists in the mempool, not on whether that transaction is a `DeployAccount`.

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip `__validate__`) when:
1. The incoming tx is `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0`
3. `account_tx_in_pool_or_recent_block(sender)` returns `true`

**Root cause — `account_tx_in_pool_or_recent_block`:** [2](#0-1) 

This returns `true` if `self.state.contains_account(addr) || self.tx_pool.contains_account(addr)` — it does not filter by transaction type. The comment in `skip_stateful_validations` acknowledges this imprecision ("either it has a deploy_account transaction **or transactions with future nonces that passed validations**") but does not guard against the attacker-controlled case.

**Effect when `skip_validate = true`:** [3](#0-2) 

`validate: !skip_validate` becomes `validate: false`, so `StatefulValidator::validate` never calls the `__validate__` entry point. The transaction is accepted and forwarded to the mempool with no signature check.

**Attack path:**

1. Victim Alice submits `DeployAccount` for address A. It passes `__validate__` (Alice controls the key) and enters `tx_pool` for address A.
2. Attacker calls `add_tx` on the gateway with `Invoke { sender: A, nonce: 1, calldata: <anything>, signature: [] }`.
3. Gateway stateless checks pass (empty signature is within `max_signature_length`). [4](#0-3) 

4. `validate_nonce` passes: `0 ≤ 1 ≤ max_allowed_nonce_gap`. [5](#0-4) 

5. `validate_by_mempool` passes: no duplicate hash, nonce=1 ≥ account_nonce=0, no existing nonce=1 entry (the `DeployAccount` occupies nonce=0). [6](#0-5) 

6. `skip_stateful_validations` returns `true` because `tx_pool.contains_account(A)` is `true` (the `DeployAccount` is there).
7. `run_validate_entry_point` is called with `validate: false` — `__validate__` is **never invoked**.
8. The attacker's Invoke(nonce=1) enters the mempool.
9. Alice's legitimate Invoke(nonce=1) is rejected with `DuplicateNonce`. [7](#0-6) 

10. Batcher executes `DeployAccount` → Alice's account is deployed. Then executes the attacker's Invoke → `__validate__` fails at execution time → transaction rejected, nonce **not** incremented, fee **not** charged.
11. Alice must wait for the next block to resubmit nonce=1. The attacker can immediately repeat step 2 for free (no fee is ever charged for a `__validate__`-failing transaction).

### Impact Explanation

- **Invalid transaction admitted:** The gateway accepts an Invoke with an arbitrary/empty signature into the mempool without running `__validate__`, violating the core admission invariant.
- **Nonce-slot squatting:** The attacker occupies the victim's nonce=1 slot, forcing the victim's first post-deploy Invoke to be delayed by at least one block per attack iteration.
- **Free-of-cost DoS:** Because `__validate__` failure at execution time results in no fee charge and no nonce increment, the attacker bears zero cost per iteration and can repeat indefinitely.
- **Fee-escalation amplification:** If `enable_fee_escalation` is on, the attacker can submit progressively higher-fee malicious Invokes, forcing the victim to outbid them to reclaim nonce=1 — while the attacker never actually pays.

### Likelihood Explanation

The attack requires knowing the victim's account address (deterministic in Starknet, often public) and detecting that a `DeployAccount` is pending. The latter can be inferred by probing the gateway: if `add_tx(Invoke{nonce=1, addr=A})` returns a tx hash rather than a `ValidateFailure`, a `DeployAccount` is pending. No privileged access, no special tooling, and no on-chain funds are required.

### Recommendation

Replace the undifferentiated `account_tx_in_pool_or_recent_block` check with a type-specific query — e.g., `deploy_account_in_pool_or_recent_block(address)` — that returns `true` only when a `DeployAccount` transaction (or a committed deploy event) exists for the address. This preserves the UX intent while closing the unauthenticated-admission path.

### Proof of Concept

```
// 1. Alice submits DeployAccount for address A (valid signature, passes __validate__)
gateway.add_tx(deploy_account_tx { sender: A, nonce: 0, sig: alice_sig })
// → accepted, enters mempool

// 2. Attacker submits Invoke with nonce=1, empty signature
gateway.add_tx(invoke_tx { sender: A, nonce: 1, calldata: [drain_funds], sig: [] })
// → skip_stateful_validations returns true (DeployAccount is in pool)
// → __validate__ NOT called
// → accepted, enters mempool at nonce=1

// 3. Alice submits her legitimate Invoke(nonce=1)
gateway.add_tx(invoke_tx { sender: A, nonce: 1, calldata: [alice_intent], sig: alice_sig })
// → MempoolError::DuplicateNonce  ← Alice is blocked

// 4. Batcher executes DeployAccount → A deployed, nonce becomes 1
// 5. Batcher executes attacker's Invoke → __validate__ fails → rejected, nonce stays 1, fee = 0
// 6. Attacker immediately repeats step 2 for free
``` [1](#0-0) [2](#0-1) [8](#0-7)

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

**File:** crates/apollo_mempool/src/mempool.rs (L768-773)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```
