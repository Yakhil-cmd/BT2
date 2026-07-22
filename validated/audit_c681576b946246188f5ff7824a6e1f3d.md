### Title
`skip_stateful_validations` admits invoke transactions without signature validation by checking `account_tx_in_pool_or_recent_block` instead of verifying a `deploy_account` exists — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function is designed to let users submit a `deploy_account + invoke(nonce=1)` pair atomically. It skips the `__validate__` entry-point call for the invoke when the account is not yet deployed, provided a deploy_account is already in the mempool. The guard it uses — `account_tx_in_pool_or_recent_block(sender_address)` — returns `true` for **any** transaction in the mempool for that address, not specifically a `deploy_account`. An attacker who observes a victim's `deploy_account` in the mempool can immediately submit an invoke from the victim's address with an arbitrary/invalid signature; the gateway skips `__validate__` and admits the transaction. The victim's legitimate invoke is then rejected by the mempool with `DuplicateNonce`.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when three conditions hold for an incoming invoke:

1. `tx.nonce() == Nonce(Felt::ONE)`
2. `account_nonce == Nonce(Felt::ZERO)` (account not yet on-chain)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When all three hold, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false` and therefore never calls the account's `__validate__` entry point: [2](#0-1) 

The code comment claims the mempool check is sufficient:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This claim is false. `account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`MempoolState::contains_account` checks only whether the address appears in the `staged` or `committed` maps — it carries no information about the **type** of transaction stored: [4](#0-3) 

**Attack scenario:**

| Step | Actor | Action |
|------|-------|--------|
| 1 | Alice | Submits `deploy_account(nonce=0)` to address X → admitted to mempool |
| 2 | Bob | Observes Alice's `deploy_account` in the mempool; extracts address X |
| 3 | Bob | Submits `invoke(nonce=1, sender=X, signature=<garbage>)` |
| 4 | Gateway | `validate_state_preconditions`: nonce 1 ≥ account_nonce 0 → passes |
| 5 | Gateway | `validate_by_mempool`: no existing nonce-1 tx for X → passes |
| 6 | Gateway | `skip_stateful_validations`: Alice's deploy_account is in pool → returns `true` |
| 7 | Gateway | `run_validate_entry_point(skip_validate=true)` → `__validate__` **never called** |
| 8 | Mempool | Bob's invalid invoke admitted at nonce=1 for address X |
| 9 | Alice | Submits `invoke(nonce=1, sender=X, signature=<valid>)` |
| 10 | Gateway | `validate_by_mempool` → `DuplicateNonce` → Alice's invoke **rejected** |

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering and fee-escalation rules; it does not inspect transaction type: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

The gateway **admits an invalid transaction** (Bob's invoke with no valid signature) into the mempool by skipping the `__validate__` entry-point check. Simultaneously, it **rejects a valid transaction** (Alice's correctly-signed invoke) with `DuplicateNonce`. This directly matches the High impact criterion:

> *Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

If fee escalation is disabled (`enable_fee_escalation = false`), Alice's invoke is permanently blocked until Bob's invalid invoke is eventually executed and rejected by the batcher, at which point Bob can immediately repeat the attack. If fee escalation is enabled, Alice is forced to pay a higher fee to replace Bob's transaction — an economic cost imposed by the attacker at zero cost to themselves.

---

### Likelihood Explanation

The attack requires only that the attacker observe a `deploy_account` transaction in the mempool (public information on any node with a public RPC endpoint) and submit an invoke to the same address before the victim does. No cryptographic material, privileged access, or special contract is needed. The attacker pays only the gas for their own invalid invoke submission attempt (which is rejected at the gateway level for the signature check, so no fee is charged). The attack is repeatable.

---

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists in the mempool for the sender address. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type stored for the address, rather than merely checking address presence. Alternatively, the gateway can track pending deploy-account hashes per address and verify the specific hash is present before granting the validation skip.

---

### Proof of Concept

```
1. Alice submits:
     deploy_account { class_hash, salt, constructor_calldata=[alice_pubkey], nonce=0, sig=<valid> }
     → gateway runs __validate_deploy__, passes, tx admitted to mempool for address X

2. Bob observes Alice's deploy_account in the mempool, extracts address X.

3. Bob submits:
     invoke { sender_address=X, nonce=1, calldata=[...], sig=[0xdeadbeef] }

4. Gateway stateful path:
     account_nonce = get_nonce_from_state(X) = 0          // X not yet on-chain
     validate_state_preconditions: nonce 1 in [0, 0+max_gap] → OK
     validate_by_mempool: no nonce-1 tx for X in pool → OK
     skip_stateful_validations:
         tx.nonce()==1 && account_nonce==0 → true
         account_tx_in_pool_or_recent_block(X) → true  // Alice's deploy_account is there
         returns true  ← __validate__ SKIPPED
     run_validate_entry_point(skip_validate=true) → no __validate__ call
     → Bob's invoke admitted to mempool

5. Alice submits:
     invoke { sender_address=X, nonce=1, calldata=[...], sig=<valid ECDSA> }

6. Gateway stateful path:
     validate_by_mempool → MempoolError::DuplicateNonce { address: X, nonce: 1 }
     → Alice's valid invoke REJECTED
``` [1](#0-0) [3](#0-2) [2](#0-1)

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
