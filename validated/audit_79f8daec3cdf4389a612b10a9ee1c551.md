### Title
Gateway `skip_stateful_validations` accepts invalid-signature invoke transactions via fee escalation on undeployed accounts - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
The `skip_stateful_validations` function skips the `__validate__` entry point (signature check) for any invoke transaction with nonce=1 whenever the sender address has *any* transaction in the mempool — not specifically a `deploy_account`. An unprivileged attacker can exploit this by submitting a fee-escalating invoke transaction with an invalid signature from a victim's undeployed account address, bypassing signature verification and getting the invalid transaction accepted into the mempool, where it replaces the victim's valid transaction.

### Finding Description

The `skip_stateful_validations` function returns `true` (skip `__validate__`) when three conditions hold simultaneously:

1. The transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

Condition (3) is satisfied whenever **any** transaction from the address is in the mempool — the code comment explicitly acknowledges this: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."* [2](#0-1) 

The mempool's `account_tx_in_pool_or_recent_block` implementation confirms it checks for any account presence, not specifically a `deploy_account`: [3](#0-2) 

The gateway's `run_pre_validation_checks` calls these in order: (a) `validate_state_preconditions`, (b) `validate_by_mempool` (fee escalation check), (c) `skip_stateful_validations`, then (d) `run_validate_entry_point` with `validate: !skip_validate`: [4](#0-3) [5](#0-4) 

When `skip_validate=true`, the `AccountTransaction` is constructed with `validate: false`, so `validate_tx` returns `Ok(None)` immediately without calling the `__validate__` entry point: [6](#0-5) 

**Attack scenario:**

1. Alice submits `deploy_account(nonce=0)` and `invoke(nonce=1, fee=F, valid_sig)` simultaneously (the intended UX flow).
2. Alice's `deploy_account` enters the mempool; `account_tx_in_pool_or_recent_block(Alice)` now returns `true`.
3. Alice's own `invoke(nonce=1)` also skips `__validate__` for the same reason and enters the mempool.
4. Bob submits `invoke(sender=Alice, nonce=1, fee=F+1, invalid_sig)`.
5. **`validate_state_preconditions`**: nonce=1 ≥ account_nonce=0, within `max_allowed_nonce_gap=200` → passes.
6. **`validate_by_mempool`**: fee escalation F+1 > F → passes.
7. **`skip_stateful_validations`**: `account_tx_in_pool_or_recent_block(Alice)` = `true` → returns `true` (skip).
8. **`run_validate_entry_point`**: `__validate__` is **not called**; Bob's invalid-signature tx is accepted.
9. Bob's tx is added to the mempool via `mempool.add_tx`, replacing Alice's valid invoke via fee escalation.
10. Alice's `deploy_account` executes → account deployed.
11. Bob's invoke executes → fails signature check → rejected.
12. Alice's nonce=1 tx is permanently gone from the mempool.

The `mempool.validate_tx` path that runs during step 6 is: [7](#0-6) 

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An unprivileged attacker can grief any user of the deploy_account + invoke UX feature by replacing their valid nonce=1 invoke transaction with an invalid-signature transaction. The victim's transaction is permanently evicted from the mempool. The invalid transaction will fail during block execution and be rejected, but the victim must resubmit their transaction (potentially at a higher fee, and potentially missing time-sensitive execution windows). The attacker's only cost is paying a marginally higher fee than the victim.

### Likelihood Explanation

**Medium.** The attacker must:
- Monitor the mempool for `deploy_account` transactions (publicly observable in a distributed node).
- Submit a fee-escalating invoke before the victim's `deploy_account` is included in a block.
- Pay a fee slightly higher than the victim's invoke fee.

No privileged access, special contract, or cryptographic capability is required. The window is the time between the victim's `deploy_account` entering the mempool and being committed to a block.

### Recommendation

**Short term:** In `skip_stateful_validations`, replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is pending for the sender address. The mempool should expose a `has_pending_deploy_account(address)` query, or the gateway should inspect the transaction type of the pending transaction.

**Long term:** Audit all other callers of `account_tx_in_pool_or_recent_block` to ensure none rely on the implicit assumption that the presence of any transaction implies a pending `deploy_account`. Document the invariant that `skip_stateful_validations` is only safe when the pending transaction is specifically a `deploy_account`.

### Proof of Concept

```
# State: Alice's account does not exist on-chain (nonce = 0)

# Step 1: Alice submits deploy_account + invoke simultaneously
POST /gateway/add_transaction
  deploy_account { sender: Alice, nonce: 0, sig: valid_alice_sig }

POST /gateway/add_transaction
  invoke { sender: Alice, nonce: 1, fee: 100, calldata: [...], sig: valid_alice_sig }
  # Alice's invoke skips __validate__ because deploy_account is in pool
  # Both accepted into mempool

# Step 2: Bob submits fee-escalating invoke with invalid signature
POST /gateway/add_transaction
  invoke { sender: Alice, nonce: 1, fee: 101, calldata: [...], sig: [0xdeadbeef] }
  # validate_state_preconditions: nonce=1 >= 0, within gap=200 → OK
  # validate_by_mempool: fee 101 > 100, fee escalation passes → OK
  # skip_stateful_validations: account_tx_in_pool_or_recent_block(Alice) = true → skip=true
  # run_validate_entry_point: __validate__ NOT called
  # ACCEPTED — replaces Alice's invoke in mempool

# Step 3: Block is produced
  deploy_account executes → Alice's account deployed, nonce becomes 1
  Bob's invoke executes → __validate__ called → INVALID SIGNATURE → rejected
  Alice's valid invoke is gone; she must resubmit
```

The root cause is at: [8](#0-7)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
