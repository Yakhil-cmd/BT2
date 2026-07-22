### Title
Signature Validation Bypass via Overly Broad `skip_stateful_validations` Condition Allows Invalid Transactions into Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point (signature check) for any invoke transaction with `nonce == 1` sent to an account whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true`. The check is intended to confirm that a `deploy_account` transaction is pending, but the actual predicate is satisfied by **any** transaction for that address already in the mempool. An attacker who observes a legitimate `deploy_account + invoke` pair in the mempool can submit a second invoke with a higher fee and an **invalid signature** for the same address; the gateway accepts it without calling `__validate__`, and it displaces the victim's legitimate invoke via fee escalation.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks`:

```
validate_state_preconditions  →  validate_by_mempool  →  skip_stateful_validations
``` [1](#0-0) 

The skip condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
``` [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`, meaning the account's `__validate__` entry point is **never executed** at the gateway:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

`account_tx_in_pool_or_recent_block` returns `true` if the address appears in the mempool pool **or** in the mempool's committed/staged state maps — it does **not** distinguish between a `deploy_account` transaction and any other transaction type:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is circular: once Alice's legitimate invoke (nonce 1) is in the mempool via the UX skip, the attacker's invoke also satisfies the predicate — Alice's address is already in the pool — and the attacker's transaction also skips `__validate__`.

The gateway's `validate_nonce` for an invoke with `tx_nonce=1` and `account_nonce=0` passes because `0 ≤ 1 ≤ max_allowed_nonce_gap`: [5](#0-4) 

The mempool's `validate_incoming_tx` also passes because `tx_nonce (1) < account_nonce (0)` is false: [6](#0-5) 

Fee escalation in the mempool allows the attacker's transaction to replace Alice's invoke if the attacker provides a higher fee: [7](#0-6) 

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction (invalid signature) before sequencing.**

An attacker can inject an invoke transaction with an arbitrary (invalid) signature for any account currently in the `deploy_account + invoke` UX flow. The gateway accepts it without running `__validate__`. The attacker's transaction then displaces the victim's legitimate invoke via fee escalation. The victim's invoke is permanently evicted from the mempool and must be resubmitted. The attacker's transaction fails at execution time (the batcher runs `__validate__` with `validate: true`), but if the newly-deployed account has no balance, no fee is charged, making the griefing attack zero-cost to the attacker.

### Likelihood Explanation

The `deploy_account + invoke` UX flow is an explicitly supported and documented feature: [8](#0-7) 

Any attacker monitoring the public mempool can observe a `deploy_account` transaction, derive the target contract address, and immediately submit a competing invoke. The attack requires no privileged access and no knowledge of the victim's private key.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **`deploy_account` transaction** is pending for the sender address. The mempool should expose a dedicated query such as `has_pending_deploy_account(address)` that inspects the pool for a `DeployAccount` transaction type at nonce 0 for the given address. Only when such a transaction is confirmed pending should `skip_stateful_validations` return `true`.

### Proof of Concept

1. Alice submits `deploy_account` (nonce 0) and `invoke` (nonce 1) simultaneously.
2. Gateway accepts `deploy_account` (calls `__validate_deploy__` in transactional state — passes).
3. Gateway accepts Alice's `invoke` (nonce 1): `account_tx_in_pool_or_recent_block` returns `true` (deploy_account is in pool) → `skip_validate = true` → `__validate__` skipped → accepted.
4. Both transactions are now in the mempool. Alice's address is visible.
5. Attacker submits `invoke` (nonce 1, higher fee, **invalid signature**) for Alice's address.
6. Gateway stateless check: passes (signature length within bounds).
7. Gateway `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` → passes.
8. Gateway `validate_by_mempool`: no duplicate hash, `tx_nonce (1) ≥ account_nonce (0)` → passes.
9. Gateway `skip_stateful_validations`: `tx.nonce() == 1 && account_nonce == 0 && account_tx_in_pool_or_recent_block(Alice) == true` → returns `true`.
10. `run_validate_entry_point` called with `validate: false` → `__validate__` **not called**.
11. Attacker's invalid-signature invoke is accepted by the gateway and sent to the mempool.
12. Mempool fee escalation: attacker's invoke (higher fee) replaces Alice's invoke. Alice's transaction is evicted.
13. Batcher executes `deploy_account` → Alice's account is deployed.
14. Batcher executes attacker's invoke with `validate: true` → `__validate__` fails (invalid signature) → transaction reverts. If account has no balance, no fee is charged.
15. Alice's invoke is permanently lost from the mempool. [9](#0-8) [10](#0-9)

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

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L411-443)
```rust
    fn add_tx_validations(
        &mut self,
        tx_reference: TransactionReference,
        tx: &InternalRpcTransaction,
        account_nonce: Nonce,
    ) -> MempoolResult<()> {
        self.validate_incoming_tx(tx_reference, account_nonce)?;
        let replaced_tx_reference = self.validate_fee_escalation(tx_reference)?;

        // The replaced transaction is still pooled, so its bytes still count toward
        // `size_in_bytes()`. Credit what its removal will free: a same-size bump nets to zero (no
        // overflow handling), and a larger replacement only needs room for the delta, consistent
        // with how a fresh next-nonce transaction is treated. The removal happens only after
        // capacity is confirmed below, so a rejected incoming transaction never strands the
        // account.
        let freed_bytes = replaced_tx_reference.map_or(0, |reference| {
            self.tx_pool
                .get_by_tx_hash(reference.tx_hash)
                .expect("Replacement target from pool must exist.")
                .total_bytes()
        });

        if self.exceeds_capacity(tx, freed_bytes) {
            self.handle_capacity_overflow(tx, account_nonce, freed_bytes)?;
        }

        // Capacity is confirmed: this is the final, infallible mutation before the incoming
        // transaction is inserted by the caller.
        if let Some(existing_tx_reference) = replaced_tx_reference {
            self.remove_replaced_tx(existing_tx_reference);
        }

        Ok(())
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_integration_tests/src/utils.rs (L713-726)
```rust
/// Generates a deploy account transaction followed by an invoke transaction from the same account.
/// The first invoke_tx can be inserted to the first block right after the deploy_tx due to
/// the skip_validate feature. This feature allows the gateway to accept this transaction although
/// the account does not exist yet.
pub fn create_deploy_account_tx_and_invoke_tx(
    tx_generator: &mut MultiAccountTransactionGenerator,
    account_id: AccountId,
) -> Vec<RpcTransaction> {
    let undeployed_account_tx_generator = tx_generator.account_with_id_mut(account_id);
    assert!(!undeployed_account_tx_generator.is_deployed());
    let deploy_tx = undeployed_account_tx_generator.generate_deploy_account();
    let invoke_tx = undeployed_account_tx_generator.generate_trivial_rpc_invoke_tx(1);
    vec![deploy_tx, invoke_tx]
}
```
