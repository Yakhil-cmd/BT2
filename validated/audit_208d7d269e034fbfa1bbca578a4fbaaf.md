### Title
Unsigned Invoke Transaction Admitted to Mempool via `skip_stateful_validations` Overly-Broad Mempool Presence Check — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` UX feature is intended to let a user submit a `deploy_account` (nonce 0) and an `invoke` (nonce 1) together before the account exists on-chain. The guard that enables the skip is `account_tx_in_pool_or_recent_block`, which returns `true` if **any** transaction from that address is in the mempool — not specifically a `deploy_account` transaction. An unprivileged attacker who observes a victim's pending `deploy_account` in the mempool can submit an `invoke` with nonce 1 and an arbitrary/empty signature for the victim's address. The gateway will skip the `__validate__` entry-point call entirely and admit the unsigned transaction into the mempool.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip signature validation) when all three conditions hold:
1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

**The guard that is too broad:** [2](#0-1) 

`account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool (`tx_pool.contains_account`) or is known from a committed block (`state.contains_account`). It does not distinguish between a `deploy_account` transaction and an `invoke` transaction.

**How the gateway uses the skip flag:** [3](#0-2) 

When `skip_validate` is `true`, `ExecutionFlags { validate: false, … }` is set, and the blockifier's `perform_validations` returns immediately without calling `__validate__`: [4](#0-3) 

**Attack path:**

1. Victim submits a `deploy_account` tx (nonce 0) → accepted into the mempool.
2. Attacker observes the victim's address in the mempool.
3. Attacker submits an `invoke` tx (nonce 1, empty/forged signature) for the victim's address.
4. Gateway `run_pre_validation_checks`:
   - `validate_state_preconditions`: nonce 1 ≥ account_nonce 0, within `max_allowed_nonce_gap` → **pass**.
   - `validate_by_mempool`: mempool accepts nonce 1 as a future-nonce tx (gap) → **pass**.
   - `skip_stateful_validations`: victim's `deploy_account` is in the pool → returns `true` → **signature check skipped**.
5. `run_validate_entry_point` is called with `skip_validate = true`; `validate = false`; blockifier returns `Ok(())` without calling `__validate__`.
6. The unsigned invoke tx is forwarded to the mempool via `add_tx`. [5](#0-4) 

The comment in `skip_stateful_validations` claims the mempool presence check is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." The second branch of that disjunction is the vulnerability: an attacker can place a future-nonce invoke tx (nonce 1) into the pool for an undeployed account **without a valid signature**, because the skip logic itself is what would have enforced the signature — creating a circular bypass.

---

### Impact Explanation

The gateway admits an `invoke` transaction with an arbitrary/empty signature into the mempool, violating the invariant that every admitted invoke transaction must carry a signature that passes the account's `__validate__` entry point. This matches:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concrete consequences:
- The attacker's unsigned tx occupies a mempool slot for the victim's account at nonce 1, potentially front-running or displacing the victim's own legitimate nonce-1 invoke (if submitted later with a lower tip).
- The tx will be pulled by the batcher and executed; for standard accounts it reverts at `__validate__`, wasting block gas and bouncer budget.
- For any account whose `__validate__` is permissive (no signature check, or a bug in the account contract), the attacker's calldata executes successfully on behalf of the victim.

---

### Likelihood Explanation

The attack requires no special privilege. The attacker only needs to:
1. Watch the public mempool (or the gateway's P2P gossip) for `deploy_account` transactions.
2. Craft an `invoke` with nonce 1 targeting the same address before the victim submits their own nonce-1 tx.

Both steps are trivially automatable. The window is the time between the victim's `deploy_account` entering the mempool and the victim submitting their first `invoke`.

---

### Recommendation

Replace the overly-broad `account_tx_in_pool_or_recent_block` check with a query that specifically confirms a **`deploy_account`** transaction is pending for the address. The mempool should expose a dedicated method such as `has_pending_deploy_account(address)` that inspects the transaction type, not merely the address presence. Until then, the `skip_stateful_validations` bypass should be disabled or gated on a stricter condition.

---

### Proof of Concept

```
# Step 1 – victim submits deploy_account (nonce 0)
POST /gateway/add_transaction
{
  "type": "DEPLOY_ACCOUNT",
  "sender_address": "0xVICTIM",
  "nonce": "0x0",
  "signature": ["<valid sig>"],
  ...
}
# → accepted; mempool now contains deploy_account for 0xVICTIM

# Step 2 – attacker submits invoke (nonce 1, empty signature)
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xVICTIM",
  "nonce": "0x1",
  "signature": [],          # ← no valid signature
  "calldata": ["<drain>"],
  ...
}
# Gateway flow:
#   validate_state_preconditions  → OK  (nonce 1 ≥ account_nonce 0)
#   validate_by_mempool           → OK  (future-nonce gap accepted)
#   skip_stateful_validations     → true (deploy_account is in pool)
#   run_validate_entry_point      → validate=false → OK (no __validate__ call)
# → 200 OK; unsigned invoke admitted to mempool
``` [6](#0-5) [2](#0-1) [4](#0-3)

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
