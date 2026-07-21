### Title
Pending `deploy_account` in mempool enables signature-bypass for nonce-1 invoke transactions — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` UX feature in the gateway's stateful validator allows any attacker to submit an invoke transaction on behalf of any victim account whose `deploy_account` is currently pending in the mempool, without providing a valid signature. The gateway accepts the unsigned invoke, the mempool stores it, and the victim's own legitimate nonce-1 invoke is rejected as a duplicate nonce — blocking the victim's first post-deployment transaction for at least one block.

### Finding Description

`skip_stateful_validations` is designed to let a user submit `deploy_account` (nonce 0) and `invoke` (nonce 1) in the same batch before the account is on-chain. When the conditions below are met, the gateway sets `validate: false` in `ExecutionFlags`, causing `validate_tx` to return `Ok(None)` without ever calling the account's `__validate__` entry point:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    let account_address = tx.sender_address();
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
```

The check only verifies that *some* transaction for `sender_address` exists in the mempool — it does **not** verify that the caller submitting the invoke is the same party who submitted the `deploy_account`, nor does it verify the invoke's signature in any way.

`run_validate_entry_point` then builds the `AccountTransaction` with `validate: !skip_validate`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

When `skip_validate = true`, `validate_tx` short-circuits immediately:

```rust
// crates/blockifier/src/transaction/account_transaction.rs:999-1001
if !self.execution_flags.validate {
    return Ok(None);
}
```

The mempool's own `validate_tx` only checks for duplicate hashes and fee escalation — it performs no signature check. So the attacker's unsigned invoke is stored in the mempool under the victim's address at nonce 1.

**Attack scenario:**

1. Alice submits `deploy_account` (nonce 0) → accepted, enters mempool.
2. Bob observes Alice's address in the mempool and submits `invoke` with `sender_address = Alice`, `nonce = 1`, arbitrary `calldata`, and an empty or garbage signature.
3. Gateway: `account_nonce == 0`, `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(Alice) == true` → `skip_validate = true` → no `__validate__` call → **accepted**.
4. Mempool: no duplicate nonce for Alice at nonce 1 → **accepted**.
5. Alice submits her own legitimate invoke (nonce 1) → mempool returns `DuplicateNonce` → **rejected**.
6. Batcher executes the block: `deploy_account` succeeds; Bob's invoke is executed with `validate: true` (via `AccountTransaction::new_for_sequencing`), `__validate__` is called, fails (wrong signature), transaction is rejected/reverted.
7. Alice can now resubmit her invoke — delayed by one full block.

The attacker can repeat steps 2–7 indefinitely to persistently block Alice's nonce-1 invoke at zero cost (Bob's transaction is rejected, so no fee is charged to Bob if `__validate__` fails before execution).

### Impact Explanation

This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

An invalid transaction — one with no valid account signature — is admitted through the gateway and mempool. The victim's valid transaction is simultaneously rejected as a duplicate nonce. The attacker can sustain this to permanently prevent the victim from ever landing their first post-deployment invoke, or force the victim to pay a higher fee to replace the attacker's transaction via fee escalation (if enabled).

### Likelihood Explanation

The window is observable: any watcher of the mempool's `account_tx_in_pool_or_recent_block` API (or the P2P gossip layer) can detect a pending `deploy_account` and race to submit a spoofed nonce-1 invoke. No privileged access is required. The only constraint is that the victim's account must not yet be deployed (on-chain nonce = 0), which is exactly the state during the `deploy_account` + `invoke` UX flow.

### Recommendation

Before skipping `__validate__`, verify that the incoming invoke's signature is consistent with the `deploy_account` transaction already in the mempool — i.e., that both share the same `sender_address` **and** the invoke was submitted by the same party (e.g., by checking the invoke's signature against the public key embedded in the pending `deploy_account`'s constructor calldata). Alternatively, restrict the skip to cases where the gateway can cryptographically confirm the invoke originates from the account owner, rather than relying solely on the presence of any transaction for that address in the mempool.

### Proof of Concept

```
1. Alice calls gateway.add_tx(deploy_account_tx { sender: Alice, nonce: 0, sig: valid })
   → accepted; mempool.account_tx_in_pool_or_recent_block(Alice) == true

2. Bob calls gateway.add_tx(invoke_tx { sender: Alice, nonce: 1, calldata: [arbitrary], sig: [] })
   → skip_stateful_validations returns true (nonce==1, account_nonce==0, Alice in pool)
   → validate_tx short-circuits (execution_flags.validate == false)
   → mempool.validate_tx passes (no duplicate nonce at Alice/1)
   → Bob's invoke stored in mempool

3. Alice calls gateway.add_tx(invoke_tx { sender: Alice, nonce: 1, sig: valid })
   → mempool.validate_tx returns MempoolError::DuplicateNonce { address: Alice, nonce: 1 }
   → Alice's invoke REJECTED

4. Batcher executes block:
   - deploy_account succeeds (Alice's account deployed)
   - Bob's invoke: AccountTransaction::new_for_sequencing sets validate:true
     → __validate__ called on Alice's contract → fails (invalid sig) → rejected
   
5. Bob repeats step 2 → Alice's nonce-1 invoke is blocked indefinitely
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L992-1001)
```rust
impl ValidatableTransaction for AccountTransaction {
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-711)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }

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
