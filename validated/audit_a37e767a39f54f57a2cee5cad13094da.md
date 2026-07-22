### Title
Gateway Admits Unsigned Invoke Transactions for Any Account With a Pending Deploy-Account via Unchecked `skip_stateful_validations` - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips `__validate__` (signature verification) for invoke transactions with `nonce=1` when the account's on-chain nonce is `0` and `account_tx_in_pool_or_recent_block` returns `true`. This check does not verify that the submitter of the invoke transaction is the account owner — it only checks whether *any* transaction from that address exists in the mempool. An attacker can submit an invoke transaction for a victim's address with an invalid signature and have it admitted to the mempool without signature verification, as long as the victim has a pending `deploy_account` transaction.

---

### Finding Description

The `skip_stateful_validations` function implements a UX feature that allows a user to submit a `deploy_account` + `invoke` pair simultaneously, skipping `__validate__` for the invoke because the account doesn't exist on-chain yet:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-461
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false` in the execution flags:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The blockifier's `StatefulValidator::perform_validations` then returns early without calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The authorization check used is `account_tx_in_pool_or_recent_block`, which returns `true` if the account address appears in the mempool pool or in a committed block:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

This check does **not** verify that the submitter of the invoke transaction is the account owner. It only checks whether the address appears anywhere in the mempool. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this reasoning does not account for the fact that the check is performed on the `sender_address` field of the attacker-controlled invoke transaction — not on the identity of the submitter. [5](#0-4) 

**Attack sequence:**

1. Victim submits a `deploy_account` transaction for address `A` (nonce=0). This passes normal gateway validation and is admitted to the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
2. Attacker submits an invoke transaction with `sender_address=A`, `nonce=1`, and an **arbitrary/invalid signature**.
3. Gateway stateful validation: `account_nonce=0` (A not deployed), `tx.nonce()=1`, `account_tx_in_pool_or_recent_block(A)=true` → all three conditions satisfied → `skip_stateful_validations` returns `true`.
4. `run_validate_entry_point` sets `validate: false` → `__validate__` is never called.
5. The attacker's invalid invoke transaction is admitted to the mempool without any signature check.

The nonce check in `validate_nonce` does not block this: for `account_nonce=0` and `tx_nonce=1`, the range check `0 <= 1 <= 200` passes. [6](#0-5) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

The gateway admits invoke transactions with invalid signatures for any account that has a pending `deploy_account` in the mempool. The admitted transactions will fail during batcher execution when `__validate__` is run, but they have already been accepted into the mempool. Consequences include:

- **Mempool pollution**: An attacker can flood the mempool with invalid invoke transactions targeting any account with a pending `deploy_account`, wasting mempool capacity and batcher resources.
- **Nonce slot occupation**: The attacker's invalid nonce=1 transaction occupies the nonce=1 slot for the victim's account. Depending on mempool fee-escalation rules, this may delay or displace the victim's legitimate invoke transaction.
- **Unauthorized transaction admission**: The gateway's invariant — that only transactions passing signature verification (or with a legitimate UX skip) are admitted — is broken. Any unprivileged attacker can trigger this by observing the public mempool for pending `deploy_account` transactions.

---

### Likelihood Explanation

`deploy_account` transactions are publicly visible in the mempool. Any attacker monitoring the mempool can immediately submit a crafted invoke transaction for any newly seen `deploy_account` sender address. No special privileges, keys, or prior state are required. The attack is trivially automatable.

---

### Recommendation

The `skip_stateful_validations` function must verify that the existing mempool transaction for the account is specifically a `deploy_account` transaction, not just any transaction. The `account_tx_in_pool_or_recent_block` API should be replaced with a more specific check, such as `deploy_account_tx_in_pool(sender_address)`, that returns `true` only when a `deploy_account` transaction for that exact address is pending in the mempool.

Alternatively, the gateway could require the user to provide the hash of their own `deploy_account` transaction (as the `native_blockifier` `PyValidator` does via the `deploy_account_tx_hash` parameter), and verify that this hash corresponds to a pending `deploy_account` for the same `sender_address` before skipping `__validate__`. [7](#0-6) 

---

### Proof of Concept

```
1. Victim submits:
   deploy_account_tx {
     sender_address: 0xVICTIM,
     nonce: 0,
     signature: <valid>,
     ...
   }
   → Admitted to mempool. account_tx_in_pool_or_recent_block(0xVICTIM) == true.

2. Attacker submits:
   invoke_tx {
     sender_address: 0xVICTIM,   // victim's address
     nonce: 1,
     signature: [0xDEAD, 0xBEEF], // arbitrary invalid signature
     calldata: <anything>,
     resource_bounds: <valid>,
   }

3. Gateway stateful validation path:
   - get_nonce_from_state(0xVICTIM) → Nonce(0)   [account not deployed]
   - validate_nonce: 0 <= 1 <= 200 → OK
   - skip_stateful_validations:
       tx.nonce() == 1 ✓
       account_nonce == 0 ✓
       account_tx_in_pool_or_recent_block(0xVICTIM) == true ✓
       → returns true (skip)
   - run_validate_entry_point: validate=false → __validate__ NOT called → Ok(())

4. Attacker's invoke tx with invalid signature is admitted to the mempool.
``` [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-110)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
```
