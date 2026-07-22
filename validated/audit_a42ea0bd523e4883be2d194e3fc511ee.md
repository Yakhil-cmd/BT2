### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures via Overly Broad Mempool Presence Check - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator bypasses the `__validate__` entry-point call (signature verification) for any invoke transaction with `nonce == 1` whenever the sender account has *any* transaction present in the mempool or a recent block — not exclusively a `deploy_account` transaction. An attacker who controls an account with on-chain nonce 0 can first submit a valid invoke with nonce=0 (or a valid `deploy_account`), then immediately submit a second invoke with nonce=1 carrying an arbitrary/invalid signature. The gateway admits the second transaction to the mempool without ever calling `__validate__`, satisfying the "High — Mempool/gateway/RPC admission accepts invalid transactions" impact criterion.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, the function `skip_stateful_validations` returns `true` — causing `run_validate_entry_point` to set `execution_flags.validate = false` and skip the `__validate__` call — whenever all three conditions hold:

1. The transaction is an `Invoke` with `nonce == Nonce(Felt::ONE)`,
2. The on-chain account nonce is `Nonce(Felt::ZERO)`, and
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

Condition 3 is implemented by `Mempool::account_tx_in_pool_or_recent_block`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

This returns `true` for **any** transaction from the account — including a plain invoke with nonce=0 — not only for a `deploy_account` transaction. The code comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is incorrect: a valid invoke with nonce=0 in the mempool does not imply that a subsequent invoke with nonce=1 carries a valid signature.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, this causes an early return before `__validate__` is called: [4](#0-3) 

After stateful validation passes, `add_tx_inner` in the gateway unconditionally forwards the transaction to the mempool: [5](#0-4) 

**Attack path (deploy_account + invalid invoke):**

1. Attacker creates a valid `deploy_account` for address X → enters mempool; on-chain nonce of X is still 0.
2. Attacker submits `invoke(sender=X, nonce=1, signature=[0xdead, 0xbeef])` (invalid signature).
   - Stateless validation: passes (signature length ≤ limit, resource bounds valid).
   - `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce` → passes. [6](#0-5) 
   - `validate_by_mempool`: no duplicate nonce=1 → passes.
   - `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block=true` → returns `true`.
   - `run_validate_entry_point`: `skip_validate=true` → `__validate__` **not called**.
3. Invalid invoke is forwarded to the mempool and admitted.

**Alternative path (account deployed via `deploy` syscall, nonce=0 in state):**

An account deployed via a `deploy` syscall (not `deploy_account`) has on-chain nonce=0. The attacker submits a valid invoke with nonce=0 first, then an invalid invoke with nonce=1 — same result.

### Impact Explanation

The gateway admits an invoke transaction with an invalid (or completely absent) signature to the mempool without any signature verification. This directly satisfies the **"High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing"** criterion. An attacker can repeatedly inject signature-invalid transactions into the mempool, consuming mempool capacity and potentially displacing legitimate transactions. The batcher re-validates with `validate: true` via `AccountTransaction::new_for_sequencing` [7](#0-6)  and will reject the invalid transaction during execution, so no unauthorized state change occurs — but the mempool admission invariant is broken.

### Likelihood Explanation

No privileged access is required. Any user can create a `deploy_account` transaction (or deploy an account via syscall) and then submit an invalid invoke with nonce=1. With multiple accounts, the attack scales linearly. The only cost to the attacker is the fee for the valid `deploy_account` transactions; the invalid invokes are admitted for free and rejected by the batcher without fee collection.

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is present in the mempool for the sender address. Add a dedicated mempool API such as `deploy_account_in_pool(address) -> bool` that only returns `true` when a `deploy_account` transaction (not any transaction type) is queued for that address. This preserves the intended UX for the deploy_account + invoke flow while closing the signature-bypass window for accounts that have other transaction types in the mempool.

### Proof of Concept

1. Deploy account X via `deploy_account` (or via `deploy` syscall from another contract, leaving nonce=0).
2. Submit `invoke(sender=X, nonce=0, calldata=..., signature=<valid>)` → accepted, enters mempool. On-chain nonce of X remains 0.
3. Before the nonce=0 tx is committed, submit `invoke(sender=X, nonce=1, calldata=..., signature=[0x1337, 0x1337])` (invalid ECDSA signature).
4. Observe: gateway returns a transaction hash (success); transaction appears in the mempool.
5. When the batcher processes it, `__validate__` is called with `validate: true`, the signature check fails, and the tx is rejected — but it was admitted to the mempool without any signature verification, violating the admission invariant.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway/src/gateway.rs (L275-286)
```rust
        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
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
