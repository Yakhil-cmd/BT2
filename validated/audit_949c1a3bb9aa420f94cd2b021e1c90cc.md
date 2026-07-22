### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` Signature Check for Invoke Transactions When Any Mempool Transaction Exists for Sender, Not Just `deploy_account` - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway is intended to skip the `__validate__` entry-point (signature verification) for an invoke transaction with nonce=1 only when a `deploy_account` transaction is pending in the mempool for the same sender. However, the guard `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from the sender's address — not specifically a `deploy_account`. An unprivileged attacker can exploit this by first submitting a valid invoke with nonce=0 (which passes all checks), then submitting an invoke with nonce=1 carrying an invalid or arbitrary signature. The gateway skips `__validate__` for the second transaction and admits it to the mempool without any signature verification.

---

### Finding Description

In `skip_stateful_validations` the skip condition is:

```
tx is Invoke
AND tx.nonce() == 1
AND account_nonce == 0
AND account_tx_in_pool_or_recent_block(sender) == true
``` [1](#0-0) 

The comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is incorrect. An invoke with nonce=0 passes nonce validation when `account_nonce == 0` (the range check `account_nonce <= tx_nonce <= account_nonce + max_allowed_nonce_gap` is satisfied), so it can be in the mempool without any `deploy_account` ever being submitted. [2](#0-1) 

The `account_tx_in_pool_or_recent_block` function checks for the presence of **any** transaction from the address in the pool or recent block state — it does not filter by transaction type: [3](#0-2) 

When `skip_validate=true` is returned, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, causing `StatefulValidator::perform_validations` to return `Ok(())` immediately after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point: [4](#0-3) [5](#0-4) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering and duplicate hashes — it does not verify signatures: [6](#0-5) 

---

### Impact Explanation

The gateway's stateful validation path is the only place where the account's `__validate__` entry point (signature verification) is executed before a transaction enters the mempool. When this check is skipped for an invoke with nonce=1 based on a non-`deploy_account` transaction being present in the mempool, the gateway admits a transaction with an invalid or forged signature. This violates the invariant that every transaction in the mempool has passed account-level signature verification.

**Matching impact**: *High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

---

### Likelihood Explanation

Any unprivileged user can trigger this with two sequential RPC calls:

1. Submit a valid `invoke` with `nonce=0` for a fresh address (passes all stateless and stateful checks; `account_nonce=0`, nonce range `[0, max_allowed_nonce_gap]` is satisfied).
2. Submit an `invoke` with `nonce=1` and an **invalid/arbitrary signature**.

After step 1, `account_tx_in_pool_or_recent_block` returns `true` for the sender. In step 2, the gateway sees `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block==true` and sets `skip_validate=true`, admitting the unsigned transaction to the mempool.

No privileged access, special keys, or unusual network conditions are required.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a type-specific query that returns `true` only when a `deploy_account` transaction for the sender's address is present in the mempool or a recent committed block. Concretely, add a new mempool API such as `deploy_account_tx_in_pool_or_recent_block(address)` that inspects the transaction type before returning `true`, and use that in `skip_stateful_validations` instead of the current call. [7](#0-6) 

---

### Proof of Concept

```
// Step 1: attacker controls fresh address X (no on-chain state, nonce = 0)

// Submit valid invoke with nonce=0 — passes all gateway checks
POST /gateway/add_transaction
{
  type: "INVOKE",
  sender_address: X,
  nonce: 0,
  signature: <valid>,
  resource_bounds: { l2_gas: { max_amount: N, max_price_per_unit: P } }
}
// → admitted to mempool; account_tx_in_pool_or_recent_block(X) now returns true

// Step 2: submit invoke with nonce=1 and INVALID signature
POST /gateway/add_transaction
{
  type: "INVOKE",
  sender_address: X,
  nonce: 1,
  signature: [0x0, 0x0],   // invalid / forged
  resource_bounds: { l2_gas: { max_amount: N, max_price_per_unit: P } }
}
// Gateway path:
//   validate_nonce: 0 <= 1 <= 0+max_allowed_nonce_gap  → OK
//   validate_by_mempool: nonce ordering OK, no duplicate hash → OK
//   skip_stateful_validations:
//     tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(X)==true
//     → returns true (skip __validate__)
//   run_validate_entry_point: validate=false → __validate__ NOT called
// → transaction with invalid signature admitted to mempool
```

The transaction with the forged signature now resides in the mempool. The batcher will eventually attempt execution and reject it, but the gateway's admission invariant — that every mempool transaction has passed account-level signature verification — has been broken, enabling mempool pollution and wasted batcher resources at negligible cost to the attacker.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
