### Title
Signature Validation Bypass via `skip_stateful_validations` for Invoke Transactions with Nonce=1 — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point call (the only place account signatures are verified) for any invoke transaction with `nonce == 1` sent to an address that has **any** transaction in the mempool or a recent block. An unprivileged attacker can exploit this to inject an invoke transaction carrying an arbitrary/invalid signature into the mempool without ever having that signature checked.

---

### Finding Description

The gateway stateful-validation path in `extract_state_nonce_and_run_validations` runs three sequential steps:

1. `validate_state_preconditions` — checks resource bounds and nonce range.
2. `validate_by_mempool` — checks for duplicate tx-hash and nonce ordering.
3. `skip_stateful_validations` — decides whether to skip the `__validate__` entry-point call. [1](#0-0) 

`skip_stateful_validations` returns `true` (skip) when all three conditions hold:

```
tx is Invoke  AND  tx.nonce() == 1  AND  account_nonce == 0
AND  account_tx_in_pool_or_recent_block(sender_address) == true
``` [2](#0-1) 

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the function returns `Ok(())` immediately without calling `__validate__`: [4](#0-3) 

And in `AccountTransaction::validate_tx`, the same flag causes an early `Ok(None)` return: [5](#0-4) 

The critical flaw is in the guard condition. The code comment claims:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

But `account_tx_in_pool_or_recent_block` checks whether **any** transaction from that address is present — it does not verify that the pending transaction is a `deploy_account` from the legitimate owner: [6](#0-5) 

`MempoolState::contains_account` returns `true` if the address appears in either the staged or committed nonce maps: [7](#0-6) 

An attacker who knows that victim address `X` has a pending `deploy_account` (nonce=0) in the mempool can submit an invoke transaction for `X` with `nonce=1` and a completely arbitrary signature. The nonce check passes because `0 ≤ 1 ≤ max_allowed_nonce_gap`: [8](#0-7) 

The mempool's `validate_tx` only checks for duplicate tx-hash and nonce ordering — it never inspects the signature: [9](#0-8) 

The stateless validator only checks signature **length**, not cryptographic validity: [10](#0-9) 

No other guard in the gateway pipeline verifies the signature content. The transaction is admitted to the mempool with an invalid signature and no `__validate__` call ever made.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions.**

An attacker can inject invoke transactions with arbitrary signatures for any account that has a pending `deploy_account` (or any other transaction) in the mempool. These transactions bypass the only cryptographic authorization check (`__validate__`) at the gateway level. The mempool accepts them, and the batcher will attempt to execute them. During batcher execution, `__validate__` is called with `validate: true` (the batcher sets its own `execution_flags`), the invalid signature causes execution failure, and the transaction is rejected — but only after consuming batcher resources and occupying a mempool slot.

This enables:
- Targeted DoS against any account currently deploying (pending `deploy_account`).
- Mempool flooding with signature-invalid transactions for any known pending address.
- Wasted batcher execution cycles on transactions that will always fail.

---

### Likelihood Explanation

**High.** The trigger requires only:
1. Knowledge of a victim address with a pending `deploy_account` in the mempool (observable via the public `/mempoolSnapshot` endpoint or P2P gossip).
2. Submission of a single invoke transaction with `nonce=1` and any payload.

No privileged access, special keys, or cryptographic capability is required. The condition `account_tx_in_pool_or_recent_block` is trivially satisfied for any address that has ever had a transaction committed (the committed map is retained across blocks).

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** for the sender address is pending in the mempool. The mempool should expose a dedicated query such as `has_pending_deploy_account(address) -> bool` that inspects the transaction type, not just address presence.

Alternatively, remove the `skip_stateful_validations` shortcut entirely and require all invoke transactions to pass `__validate__` at the gateway, accepting the UX trade-off of requiring users to submit `deploy_account` before `invoke`.

---

### Proof of Concept

**Setup:**
- Victim `Alice` submits `deploy_account` for address `0xALICE` (nonce=0). It is admitted to the mempool. `account_tx_in_pool_or_recent_block(0xALICE)` now returns `true`.

**Attack:**
1. Attacker constructs an `RpcInvokeTransactionV3` with:
   - `sender_address = 0xALICE`
   - `nonce = 1`
   - `signature = [0xDEAD, 0xBEEF]` (arbitrary, 2 felts — passes the size check)
   - Valid resource bounds above the minimum gas price threshold.

2. Attacker submits to the gateway `add_tx` endpoint.

3. Gateway stateless validation: signature length ≤ `max_signature_length` → **passes**.

4. `convert_rpc_tx_to_internal_rpc_tx`: tx_hash computed from fields (signature is part of hash input but not verified) → **passes**.

5. `extract_state_nonce_and_run_validations`:
   - `get_nonce_from_state(0xALICE)` → `Nonce(0)` (not deployed yet).
   - `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` → **passes**.
   - `validate_by_mempool`: no duplicate hash, nonce not too old → **passes**.
   - `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(0xALICE)==true` → returns **`true`** (skip).
   - `run_validate_entry_point(skip_validate=true)`: `validate=false`, `__validate__` **never called**.

6. `mempool_client.add_tx(...)` → attacker's invoke tx with invalid signature is **admitted to the mempool**.

**Result:** An invoke transaction with a signature `[0xDEAD, 0xBEEF]` that would fail any real ECDSA check is now queued for sequencing. The batcher will pick it up, call `__validate__`, fail, and reject it — but the admission invariant is broken and the attack can be repeated indefinitely for any address with a pending deploy.

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L142-150)
```rust
    fn validate_tx_size(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        self.validate_tx_extended_calldata_size(tx)?;
        self.validate_tx_signature_size(tx)?;
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_proof_size(invoke_tx)?;
        }

        Ok(())
    }
```
