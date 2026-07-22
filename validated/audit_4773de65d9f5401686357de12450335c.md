### Title
Signature Validation Bypass via `skip_stateful_validations` Overly Broad Mempool Presence Check — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point (signature check) for any Invoke transaction with `nonce == 1` when the account's on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true`. The check is supposed to confirm a pending `deploy_account` exists, but it returns `true` for **any** transaction type in the pool for that address. An attacker who observes a legitimate user's `deploy_account` in the mempool can immediately submit an Invoke with `nonce=1` carrying an **invalid signature**; the gateway accepts it without signature validation, and the legitimate user's subsequent valid Invoke with `nonce=1` is rejected as a duplicate nonce.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When `skip_validate == true`, `run_validate_entry_point` sets `execution_flags.validate = false`, so the blockifier's `StatefulValidator` skips the `__validate__` call entirely: [2](#0-1) 

**The overly broad check — `account_tx_in_pool_or_recent_block`:** [3](#0-2) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

`tx_pool.contains_account` returns `true` if the address has **any** transaction in the pool — not specifically a `deploy_account`. The code comment claims this is sufficient because it "means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but the latter is circular: those future-nonce transactions may themselves have skipped validation via this same path.

**Attack flow:**

1. Alice submits a valid `deploy_account` for address `A` → accepted into the mempool. `tx_pool.contains_account(A)` is now `true`.
2. Attacker submits `Invoke(sender=A, nonce=1, signature=INVALID)`.
3. Gateway stateful validation:
   - `validate_nonce`: `0 ≤ 1 ≤ max_gap` → passes. [4](#0-3) 
   - `validate_by_mempool`: no duplicate hash, nonce not too old, no existing nonce-1 tx → passes. [5](#0-4) 
   - `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`. [6](#0-5) 
   - `run_validate_entry_point`: `validate=false` → `__validate__` is **never called**. [7](#0-6) 
4. Attacker's invalid-signature Invoke is admitted to the mempool.
5. Alice submits `Invoke(sender=A, nonce=1, signature=VALID)`.
6. `validate_fee_escalation` finds an existing nonce-1 tx for address `A` → `MempoolError::DuplicateNonce` → Alice's valid transaction is **rejected**. [8](#0-7) 

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts invalid transactions and rejects valid transactions before sequencing.**

- An attacker can inject an Invoke with an arbitrary/invalid signature into the mempool for any account that has a pending `deploy_account`, bypassing the `__validate__` entry-point entirely.
- The legitimate user's first post-deployment Invoke (nonce=1) is blocked by the duplicate-nonce guard.
- The attacker's transaction will revert during execution (the blockifier always runs `__validate__` at execution time), but the damage — blocking the victim's transaction — is already done.
- The attack is cheap: it requires only observing the mempool and submitting one transaction per victim account.

---

### Likelihood Explanation

The mempool is observable (P2P propagation, RPC). Any `deploy_account` transaction is visible before it is included in a block. The attacker needs no privileged access, no special funds (beyond gas for the Invoke), and no knowledge of the victim's private key. The race window is the entire time the `deploy_account` sits in the mempool before being sequenced.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is pending for the address. The mempool should expose a method such as `has_pending_deploy_account(address)` that inspects the transaction type, not just the address presence. Alternatively, the gateway can inspect the transaction type of the pending transaction before deciding to skip validation.

---

### Proof of Concept

```
1. Alice: submit RpcDeployAccountTransaction for address A (valid sig, class_hash=C)
   → Gateway accepts, mempool now has deploy_account for A
   → tx_pool.contains_account(A) == true

2. Attacker: submit RpcInvokeTransactionV3 {
       sender_address: A,
       nonce: 1,
       signature: [0xDEAD, 0xBEEF],   // invalid
       calldata: [...],
       resource_bounds: <valid>,
   }
   → StatelessTransactionValidator: passes (signature length within limit)
   → StatefulTransactionValidator:
       account_nonce = get_nonce_from_state(A) = 0
       validate_nonce: 0 <= 1 <= max_gap  ✓
       validate_by_mempool: no dup hash, nonce not too old  ✓
       skip_stateful_validations:
           nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
           → returns true (SKIP __validate__)
       run_validate_entry_point: execution_flags.validate=false → skipped
   → Attacker's invalid-sig invoke ADMITTED to mempool

3. Alice: submit RpcInvokeTransactionV3 {
       sender_address: A,
       nonce: 1,
       signature: <valid ECDSA sig>,
       ...
   }
   → validate_by_mempool → validate_fee_escalation:
       tx_pool.get_by_address_and_nonce(A, 1) is_some() == true
       → MempoolError::DuplicateNonce
   → Alice's VALID invoke REJECTED
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L768-773)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
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
