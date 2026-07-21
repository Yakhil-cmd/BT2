### Title
Unauthenticated Nonce-1 Invoke Bypasses `__validate__` Signature Check at Gateway via `skip_stateful_validations` — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (signature verification) for any invoke transaction with nonce=1 when the on-chain account nonce is 0, provided `account_tx_in_pool_or_recent_block` returns `true` for the sender. An attacker who observes a legitimate `deploy_account` transaction in the mempool can immediately submit a nonce=1 invoke from the same address with a fabricated signature, bypassing the gateway's only signature-level guard and injecting an invalid transaction into the mempool.

---

### Finding Description

`skip_stateful_validations` is the UX feature that allows a user to broadcast `deploy_account` + `invoke(nonce=1)` simultaneously without waiting for the deploy to be mined. Its guard is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...;
}
``` [1](#0-0) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
// crates/apollo_mempool/src/mempool.rs  line 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

It returns `true` if **any** transaction from the address is in the pool — not specifically a `deploy_account`. When a legitimate user's `deploy_account` for address X is in the pool, this check returns `true` for X.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 310-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside `blockifier::StatefulValidator::perform_validations`, the `__validate__` call is gated on this flag:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs  lines 79-81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [4](#0-3) 

The transaction is therefore admitted to the mempool without any signature verification.

The upstream checks that run **before** `skip_stateful_validations` do not catch this:

- **Stateless validator** checks signature *length* (≤ 4000 felts), not validity. [5](#0-4) 
- **`validate_by_mempool`** / `validate_incoming_tx` checks only for duplicate tx-hash and `tx_nonce >= account_nonce`. [6](#0-5) 
- **`validate_nonce`** in the gateway accepts nonce=1 when account_nonce=0 (within the 200-gap window). [7](#0-6) 

---

### Impact Explanation

**Broken invariant:** The gateway must only admit transactions whose `__validate__` entry point would pass. A nonce=1 invoke with a fabricated signature violates this invariant and is admitted.

**Concrete effects:**

1. The attacker occupies the nonce=1 slot for the victim's address in the mempool.
2. The victim's legitimate nonce=1 invoke must either wait for the attacker's transaction to be rejected during block execution (delaying the victim by ≥1 block) or pay a higher fee to replace it via fee escalation.
3. During block execution the batcher calls `__validate__` with `validate=true` (the default), so the attacker's transaction is rejected there — no funds are stolen. However, the gateway admission invariant is broken.

This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The attack requires only:
1. Monitoring the public mempool for a `deploy_account` transaction (trivially observable).
2. Submitting a nonce=1 invoke from the same sender address with any non-empty fake signature (no private key needed).

No privileged access, no special network position, and no race condition beyond normal mempool observation is required.

---

### Recommendation

Replace the generic `account_tx_in_pool_or_recent_block` check with a type-specific check that verifies a **`deploy_account`** transaction (not just any transaction) is present in the pool for the sender address. For example, expose a `deploy_account_in_pool(address)` query from the mempool and use it in `skip_stateful_validations`. This preserves the UX feature while closing the bypass.

---

### Proof of Concept

```
1. Alice submits deploy_account for address X (nonce=0, valid signature).
   → Mempool admits it (full __validate_deploy__ executed).

2. Bob observes Alice's deploy_account in the mempool.

3. Bob submits invoke(sender=X, nonce=1, signature=[0xdeadbeef, ...], calldata=[...]).

4. Gateway stateless check: signature length 2 ≤ 4000 → PASS.

5. Gateway validate_nonce: 0 ≤ 1 ≤ 200 → PASS.

6. Gateway validate_by_mempool: no duplicate hash, nonce not too old → PASS.

7. skip_stateful_validations:
     tx.nonce() == 1  ✓
     account_nonce == 0  ✓
     account_tx_in_pool_or_recent_block(X) == true  ✓  (Alice's deploy_account is in pool)
   → returns true (skip validation).

8. run_validate_entry_point sets execution_flags.validate = false.
   perform_validations returns Ok(()) without calling __validate__.

9. Bob's transaction is admitted to the mempool with a fake signature.

10. Block building:
    - Alice's deploy_account executes → X deployed, nonce → 1.
    - Bob's nonce=1 invoke is attempted → __validate__ called → FAILS (invalid signature)
      → transaction rejected, nonce NOT incremented.
    - Alice's nonce=1 invoke is NOT executed this block (delayed to next block,
      or must pay higher fee to displace Bob's transaction via fee escalation).
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L310-312)
```rust
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-456)
```rust
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
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L702-711)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-53)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
```
