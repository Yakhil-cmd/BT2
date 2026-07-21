### Title
Invoke transactions with invalid signatures admitted to mempool via unchecked `skip_stateful_validations` path — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` bypasses the `__validate__` entry point (the account's cryptographic signature check) for any invoke transaction with nonce=1 targeting an undeployed account, whenever `account_tx_in_pool_or_recent_block` returns true. Because that check is satisfied by the victim's own pending deploy_account transaction, any third party can inject an invoke with an arbitrary/invalid signature for the victim's address and have it admitted to the mempool without signature verification.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when all four conditions hold: [1](#0-0) 

```
1. tx is ExecutableTransaction::Invoke
2. tx.nonce() == Nonce(Felt::ONE)
3. account_nonce == Nonce(Felt::ZERO)   (account not yet deployed)
4. account_tx_in_pool_or_recent_block(sender_address) == true
```

Condition 4 is implemented as: [2](#0-1) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

This returns `true` if **any** transaction from that address is in the pool — not specifically a deploy_account. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." The second branch of that reasoning is circular for an undeployed account (nonce=0 in state), and the first branch is exploitable: the victim's own deploy_account, which is publicly visible in the mempool, satisfies the check.

When `skip_validate=true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

and `StatefulValidator::perform_validations` returns `Ok(())` immediately without calling `__validate__`: [4](#0-3) 

The mempool's `validate_tx` (called before `skip_stateful_validations`) only checks nonce ordering and fee escalation — it never verifies the cryptographic signature: [5](#0-4) 

**Attack steps:**

1. Victim submits a `deploy_account` for address A. It enters the mempool pool, so `tx_pool.contains_account(A)` becomes `true`.
2. Attacker submits an `Invoke` for address A with `nonce=1` and a completely invalid signature (e.g., `[0x0, 0x0]`).
3. Gateway stateful path: `account_nonce=0`, `tx.nonce()=1`, `account_tx_in_pool_or_recent_block(A)=true` → `skip_validate=true`.
4. `run_validate_entry_point` is called with `validate=false`; `__validate__` is never executed.
5. The attacker's transaction passes `validate_by_mempool` (nonce ordering is fine, no duplicate nonce yet) and is added to the mempool. [6](#0-5) 

---

### Impact Explanation

The attacker's invalid invoke is now in the mempool alongside the victim's deploy_account. When the batcher sequences the block:

- deploy_account (nonce 0) executes → account deployed, nonce becomes 1.
- Attacker's invoke (nonce 1) executes → `__validate__` runs → fails (invalid signature) → nonce incremented to 2, fee charged from account balance.
- Victim's legitimate invoke (nonce 1) is now rejected with `InvalidNonce` (account nonce is 2).

If fee escalation is enabled (`enable_fee_escalation=true`), the attacker can additionally **replace** the victim's already-queued legitimate invoke by paying a marginally higher tip, permanently displacing it: [7](#0-6) 

The broken invariant: every invoke transaction admitted to the mempool must have its signature verified by the account's `__validate__` entry point before admission. This invariant is unconditionally violated for any invoke with nonce=1 targeting an account whose deploy_account is pending.

---

### Likelihood Explanation

- The attacker requires no privileged access and no knowledge of the victim's private key.
- Pending deploy_account transactions are publicly observable in the mempool.
- The attack requires submitting a single malformed invoke transaction — trivially automatable.
- Any account in the "deploy_account pending" state is permanently vulnerable until the deploy_account is committed.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a specific `deploy_account_tx_in_pool(address) -> bool` query that returns `true` only when a deploy_account transaction for that exact address is currently pending in the mempool. This preserves the intended UX (deploy + invoke in one shot) while closing the authorization gap.

```rust
// Proposed replacement for the condition in skip_stateful_validations:
return mempool_client
    .deploy_account_tx_in_pool(tx.sender_address())   // new, specific API
    .await
    ...
```

---

### Proof of Concept

```
// Precondition: victim's deploy_account for address A is in the mempool.
// account_tx_in_pool_or_recent_block(A) == true.

// Attacker submits:
RpcInvokeTransactionV3 {
    sender_address: A,          // victim's undeployed address
    nonce: 1,
    signature: [Felt::ZERO],    // invalid — not checked
    resource_bounds: <valid>,
    calldata: <arbitrary>,
    ...
}

// Gateway path:
//   validate_nonce: 0 <= 1 <= max_allowed_nonce_gap  → OK
//   validate_by_mempool: nonce ordering OK, no duplicate  → OK
//   skip_stateful_validations: nonce==1, account_nonce==0,
//       account_tx_in_pool_or_recent_block(A)==true  → returns true
//   run_validate_entry_point: validate=false  → __validate__ NOT called
//   Transaction admitted to mempool.

// Batcher execution:
//   deploy_account(nonce=0) → OK, account deployed
//   attacker invoke(nonce=1) → __validate__ fails (bad sig), nonce→2, fee charged
//   victim invoke(nonce=1)  → InvalidNonce (account nonce is now 2)
```

The root cause is at: [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-458)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L768-792)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```
