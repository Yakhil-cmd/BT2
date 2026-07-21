### Title
Unsigned Invoke Transaction Admitted to Mempool via Unchecked `skip_stateful_validations` Condition — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry-point call (the account's signature check) for any `Invoke` transaction whose nonce is `1` and whose sender has `account_nonce == 0`, provided `account_tx_in_pool_or_recent_block` returns `true`. The pool check does **not** verify that the existing transaction is specifically a `deploy_account`; it returns `true` for **any** transaction from that address. An unprivileged observer who sees a victim's `deploy_account` in the mempool can race-submit an `Invoke(nonce=1)` with an arbitrary or empty signature for the victim's not-yet-deployed address. The gateway admits it without signature verification, blocking the victim's legitimate invoke and causing the victim's account to be charged fees when the unsigned transaction is executed and reverts.

---

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks`:

```
validate_state_preconditions  →  validate_by_mempool  →  skip_stateful_validations
``` [1](#0-0) 

`skip_stateful_validations` returns `true` (skip the `__validate__` call) when all three conditions hold:

```rust
tx.nonce() == Nonce(Felt::ONE)
    && account_nonce == Nonce(Felt::ZERO)
    && mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address()).await == true
``` [2](#0-1) 

The pool check is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

This returns `true` for **any** transaction type from that address — not exclusively a `deploy_account`. The code comment claims this is safe because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but the `skip_stateful_validations` feature itself is the mechanism that allows a future-nonce invoke to enter the pool for an undeployed account, creating a circular dependency.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is entirely bypassed:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [5](#0-4) 

The mempool's own `validate_tx` only checks nonce ordering and fee escalation — it performs no signature verification:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [6](#0-5) 

Therefore, if `skip_validate` is `true`, the transaction's signature is **never verified** anywhere in the gateway-to-mempool admission path.

---

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the public mempool can:

1. Submit `Invoke(sender=victim_address, nonce=1, signature=<garbage>)`.
2. The gateway evaluates: `account_nonce=0`, `tx_nonce=1`, `account_tx_in_pool_or_recent_block=true` → `skip_validate=true`.
3. The unsigned invoke passes all gateway checks and is admitted to the mempool.
4. The victim's legitimate `Invoke(nonce=1)` arrives and is rejected with `DuplicateNonce` (or must pay a higher fee to escalate).
5. The attacker's unsigned invoke is eventually executed by the batcher; `__validate__` fails, the transaction reverts, and the fee is charged from the victim's account balance.

This matches **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

- The mempool is public; any observer can detect a pending `deploy_account` transaction.
- The attacker needs only to submit a single well-formed (but unsigned) invoke before the victim's invoke arrives — a straightforward race condition.
- No privileged access, special keys, or on-chain state is required.
- The attack is repeatable for every new account deployment observed in the mempool.

---

### Recommendation

Replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** is present in the pool for the sender address. Expose a dedicated mempool query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, and use that in `skip_stateful_validations` instead of the current type-agnostic pool membership check.

Alternatively, add a transaction-type filter inside `account_tx_in_pool_or_recent_block` or inside `skip_stateful_validations` itself:

```rust
// Pseudocode fix
return mempool_client
    .deploy_account_tx_in_pool(tx.sender_address())
    .await
    ...
```

This closes the race window where an attacker can exploit the UX skip to inject an unsigned invoke for a victim's undeployed account.

---

### Proof of Concept

**Setup**: Alice is about to deploy a new account at address `A`.

1. Alice broadcasts `deploy_account(class_hash=C, salt=S, nonce=0, sig=valid)` → it enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.

2. Bob (attacker) observes Alice's `deploy_account` in the mempool and immediately submits:
   ```
   Invoke(sender=A, nonce=1, calldata=[drain_funds_selector, ...], signature=[0x0])
   ```

3. Gateway stateless check passes (valid format, resource bounds, etc.). [7](#0-6) 

4. `extract_state_nonce_and_run_validations` fetches `account_nonce = 0`. [8](#0-7) 

5. `validate_nonce` passes: `0 ≤ 1 ≤ 0 + max_allowed_nonce_gap`. [9](#0-8) 

6. `skip_stateful_validations` returns `true` (deploy_account is in pool). [10](#0-9) 

7. `run_validate_entry_point` is called with `skip_validate=true` → `execution_flags.validate=false` → `__validate__` is **never called**. Bob's unsigned invoke is admitted to the mempool. [11](#0-10) 

8. Alice's legitimate `Invoke(nonce=1)` arrives. The mempool already holds Bob's invoke at `(A, nonce=1)` → Alice's invoke is rejected with `DuplicateNonce` (or requires fee escalation to displace Bob's). [12](#0-11) 

9. The batcher executes Alice's `deploy_account` (account deployed), then Bob's `Invoke(nonce=1)`. `__validate__` is called on the now-deployed account, fails (invalid signature), transaction reverts, and the fee is charged from Alice's account balance.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L306-312)
```rust
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
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
    }
```
