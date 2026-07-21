### Title
Gateway Admits Invoke Transactions with Unverified Signatures via `skip_stateful_validations`, Enabling Nonce-Slot Griefing — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the Apollo gateway's stateful transaction validator intentionally bypasses the `__validate__` entry-point (account signature verification) for invoke transactions with `nonce == 1` from accounts whose `deploy_account` is pending in the mempool. Because the mempool itself never verifies signatures, an unprivileged attacker can submit an invoke transaction with an **arbitrary (wrong) signature** for any account that has a `deploy_account` in the mempool, have it admitted without any signature check, and thereby occupy the nonce-1 slot — blocking the legitimate user's invoke from being admitted until the attacker's invalid transaction is rejected by the batcher.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:
1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

This means `StatefulValidator::perform_validations` exits early without calling `__validate__`: [3](#0-2) 

**The mempool's `validate_tx` does not check signatures either:** [4](#0-3) 

It only checks nonce range and fee escalation — no cryptographic verification.

**`account_tx_in_pool_or_recent_block` checks for any transaction from the address, not specifically a `deploy_account`:** [5](#0-4) 

**The gateway's `add_tx_inner` uses the nonce returned by `extract_state_nonce_and_run_validations` (which is the on-chain nonce, not the tx nonce) to build the `AddTransactionArgs` sent to the mempool:** [6](#0-5) 

**Attack path:**

1. Legitimate user submits `deploy_account` for address `A` (class_hash, salt, constructor_calldata known from the mempool). On-chain `account_nonce(A) = 0`.
2. Attacker observes the `deploy_account` in the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker submits `Invoke(sender=A, nonce=1, signature=GARBAGE)`.
4. Gateway `validate_nonce`: nonce=1 ≥ account_nonce=0, within `max_allowed_nonce_gap` → **passes**. [7](#0-6) 

5. Gateway `validate_by_mempool`: nonce=1 is a valid future nonce → **passes**.
6. Gateway `skip_stateful_validations`: nonce=1, account_nonce=0, A in pool → returns `true`.
7. `run_validate_entry_point` skips `__validate__` → **invalid invoke admitted to mempool without signature verification**.
8. Legitimate user's `Invoke(sender=A, nonce=1, signature=CORRECT)` is rejected by the mempool as `DuplicateNonce` (same `(address, nonce)` already present).

**What happens next:**

- The batcher picks up the attacker's invalid invoke. During execution, `perform_pre_validation_stage` runs `handle_nonce` (nonce=1 matches account_nonce=1 after deploy_account executes), then calls `__validate__` with `validate=true` (the batcher's default). `__validate__` fails (wrong signature). The transaction is rejected, state is rolled back, nonce is not permanently incremented. [8](#0-7) 

- The attacker's invalid invoke is removed from the mempool as a rejected transaction.
- The legitimate user can now resubmit their invoke — but they have been delayed by one block.

**The attack is free:** the attacker submits a transaction *from* account `A` (not from their own account). Since `__validate__` fails, no fee is charged from `A`. The attacker pays nothing.

---

### Impact Explanation

This matches **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

The gateway admits an invoke transaction with an arbitrary (wrong) signature — an invalid transaction — because `skip_stateful_validations` bypasses the only signature-verification step (`__validate__`). The mempool then rejects the legitimate user's valid invoke as a `DuplicateNonce`, preventing it from being sequenced in the current block. The attacker can repeat this for every new `deploy_account` they observe in the mempool, at zero cost.

---

### Likelihood Explanation

- **Unprivileged trigger**: Any external observer can submit a transaction to the gateway.
- **Observable precondition**: `deploy_account` transactions are visible in the public mempool.
- **No funds required**: The attacker does not need to control or fund any account.
- **Timing window**: The attack window is the period between the `deploy_account` entering the mempool and it being included in a block (typically seconds to minutes).

Likelihood is **Medium**: the attack requires observing a specific mempool event and acting within a timing window, but is otherwise trivially executable.

---

### Recommendation

1. **Verify the mempool entry is specifically a `deploy_account`**: Instead of checking `account_tx_in_pool_or_recent_block` (which returns `true` for any transaction type), query the mempool for a `deploy_account` transaction specifically from the same sender address.

2. **Alternatively, require a lightweight signature proof at admission**: Even when skipping the full `__validate__` call, verify a minimal signature (e.g., over the transaction hash) using the expected account class's verification logic, so that only the account owner can submit the paired invoke.

3. **Scope the skip more narrowly**: The current check `tx.nonce() == Nonce(Felt::ONE)` is the only nonce-side guard. Consider also requiring that no other invoke with `nonce=1` from the same address is already in the mempool before granting the skip.

---

### Proof of Concept

```
// Precondition: legitimate user has submitted deploy_account for address A.
// On-chain state: account_nonce(A) = 0.
// Mempool: deploy_account(A) is present.

// Attacker submits (via gateway RPC):
Invoke {
    sender_address: A,          // target account
    nonce: 1,                   // exactly 1
    signature: [0xDEAD, 0xBEEF], // arbitrary garbage
    calldata: [...],
    resource_bounds: { ... valid bounds ... },
}

// Gateway flow:
// 1. validate_nonce: 1 >= 0, within gap → OK
// 2. validate_by_mempool: nonce=1 is future nonce → OK
// 3. skip_stateful_validations:
//      tx.nonce() == 1 ✓
//      account_nonce == 0 ✓
//      account_tx_in_pool_or_recent_block(A) == true ✓  (deploy_account is in pool)
//    → returns true (skip __validate__)
// 4. run_validate_entry_point: execution_flags.validate = false → __validate__ NOT called
// 5. Transaction admitted to mempool.

// Legitimate user now submits:
Invoke {
    sender_address: A,
    nonce: 1,
    signature: [correct_r, correct_s],  // valid signature
    ...
}
// Mempool rejects: DuplicateNonce { address: A, nonce: 1 }
// Legitimate user is blocked for one block.
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-95)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

                Ok(())
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

**File:** crates/apollo_gateway/src/gateway.rs (L263-278)
```rust
        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L478-503)
```rust
    fn handle_nonce(
        state: &mut dyn State,
        tx_info: &TransactionInfo,
        strict: bool,
    ) -> TransactionPreValidationResult<()> {
        if tx_info.is_v0() {
            return Ok(());
        }

        let address = tx_info.sender_address();
        let account_nonce = state.get_nonce_at(address)?;
        let incoming_tx_nonce = tx_info.nonce();
        let valid_nonce = if strict {
            account_nonce == incoming_tx_nonce
        } else {
            account_nonce <= incoming_tx_nonce
        };
        if valid_nonce {
            return Ok(state.increment_nonce(address)?);
        }
        Err(TransactionPreValidationError::InvalidNonce {
            address,
            account_nonce,
            incoming_tx_nonce,
        })
    }
```
