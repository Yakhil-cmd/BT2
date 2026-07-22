### Title
Signature Validation Bypass via `skip_stateful_validations` Race on Public `deploy_account` Mempool Visibility - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function bypasses the `__validate__` entry-point (signature check) for any invoke with `nonce=1` whenever `account_tx_in_pool_or_recent_block` returns `true` for the sender address. That check returns `true` if **any** transaction from the address is in the mempool — it does not verify the queued transaction is a `deploy_account`, nor that the incoming invoke belongs to the same signer. An unprivileged attacker who observes a victim's `deploy_account` in the public mempool can submit an unsigned invoke with `nonce=1` from the victim's address, bypass all signature verification at the gateway, and have the invalid transaction admitted to the mempool.

---

### Finding Description

**Root cause — `skip_stateful_validations`** [1](#0-0) 

The function's guard condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await …
}
```

`account_tx_in_pool_or_recent_block` is implemented as: [2](#0-1) 

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It returns `true` for **any** transaction type from that address. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but it does not enforce either condition — it accepts the presence of a `deploy_account` submitted by a **different sender** (the victim) as justification to skip signature validation for the attacker's invoke.

**When `skip_validate = true`, the gateway sets `validate = false`:** [3](#0-2) 

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

The blockifier's `StatefulValidator::perform_validations` then returns early without calling `__validate__`: [4](#0-3) 

```rust
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← exits without __validate__
    }
```

**Why `validate_by_mempool` does not block the attack:** [5](#0-4) 

`validate_tx` calls `validate_incoming_tx` (duplicate-hash / stale-nonce check) and `validate_fee_escalation` (duplicate-nonce check). The victim's `deploy_account` has `nonce=0`; the attacker's invoke has `nonce=1`. There is no duplicate nonce, so both checks pass.

**Full gateway admission path:** [6](#0-5) 

```
validate_state_preconditions   → nonce=1 ∈ [0, max_gap] ✓
validate_by_mempool            → no dup nonce ✓
skip_stateful_validations      → victim's deploy_account in pool → true
run_validate_entry_point       → validate=false → __validate__ skipped ✓
mempool_client.add_tx          → attacker's unsigned invoke admitted
```

---

### Impact Explanation

**Admission impact (High):** An unsigned invoke from an arbitrary sender is accepted by the gateway and placed in the mempool, violating the invariant that every admitted transaction must have passed account-level signature verification.

**Execution impact (Critical-adjacent):** When the batcher later executes the block, the `deploy_account` runs first (nonce 0→1), then the attacker's invoke runs with `nonce=1`. The blockifier now calls `__validate__` on the deployed account; the signature is absent/invalid, so the transaction reverts. However, `enforce_fee` is `true` whenever `resource_bounds > 0`: [7](#0-6) 

A reverted transaction still charges fees from the victim's pre-funded deploy address. The attacker controls the `resource_bounds` field and can set it up to the victim's entire balance, draining it. The victim's legitimate `nonce=1` invoke is simultaneously displaced from the mempool (rejected as duplicate nonce, or replaced via fee escalation).

---

### Likelihood Explanation

- The victim's `deploy_account` is public in the mempool the moment it is submitted.
- The attacker's deploy address is deterministic from the public `class_hash`, `salt`, and `constructor_calldata` fields in the `deploy_account` transaction.
- The attacker only needs to submit the malicious invoke before the victim's invoke arrives (a simple race), or use fee escalation to replace it afterward.
- No privileged access, special keys, or prior on-chain state is required.

---

### Recommendation

1. **Type-check the queued transaction.** In `skip_stateful_validations`, query the mempool for a transaction that is specifically a `deploy_account` at `nonce=0` for the sender address, rather than accepting any transaction type.

2. **Bind the skip to the deploy_account hash.** Pass the expected `deploy_account` transaction hash (as the native-blockifier path already does via `deploy_account_tx_hash`) through the Apollo gateway path and verify it matches what is actually in the mempool before skipping validation. [8](#0-7) 

The `PyValidator::should_run_stateful_validations` in the native-blockifier path already requires the caller to supply a `deploy_account_tx_hash` and checks it is `Some` before skipping — the Apollo gateway path lacks this binding entirely.

---

### Proof of Concept

```
1. Victim generates deploy address A (deterministic from class_hash C, salt S, calldata D).
2. Victim pre-funds address A with 1000 STRK.
3. Victim submits deploy_account(class_hash=C, salt=S, calldata=D, nonce=0).
   → Mempool now contains: {A: deploy_account(nonce=0)}

4. Attacker observes the deploy_account in the public mempool.
5. Attacker submits invoke(sender=A, nonce=1, calldata=[arbitrary],
                           signature=[], resource_bounds={l2_gas: max_amount=1000 STRK}).

   Gateway checks:
   a. validate_nonce: 1 ∈ [0, 0+max_gap]                          → OK
   b. validate_by_mempool: no tx at (A, nonce=1)                   → OK
   c. skip_stateful_validations:
        account_tx_in_pool_or_recent_block(A) == true              → skip=true
   d. run_validate_entry_point(validate=false):
        perform_pre_validation_stage passes (nonce OK, balance OK)
        __validate__ NOT called                                     → OK
   e. mempool.add_tx → attacker's invoke admitted.

6. Victim submits invoke(sender=A, nonce=1, calldata=[legitimate], signature=[valid]).
   → Rejected: DuplicateNonce {address: A, nonce: 1}

7. Batcher builds block:
   - Executes deploy_account(A)  → A deployed, nonce becomes 1.
   - Executes attacker's invoke(nonce=1):
       __validate__ called on A → signature [] is invalid → REVERT.
       Fee charged: up to 1000 STRK drained from A.

Result: victim's legitimate invoke is lost; victim's balance is drained.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/blockifier/src/transaction/objects.rs (L105-113)
```rust
    pub fn enforce_fee(&self) -> bool {
        match self {
            TransactionInfo::Current(context) => {
                // Assumes that the tip is enabled, as it is in the OS.
                context.resource_bounds.max_possible_fee(context.tip) > Fee(0)
            }
            TransactionInfo::Deprecated(context) => context.max_fee != Fee(0),
        }
    }
```

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
