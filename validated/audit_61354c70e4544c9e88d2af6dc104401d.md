### Title
`skip_stateful_validations` Admits Unsigned Invoke Transactions for Undeployed Accounts, Enabling Nonce-1 Slot Squatting — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` UX feature bypasses the blockifier's `__validate__` entry point (account signature verification) for invoke transactions with nonce=1 submitted against an undeployed account that has a pending `deploy_account` transaction in the mempool. Because the mempool's `validate_tx` path does not inspect the signature either, an attacker who observes a `deploy_account` transaction in the mempool can submit an invoke transaction with an **invalid or absent signature** from the same address and have it admitted. The mempool enforces one transaction per `(address, nonce)` slot; the attacker's invalid transaction occupies the nonce=1 slot, causing the legitimate owner's valid invoke transaction to be rejected with `DuplicateNonce`. The attacker can also use fee escalation to displace the legitimate transaction even if it was admitted first.

---

### Finding Description

**Normal gateway stateful path** for an invoke transaction:

1. `extract_state_nonce_and_run_validations` fetches `account_nonce` from state.
2. `run_pre_validation_checks` → `validate_state_preconditions` (resource bounds + nonce range) + `validate_by_mempool` (nonce/hash/fee-escalation checks, **no signature**) + `skip_stateful_validations`.
3. `run_validate_entry_point(skip_validate=false)` → `blockifier_validator.validate(account_tx)` → `perform_validations` → `perform_pre_validation_stage` (nonce increment, fee bounds, balance) → **`__validate__` entry point** (account signature verification) → `PostValidationReport::verify`.

**Skip path** triggered by `skip_stateful_validations`: [1](#0-0) 

When the conditions below are all true, `skip_stateful_validations` returns `true`:

- Transaction is `ExecutableTransaction::Invoke`
- `tx.nonce() == Nonce(Felt::ONE)`
- `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
- `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true` [2](#0-1) 

`run_validate_entry_point` then sets `execution_flags.validate = false`: [3](#0-2) 

Inside `perform_validations`, `perform_pre_validation_stage` still runs (nonce, fee bounds, balance), but the function returns **before** calling `__validate__`: [4](#0-3) 

The `__validate__` call — the only place the account contract's signature verification runs at gateway admission time — is therefore completely skipped. [5](#0-4) 

**The mempool's `validate_tx` does not check signatures either.** `ValidationArgs` carries only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price`: [6](#0-5) 

The mempool's `validate_tx` calls `validate_incoming_tx` (duplicate hash / nonce-too-old) and `validate_fee_escalation` (fee replacement rules): [7](#0-6) 

Neither check inspects the transaction signature. An attacker's invoke transaction with an arbitrary or empty signature therefore passes all gateway and mempool admission checks.

**Nonce-slot squatting via fee escalation:** The mempool enforces one transaction per `(address, nonce)` pair and allows a higher-fee transaction to replace an existing one. An attacker can:

1. Submit an invalid-signature invoke tx with nonce=1 from the victim's address **before** the victim does → victim's subsequent submission is rejected with `DuplicateNonce`.
2. Or, if the victim submitted first, submit with a higher fee → fee escalation replaces the victim's valid tx with the attacker's invalid one. [8](#0-7) 

At execution time, the attacker's transaction reaches `__validate__` on the now-deployed account, fails signature verification, and is rejected with no state change and no fee charged. The victim's nonce=1 slot has been consumed by a rejected transaction; the victim must resubmit.

---

### Impact Explanation

This is a **High** impact finding matching: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

An attacker can reliably prevent any account that uses the deploy-account + invoke UX flow from having its first post-deployment invoke transaction sequenced in the intended block. The attacker pays nothing (the invalid tx is rejected at execution with no fee charged), while the victim's transaction is evicted from the mempool and must be resubmitted after the deploy_account transaction has already been executed.

---

### Likelihood Explanation

- The mempool is public; any observer can detect a pending `deploy_account` transaction.
- The attack requires only submitting a single invoke transaction with nonce=1 from the victim's address — no knowledge of the victim's private key is needed.
- The attacker can repeat the attack indefinitely at zero cost (no fee is ever charged for the rejected transaction).
- The only constraint is that the victim's account must have enough pre-funded balance to pass `verify_can_pay_committed_bounds` at gateway admission time, which is a prerequisite for the legitimate UX flow anyway.

---

### Recommendation

Add a signature-presence or signature-format check in the skip path. The simplest fix is to add the same `intendedRecipient`-style guard that the external report recommends: verify in `_executeProposal` / here in `run_validate_entry_point` that the transaction's signature field is non-empty and structurally valid before admitting it under `skip_validate=true`. A stronger fix is to defer the skip decision until after a lightweight ECDSA format check, or to require the transaction hash to be signed by the expected deployer address (derivable from the pending `deploy_account` transaction already in the mempool).

---

### Proof of Concept

```
1. Alice broadcasts deploy_account tx for address X (valid signature, nonce=0).
   → Mempool admits it; account_tx_in_pool_or_recent_block(X) now returns true.

2. Attacker submits invoke tx: sender=X, nonce=1, calldata=arbitrary, signature=[].

3. Gateway stateful path:
   a. get_nonce_from_state(X) → 0  (account not deployed)
   b. validate_state_preconditions: nonce 1 >= 0 ✓, resource bounds ✓
   c. validate_by_mempool: no duplicate hash, nonce in range ✓  (no sig check)
   d. skip_stateful_validations: Invoke ✓, nonce==1 ✓, account_nonce==0 ✓,
      account_tx_in_pool_or_recent_block(X)==true ✓  → returns true
   e. run_validate_entry_point(skip_validate=true):
      execution_flags.validate = false
      perform_pre_validation_stage passes (balance pre-funded)
      __validate__ is NOT called  ← missing check
   → Attacker's tx admitted to mempool, occupies (X, nonce=1) slot.

4. Alice submits her legitimate invoke tx: sender=X, nonce=1, valid signature.
   → Mempool rejects: DuplicateNonce { address: X, nonce: 1 }

5. Batcher executes Alice's deploy_account tx (nonce=0 → 1).
   Batcher executes attacker's invoke tx (nonce=1):
     __validate__ runs on deployed account → fails (invalid signature)
     tx rejected, nonce unchanged, no fee charged.

6. Alice's legitimate invoke tx is gone from the mempool; she must resubmit.
``` [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-458)
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

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-69)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}

impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
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

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L246-268)
```rust
#[track_caller]
fn validate_and_add_txs_and_verify_no_replacement(
    mut mempool: Mempool,
    existing_tx: InternalRpcTransaction,
    invalid_replacement_inputs: impl IntoIterator<Item = AddTransactionArgs>,
    in_priority_queue: bool,
    in_pending_queue: bool,
) {
    for input in invalid_replacement_inputs {
        let expected_error = MempoolError::DuplicateNonce {
            address: input.tx.contract_address(),
            nonce: input.tx.nonce(),
        };

        // This does not change the test flow, but only checks that Mempool::validate_tx performs as
        // expected.
        validate_tx_expect_error(
            &mut mempool,
            &ValidationArgs::from(&input),
            expected_error.clone(),
        );

        add_tx_expect_error(&mut mempool, &input, expected_error);
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```
