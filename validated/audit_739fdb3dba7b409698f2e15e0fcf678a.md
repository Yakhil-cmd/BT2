### Title
Unauthenticated Invoke Transaction Admitted to Mempool via `skip_stateful_validations` Signature Bypass — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's UX shortcut for the deploy-account + invoke flow unconditionally skips the `__validate__` entry-point call for any invoke transaction whose nonce is `1` and whose sender address already appears in the mempool. Because no other path in the gateway verifies the transaction signature, an attacker can inject an invoke transaction carrying an arbitrary (invalid) signature for any victim account that has a pending `deploy_account` transaction, and the gateway will admit it to the mempool without ever calling `__validate__`.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip validation) when three conditions hold simultaneously:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When this function returns `true`, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `!tx.execution_flags.validate`, the function returns `Ok(())` immediately without calling `__validate__`: [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check is satisfied by any account that has **any** transaction in the pool or has appeared in a committed block — it does not verify that the account specifically has a `deploy_account` pending: [4](#0-3) 

The mempool's `validate_tx` (called via `validate_by_mempool` before `skip_stateful_validations`) checks only nonce validity and fee escalation — it never inspects the signature: [5](#0-4) 

The stateless validator also performs no signature check: [6](#0-5) 

The result is that the entire gateway pipeline — stateless validator → transaction converter → mempool `validate_tx` → `skip_stateful_validations` → `run_validate_entry_point` — admits the transaction to the mempool without ever verifying the signature.

### Impact Explanation

An attacker who observes that victim account `V` has a `deploy_account` transaction in the mempool (on-chain nonce = 0) can:

1. Craft an invoke transaction with `sender_address = V`, `nonce = 1`, and an arbitrary (invalid) signature.
2. Submit it to the gateway. All checks pass; `skip_stateful_validations` returns `true`; `__validate__` is never called.
3. The transaction is admitted to the mempool and occupies nonce slot `1` for `V`.
4. When `V` subsequently tries to submit their legitimate invoke with `nonce = 1`, the mempool rejects it with `DuplicateNonce` (or forces fee escalation).
5. The attacker can repeat this continuously, permanently blocking `V`'s first post-deploy invoke until the attacker's transaction is eventually executed and rejected by the batcher.

This matches the **High** impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The attack requires only:
- Observing the public mempool for a `deploy_account` transaction (trivially observable).
- Submitting a single invoke transaction with any signature.

No privileged access, no special resources, and no cryptographic capability are required. The attack is repeatable at negligible cost.

### Recommendation

The `skip_stateful_validations` path should be narrowed so that it only skips `__validate__` when the **specific** pending transaction for the account is a `deploy_account` (not just any transaction). Concretely:

- Replace the `account_tx_in_pool_or_recent_block` check with a stricter query that confirms a `deploy_account` transaction for the exact sender address is present in the mempool at nonce `0`.
- Alternatively, do not skip `__validate__` entirely; instead, run it against a speculative state that includes the not-yet-committed `deploy_account` execution result, so the account contract exists for the purpose of validation.

### Proof of Concept

```
Precondition: victim address V has deploy_account tx (nonce=0) in mempool.
              On-chain nonce for V = 0.

1. Attacker calls gateway add_tx with:
     RpcInvokeTransactionV3 {
         sender_address: V,
         nonce: 1,
         signature: [0xdeadbeef],   // arbitrary invalid signature
         resource_bounds: { l2_gas: { max_amount: X, max_price_per_unit: Y } },
         ...
     }

2. Gateway flow:
   a. stateless_tx_validator.validate() → Ok(())   // no sig check
   b. convert_rpc_tx_to_internal()      → Ok(...)  // no sig check
   c. extract_state_nonce_and_run_validations():
      - get_nonce_from_state(V)         → Nonce(0)
      - run_pre_validation_checks():
          validate_state_preconditions() → Ok(())  // nonce 1 >= 0, within gap
          validate_by_mempool()          → Ok(())  // no sig check
          skip_stateful_validations():
              tx.nonce() == 1 ✓
              account_nonce == 0 ✓
              account_tx_in_pool_or_recent_block(V) → true ✓
              returns true
      - run_validate_entry_point(skip_validate=true):
          execution_flags.validate = false
          StatefulValidator::perform_validations():
              !tx.execution_flags.validate → return Ok(())  // __validate__ SKIPPED
   d. mempool.add_tx() → Ok(())

3. Attacker's invalid-signature invoke is now in the mempool at nonce=1 for V.

4. Victim submits legitimate invoke with nonce=1:
   mempool.validate_tx() → Err(DuplicateNonce { address: V, nonce: 1 })
   → Victim's transaction is rejected.
``` [7](#0-6) [1](#0-0) [8](#0-7) [3](#0-2)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
