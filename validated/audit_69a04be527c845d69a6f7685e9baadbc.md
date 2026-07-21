### Title
Signature Bypass via `skip_stateful_validations` Allows Unsigned Invoke Transactions to Enter Mempool — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function skips the `__validate__` entry point (which performs signature verification) for any invoke transaction with nonce=1 when the target account has *any* transaction in the mempool and its on-chain nonce is zero. Because the check does not verify that the caller is the legitimate account owner, an attacker can submit an invoke transaction with an arbitrary/invalid signature for a victim's address, bypassing signature verification and occupying the victim's nonce=1 slot in the mempool with an invalid transaction.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when all of the following hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true`. [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`, so `StatefulValidator::perform_validations` returns `Ok(())` without ever calling `__validate__`: [2](#0-1) [3](#0-2) 

The mempool-side check `account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool or was seen in a recent block — it does not verify that the transaction is specifically a `deploy_account`, nor that the current invoke's sender is the same party who submitted that earlier transaction: [4](#0-3) 

**Attack path:**

1. Victim submits a `deploy_account` for address `A` (nonce=0). It enters the mempool.
2. Attacker submits an `RpcInvokeTransaction` with `sender_address = A`, `nonce = 1`, and an invalid/arbitrary signature.
3. Gateway stateless validation passes (no signature content check, only length).
4. `skip_stateful_validations` fires: `tx.nonce()==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
5. `run_validate_entry_point` is called with `skip_validate=true` → `execution_flags.validate=false` → `__validate__` is never called.
6. The attacker's unsigned invoke is forwarded to the mempool via `mempool_client.add_tx`. [5](#0-4) 

The attacker's transaction now occupies the victim's nonce=1 slot. When the victim subsequently submits their legitimate nonce=1 invoke, the mempool rejects it as a duplicate nonce. The batcher will eventually reject the attacker's transaction (since `new_for_sequencing` sets `validate: true`), but by then the victim's legitimate transaction has been displaced. [6](#0-5) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid (unsigned) transactions before sequencing.**

An attacker can inject an unsigned invoke transaction for any victim account that has a pending `deploy_account` in the mempool. This:

- Bypasses the `__validate__` signature check at the gateway level.
- Occupies the victim's nonce=1 slot in the mempool, blocking the victim's legitimate first post-deployment transaction.
- Forces the victim to wait for the batcher to reject the attacker's transaction before their own transaction can be re-submitted.

The batcher does re-run `__validate__` (via `new_for_sequencing` with `validate: true`), so funds cannot be directly stolen. However, the admission invariant — *every transaction in the mempool has passed signature verification* — is broken, and the attack can be used for targeted denial-of-service against new account deployments.

---

### Likelihood Explanation

**Medium.** The attack window is the period between a victim's `deploy_account` entering the mempool and being included in a block. This is a common, observable event (mempool is public). The attacker only needs to submit a single transaction with the victim's address and nonce=1; no privileged access is required.

---

### Recommendation

1. **Verify the transaction type in the mempool before skipping validation.** The `account_tx_in_pool_or_recent_block` check should be replaced with a check that specifically confirms a `deploy_account` transaction for the same address is pending — not just any transaction.

2. **Alternatively, restrict the skip to the same sender.** The skip should only apply when the gateway can confirm the pending transaction in the mempool is a `deploy_account` for the exact `sender_address` of the incoming invoke.

3. **Apply the `max_nonce_for_validation_skip` config.** The `StatefulTransactionValidatorConfig` already defines `max_nonce_for_validation_skip` but `skip_stateful_validations` does not use it. The function hardcodes `tx.nonce() == Nonce(Felt::ONE)` instead of checking against the config value. [7](#0-6) 

---

### Proof of Concept

```
1. Victim submits:
   RpcDeployAccountTransaction { sender_address: A, nonce: 0, ... valid_signature }
   → Enters mempool. account_tx_in_pool_or_recent_block(A) == true.

2. Attacker submits:
   RpcInvokeTransaction {
       sender_address: A,   // victim's address
       nonce: 1,
       calldata: [/* arbitrary */],
       signature: [0x1337], // invalid/arbitrary
       resource_bounds: { l2_gas: { max_amount: X, max_price_per_unit: Y } },
       ...
   }

3. Gateway stateless validation:
   - validate_contract_address(A) → Ok (valid address format)
   - validate_resource_bounds → Ok (non-zero bounds)
   - validate_tx_signature_size → Ok (length ≤ max)
   → Passes.

4. convert_rpc_tx_to_internal: computes tx_hash over (A, nonce=1, calldata, chain_id, ...).

5. extract_state_nonce_and_run_validations:
   - get_nonce_from_state(A) → Nonce(0)   [account not deployed yet]
   - validate_nonce: account_nonce(0) ≤ tx_nonce(1) ≤ max_allowed → Ok
   - skip_stateful_validations:
       tx is Invoke ✓, tx.nonce()==1 ✓, account_nonce==0 ✓
       account_tx_in_pool_or_recent_block(A) == true ✓
       → returns true (skip)
   - run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator::perform_validations → returns Ok() without __validate__
   → Passes without signature check.

6. mempool_client.add_tx(attacker's invoke) → admitted to mempool.

7. Victim submits legitimate invoke { sender_address: A, nonce: 1, valid_signature }
   → Mempool rejects: DuplicateNonce { address: A, nonce: 1 }.

8. Batcher eventually executes attacker's invoke:
   new_for_sequencing sets validate=true → __validate__ fails → tx rejected.
   But victim's nonce=1 slot was blocked during this window.
``` [8](#0-7) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-312)
```rust
    ) -> StatefulTransactionValidatorResult<()> {
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_gateway/src/gateway.rs (L253-286)
```rust
        let (internal_tx, executable_tx, proof_data) =
            self.convert_rpc_tx_to_internal_and_executable_txs(tx, &tx_signature).await?;
        drop(compilation_permit);

        let mut stateful_transaction_validator = self
            .stateful_tx_validator_factory
            .instantiate_validator(self.config.dynamic_config.native_classes_whitelist.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

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

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L147-155)
```rust
    pub fn new_for_sequencing(tx: Transaction) -> Self {
        let execution_flags = ExecutionFlags {
            only_query: false,
            charge_fee: enforce_fee(&tx, false),
            validate: true,
            strict_nonce_check: true,
        };
        AccountTransaction { tx, execution_flags }
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-283)
```rust
    pub max_nonce_for_validation_skip: Nonce,
```
