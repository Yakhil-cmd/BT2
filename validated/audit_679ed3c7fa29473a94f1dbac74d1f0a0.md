### Title
Unverified `sender_address` in `skip_stateful_validations` Allows Signature-Less Invoke Transactions to Enter the Mempool — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function grants a privileged bypass of the `__validate__` entry point (signature verification) to any invoke transaction whose `sender_address` has a pending deploy-account in the mempool. Because the check is purely address-based and never verifies that the submitter actually controls that address, an attacker who observes a victim's pending deploy-account can submit an invoke transaction from the victim's address with a completely invalid signature, and the gateway will admit it to the mempool without any cryptographic check.

---

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` and returns `true` (skip) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (nonce = 1).
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed).
4. `mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `skip_validate = true`, which sets `execution_flags.validate = false` on the `AccountTransaction` passed to the blockifier validator: [2](#0-1) 

With `validate = false`, `perform_pre_validation_stage` never calls the account's `__validate__` entry point, so the transaction's signature is never verified at the gateway level: [3](#0-2) 

The balance check (`verify_can_pay_committed_bounds`) is still executed because `charge_fee` is independent of `validate`. For the deploy-account + invoke UX case the account is pre-funded before deployment, so the balance check passes. The transaction is then forwarded to the mempool with no signature verification having occurred. [4](#0-3) 

The check that grants the bypass is purely address-based:

```
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())
```

`sender_address` is an attacker-controlled field in the RPC transaction. There is no proof that the submitter controls the private key for that address. This is the direct analog of the external report's `actualUser` parameter: a caller-supplied identity used to unlock a privileged path without verifying the caller actually is that identity. [5](#0-4) 

When the transaction is later executed by the batcher, `new_for_sequencing` sets `validate: true`, so `__validate__` is called and the transaction reverts. However, the transaction has already been admitted to the mempool and occupies the victim's nonce-1 slot. [6](#0-5) 

---

### Impact Explanation

**Mempool/gateway admission accepts invalid transactions (High).**

1. **Nonce-slot squatting**: The attacker submits an invalid invoke with nonce = 1 and a fee higher than the victim's legitimate invoke. The mempool's fee-escalation logic will reject the victim's valid transaction unless the victim pays an even higher fee, forcing economic harm.
2. **Mempool spam**: An attacker can flood the mempool with invalid transactions for every address that has a pending deploy-account, degrading mempool quality and sequencer throughput.
3. **Fee drain on revert**: When the invalid transaction is executed, `__validate__` fails and the transaction reverts. The fee for the failed validation is charged to the victim's pre-funded address, not the attacker's.

---

### Likelihood Explanation

- Pending deploy-account transactions are publicly visible in the mempool.
- Submitting an invoke with an arbitrary (invalid) signature requires no special privilege.
- The window of vulnerability is the time between the victim's deploy-account entering the mempool and being included in a block — typically several seconds to minutes.

---

### Recommendation

Before granting the `skip_validate` bypass, verify that the transaction's signature is structurally consistent with the account class being deployed (e.g., check the signature against the public key embedded in the deploy-account's constructor calldata). Alternatively, restrict the bypass to transactions that arrive in the same RPC call batch as the deploy-account, or require the invoke to carry a proof-of-knowledge of the deployer's key.

At minimum, add a guard analogous to the external report's whitelist pattern: only skip `__validate__` if the invoke transaction was submitted by the same origin as the deploy-account, or if the signature passes a lightweight pre-check.

---

### Proof of Concept

```
1. Alice pre-funds address X with STRK.
2. Alice submits RpcTransaction::DeployAccount for address X (nonce = 0).
   → Mempool now contains a deploy-account for address X.

3. Attacker observes the mempool and crafts:
     RpcInvokeTransactionV3 {
         sender_address: X,
         nonce: 1,
         signature: [0x0, 0x0],   // completely invalid
         resource_bounds: <non-zero, passes stateless check>,
         calldata: <arbitrary>,
         ...
     }

4. Gateway stateless validator: passes (signature size is valid, resource bounds non-zero).
   crates/apollo_gateway/src/stateless_transaction_validator.rs

5. Gateway stateful validator:
   - account_nonce = 0  (X not yet deployed)
   - tx_nonce = 1
   - account_tx_in_pool_or_recent_block(X) = true  (deploy-account is in pool)
   → skip_stateful_validations returns true
   → run_validate_entry_point called with skip_validate = true
   → __validate__ is NOT called; signature is never checked
   - verify_can_pay_committed_bounds: passes (X is pre-funded)
   → Transaction admitted to mempool.

6. Attacker's invalid invoke now occupies nonce-1 slot for address X.
   Alice's valid invoke with nonce = 1 is rejected (DuplicateNonce) or
   requires fee escalation to displace the attacker's transaction.

7. When the batcher executes the attacker's invoke:
   - new_for_sequencing sets validate = true
   - __validate__ is called, fails (invalid signature)
   - Transaction reverts; small fee charged to Alice's address X.
``` [7](#0-6) [2](#0-1)

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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
