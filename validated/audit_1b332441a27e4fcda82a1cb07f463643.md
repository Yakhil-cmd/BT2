### Title
Signature Validation Skipped for Post-Deploy-Account Invoke Transactions Allows Invalid Transaction Admission - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry point (which performs account signature verification) for any Invoke transaction with `nonce=1` when `account_nonce=0` and any account transaction exists in the mempool for that address. An unprivileged attacker can exploit this to submit an Invoke with an invalid signature for any address that has a pending `deploy_account` transaction, bypassing signature verification at the admission gate. Combined with fee escalation, the attacker can replace a legitimate user's valid invoke with an invalid one, causing the legitimate transaction to be permanently evicted from the mempool.

### Finding Description

`skip_stateful_validations` returns `true` (skip) when all three conditions hold:

```
tx.nonce() == Nonce(Felt::ONE)
&& account_nonce == Nonce(Felt::ZERO)
&& mempool_client.account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate == false`, the function returns early before calling `__validate__`: [3](#0-2) 

`perform_pre_validation_stage` is still called (nonce increment, fee bounds, balance check), but the account's `__validate__` entry point — which is the only place signature verification occurs — is completely skipped. [4](#0-3) 

The third condition (`account_tx_in_pool_or_recent_block`) only checks whether *any* transaction from that address exists in the mempool or was recently committed. It does **not** verify that the incoming invoke originates from the same party who submitted the `deploy_account`: [5](#0-4) 

`contains_account` checks `staged` or `committed` maps, both of which are populated by any transaction from that address: [6](#0-5) 

The mempool's `validate_tx` (called via `validate_by_mempool` before the skip decision) only checks nonce ordering and duplicate tx_hash — it does **not** check signatures: [7](#0-6) 

Fee escalation is enabled in production (`"enable_fee_escalation": true`): [8](#0-7) 

This means an attacker's higher-tip invalid invoke can replace a legitimate lower-tip invoke in the mempool pool without any signature check.

### Impact Explanation

**Broken invariant**: Every transaction admitted to the mempool must carry a valid account signature, or be explicitly exempt for a legitimate reason tied to the submitting party.

**Corrupted value**: The admission decision — an Invoke transaction with an invalid (attacker-controlled) signature is accepted into the mempool.

**Secondary impact**: Via fee escalation, the attacker's invalid invoke can evict the legitimate user's valid invoke from the mempool. The deploy_account then executes successfully (nonce → 1), the attacker's fake invoke fails at execution (invalid signature), and the legitimate invoke is permanently gone. The user must detect the failure and resubmit.

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

- The attack window is the time between a `deploy_account` being submitted and being included in a block (potentially many blocks if the mempool is congested).
- The attacker only needs to observe the public mempool for pending `deploy_account` transactions, which is trivially possible.
- The attacker must pay a higher tip than the victim's invoke, but this cost is bounded and predictable.
- No privileged access is required; any unprivileged user can submit transactions to the gateway.

### Recommendation

1. **Verify the sender identity**: When `skip_stateful_validations` returns `true`, confirm that the `deploy_account` transaction in the mempool for the sender address was submitted by the same party (e.g., by checking that the `deploy_account`'s `contract_address` matches the invoke's `sender_address` and that the deploy_account tx is still pending, not just any account transaction).

2. **Lightweight signature check**: Even when skipping the full `__validate__` entry point execution, perform a static cryptographic signature check against the transaction hash before admission.

3. **Prevent fee escalation for skip-validated transactions**: Mark transactions admitted via the skip path and disallow them from participating in fee escalation replacement of fully-validated transactions.

### Proof of Concept

```
1. Alice pre-funds address A with STRK (required for deploy_account to succeed).
2. Alice submits deploy_account for A (nonce=0, valid signature, tip=T).
3. Alice submits invoke from A (nonce=1, valid signature, tip=T, calldata=<legitimate>).
4. Bob observes Alice's deploy_account in the public mempool.
5. Bob submits invoke from A (nonce=1, INVALID signature, tip=T+1, calldata=<anything>).
6. Gateway stateful validator:
   - account_nonce = 0 (A not deployed yet)
   - tx_nonce = 1
   - account_tx_in_pool_or_recent_block(A) = true (Alice's deploy_account is in pool)
   → skip_stateful_validations returns true
   → run_validate_entry_point sets execution_flags.validate = false
   → __validate__ NOT called → Bob's invoke admitted to mempool
7. Mempool fee escalation: Bob's invoke (tip=T+1) replaces Alice's invoke (tip=T).
8. Batcher executes block:
   - deploy_account executes successfully (account A deployed, nonce → 1)
   - Bob's invoke executes: __validate__ IS called → fails (invalid signature) → reverted
9. Alice's legitimate invoke is permanently evicted from the mempool.
   Alice must detect the failure and resubmit her invoke.
```

The root cause is structurally identical to the FortaStaking analog: a validation check (`_doSafeTransferAcceptanceCheck` / `__validate__`) is skipped during the "constructor-phase" admission (minting during constructor / invoke before account deployment), but enforced during the subsequent operation (inactive share minting / batcher execution), with the difference that here the skip gate is exploitable by a third party rather than only by the original submitter.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-457)
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

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
    }
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

**File:** crates/apollo_deployments/resources/app_configs/mempool_config.json (L1-8)
```json
{
  "mempool_config.dynamic_config.transaction_ttl": 300,
  "mempool_config.static_config.capacity_in_bytes": 1073741824,
  "mempool_config.static_config.committed_nonce_retention_block_count": 100,
  "mempool_config.static_config.declare_delay": 20,
  "mempool_config.static_config.enable_fee_escalation": true,
  "mempool_config.static_config.fee_escalation_percentage": 10
}
```
