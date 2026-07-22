### Title
`skip_stateful_validations` admits unsigned invoke transactions for any account with a pending deploy-account in the mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function skips the `__validate__` entry point (the sole signature-verification step) for any invoke transaction whose nonce is `1` and whose sender's on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true` for that sender address. Because the mempool check is keyed only on the *address* — not on any proof that the current submitter controls that address — an unprivileged attacker can submit an invoke transaction with an arbitrary or empty signature for any victim account that has a pending deploy-account transaction in the mempool, and the gateway will admit it without ever calling `__validate__`.

---

### Finding Description

**Invariant broken:** Every non-v0 account transaction must have its `__validate__` entry point executed before it is admitted to the mempool. `__validate__` is the only place where the account contract verifies the caller's signature.

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:

1. The transaction is an `Invoke` with `nonce == 1`.
2. The account's on-chain nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [2](#0-1) 

Condition 3 is satisfied whenever *any* transaction from that address exists in the mempool pool or in the mempool's committed-block state: [3](#0-2) 

The check does **not** verify that the submitter of the current transaction is the same party who submitted the deploy-account. An attacker who observes a victim's deploy-account in the mempool can immediately submit an invoke with `sender_address = victim`, `nonce = 1`, and an invalid/empty signature. All three conditions are satisfied, so `skip_validate = true`.

**Effect on gateway validation:**

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`, so `blockifier_validator.validate(account_tx)` never calls `validate_tx` / `__validate__`: [4](#0-3) [5](#0-4) [6](#0-5) 

The transaction passes all gateway checks and is forwarded to the mempool.

**Analog to the EVM bug:** `unstakeLP` checked whether the caller held enough ZEROvp (a resource check) but not whether the caller owned the specific token (an ownership check). Here, `skip_stateful_validations` checks whether *some* transaction from the address exists in the mempool (a resource/presence check) but not whether the *current submitter* controls the account (an ownership/authorization check).

**Stateless validator does not close the gap:** `StatelessTransactionValidator::validate` only checks signature *length*, not validity: [7](#0-6) 

`validate_by_mempool` checks nonce ordering and duplicates, not signatures: [8](#0-7) 

**Execution outcome:** When the batcher later executes the transaction it reconstructs the `AccountTransaction` with `validate: true` (the default for sequencing): [9](#0-8) 

For accounts with real signature verification, `__validate__` will fail and the transaction will be rejected. However, the transaction was already admitted to the mempool, occupying a slot and consuming sequencer resources.

---

### Impact Explanation

**Category:** High — Mempool/gateway admission accepts invalid transactions before sequencing.

An attacker can inject unsigned invoke transactions for any victim account that has a pending deploy-account in the mempool. Concrete effects:

- **Mempool slot squatting:** The attacker's transaction occupies the `(victim_address, nonce=1)` slot. Depending on fee-escalation rules, the victim's legitimate invoke may be delayed or require a higher fee to displace the attacker's entry.
- **Sequencer resource waste:** The batcher executes the attacker's transaction, runs `__validate__`, fails, and discards it — consuming gas accounting, state-read, and CPU resources for every injected transaction.
- **Sustained DoS:** Because the attack is cheap (only a valid-fee transaction is required) and the mempool's `account_tx_in_pool_or_recent_block` persists even after a block is committed, the attacker can continuously re-inject invalid transactions for any account that has ever appeared in the mempool.

---

### Likelihood Explanation

- The mempool is observable; deploy-account transactions are visible to any node.
- The attack requires no special privilege, no stake, and no knowledge of the victim's private key.
- The attack window is the entire period between a deploy-account being submitted and its block being committed — typically multiple seconds to minutes.
- The attacker only needs to pay the fee for their own (failing) transaction.

---

### Recommendation

1. **Verify transaction type in the mempool:** Change `account_tx_in_pool_or_recent_block` (or add a new query) to confirm that the transaction in the mempool for the address is specifically a `DeployAccount` transaction, not an arbitrary invoke or declare.

2. **Require a lightweight signature check even when skipping full `__validate__`:** Before skipping, verify that the transaction's signature is structurally consistent with the account's expected key (e.g., check the ECDSA signature against the deploy-account's `contract_address_salt`-derived public key).

3. **Scope the skip to same-session submissions:** Track that the deploy-account and the invoke were submitted in the same gateway request or within a short time window from the same source, rather than relying solely on mempool presence.

---

### Proof of Concept

```
1. Alice submits RpcDeployAccountTransaction for address 0xALICE (nonce=0).
   → Mempool now contains Alice's deploy-account.
   → account_tx_in_pool_or_recent_block(0xALICE) == true.

2. Bob submits RpcInvokeTransaction:
     sender_address = 0xALICE
     nonce          = 1
     calldata       = [arbitrary]
     signature      = []   // empty / invalid

3. Gateway stateless validator: passes (signature length 0 ≤ max_signature_length).

4. Gateway stateful validator calls skip_stateful_validations:
     tx.nonce()    == Nonce(1)  ✓
     account_nonce == Nonce(0)  ✓  (Alice not yet deployed on-chain)
     account_tx_in_pool_or_recent_block(0xALICE) == true  ✓
   → skip_validate = true
   → run_validate_entry_point sets execution_flags.validate = false
   → __validate__ is never called
   → Transaction admitted to mempool.

5. Batcher executes Alice's deploy-account (nonce 0 → 1), then Bob's invoke:
     execution_flags.validate = true  (new_for_sequencing default)
     __validate__ is called on Alice's newly deployed contract
     Alice's __validate__ checks signature → fails (Bob has no valid key)
     Transaction reverted / rejected.

6. Bob's transaction occupied Alice's nonce-1 slot in the mempool,
   delayed Alice's legitimate invoke, and wasted batcher execution resources.
   Bob can repeat this indefinitely at low cost.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L413-424)
```rust
/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-84)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L992-1001)
```rust
impl ValidatableTransaction for AccountTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut GasCounter,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```
