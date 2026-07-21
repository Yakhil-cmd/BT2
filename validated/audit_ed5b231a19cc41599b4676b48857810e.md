### Title
Invoke Transaction with Nonce=1 Admitted to Mempool Without Signature Verification via `skip_stateful_validations` Front-Running — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's UX feature that skips `__validate__` for the first invoke after a `deploy_account` can be triggered by any third-party observer, not only the account owner. An attacker who sees a `deploy_account` transaction in the mempool can immediately submit an invoke with `nonce=1` for the same address carrying an arbitrary/invalid signature. The gateway admits it without running the account's `__validate__` entry point, placing an unverified transaction in the nonce-1 slot and forcing the legitimate user to pay a fee-escalation premium or lose their slot for that block.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip the `__validate__` call) whenever **all three** conditions hold:

1. The incoming transaction is an `Invoke` with `tx.nonce() == Nonce(Felt::ONE)`.
2. The on-chain account nonce is `Nonce(Felt::ZERO)` (account not yet deployed).
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

Condition 3 is satisfied as soon as **any** transaction from that address is in the mempool. Because a `deploy_account` (nonce=0) submitted by Alice passes full execution validation and enters the pool, `account_tx_in_pool_or_recent_block` immediately returns `true` for Alice's address. [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `execution_flags.validate` is `false` the function returns `Ok(())` immediately, never calling the account's `__validate__` entry point: [4](#0-3) 

The stateless validator only checks signature **length** (≤ 4000 felts), not its cryptographic validity: [5](#0-4) 

Therefore an attacker who observes Alice's `deploy_account` in the mempool can submit an `Invoke(nonce=1, sender=Alice, signature=<garbage>)` and have it admitted without any signature check.

---

### Impact Explanation

**Broken invariant (admission):** Every transaction admitted to the mempool must either have a verified signature or be explicitly exempt for a reason that cannot be triggered by a third party. Here a third party can trigger the exemption for any address whose `deploy_account` is visible in the mempool.

Concrete consequences:

* The attacker's invalid invoke occupies Alice's `nonce=1` slot. Alice's legitimate `nonce=1` invoke is rejected as a duplicate or must pay a fee-escalation premium to replace it.
* When the batcher executes the attacker's invoke, `new_for_sequencing` re-enables `validate=true`: [6](#0-5) 

  `__validate__` then fails (invalid signature), the transaction is rejected, and Alice's nonce-1 slot is freed — but only after one block delay.
* The attack is free: no fee is charged for a transaction whose `__validate__` panics.
* At scale, an attacker can monitor the mempool for all `deploy_account` transactions and front-run every new account's first invoke, causing systematic disruption.

This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

* `deploy_account` transactions are publicly visible in the mempool.
* The attacker needs only to craft an `Invoke` with `nonce=1` and any non-empty signature (to pass the stateless length check). No cryptographic material from Alice is required.
* The attack is repeatable and costless.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a `deploy_account` transaction (nonce=0, type=DeployAccount) for the sender address is present in the pool. Alternatively, perform a lightweight signature pre-check (e.g., ECDSA format validation) even when skipping the full `__validate__` entry point, so that obviously invalid signatures are rejected before admission.

---

### Proof of Concept

```
1. Alice broadcasts:
     deploy_account { sender=A, nonce=0, class_hash=C, salt=S, signature=<valid> }
   → admitted to mempool; account_tx_in_pool_or_recent_block(A) == true

2. Attacker broadcasts (before Alice's deploy_account is committed):
     invoke { sender=A, nonce=1, calldata=<drain Alice's funds>, signature=<0x1337> }

3. Gateway stateful path:
     get_nonce_from_state(A)  → Nonce(0)          ✓ (account not deployed)
     validate_nonce(nonce=1)  → 0 ≤ 1 ≤ 200       ✓
     validate_by_mempool()    → no duplicate hash  ✓
     skip_stateful_validations:
       tx.nonce()==1 && account_nonce==0 && account_in_pool==true → return true
     run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       StatefulValidator::perform_validations → returns Ok(()) immediately
   → attacker's invoke admitted to mempool

4. Alice's legitimate invoke { sender=A, nonce=1, signature=<valid> }
   → rejected (DuplicateNonce) or must pay higher tip to replace attacker's tx

5. Batcher executes attacker's invoke:
     new_for_sequencing sets validate=true
     __validate__ called → ECDSA fails → transaction rejected, no fee charged
   → Alice's nonce-1 slot freed after one block; Alice's invoke was delayed/lost
``` [7](#0-6) [4](#0-3) [8](#0-7)

### Citations

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L31-54)
```rust
impl StatelessTransactionValidator {
    #[instrument(skip(self), level = Level::INFO)]
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
