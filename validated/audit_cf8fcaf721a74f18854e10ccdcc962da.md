### Title
Signature Validation Bypass via `skip_stateful_validations` Admits Unsigned Invoke Transactions for New Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`skip_stateful_validations` in the gateway's stateful validator skips the account's `__validate__` entry point (signature verification) for any invoke transaction with `nonce=1` whenever `account_tx_in_pool_or_recent_block` returns `true` for the sender. Because that check returns `true` for **any** account that has **any** transaction in the mempool pool — not specifically a `deploy_account` — an unprivileged attacker can submit an invoke with `nonce=1` carrying an arbitrary/invalid signature for a victim account that has a pending `deploy_account` in the pool, bypass the gateway's signature check entirely, and have the transaction admitted to the mempool. With fee escalation enabled, the attacker can then replace the victim's legitimate first invoke with the unsigned fake, which will revert on-chain after the `deploy_account` executes, permanently consuming the victim's nonce=1 slot.

---

### Finding Description

**Trigger condition in `skip_stateful_validations`** [1](#0-0) 

The function returns `true` (skip validation) when:
- the incoming transaction is an `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)` and `account_nonce == Nonce(Felt::ZERO)`
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

**What `account_tx_in_pool_or_recent_block` actually checks** [2](#0-1) 

It returns `true` if the account has **any** transaction in the pool (`tx_pool.contains_account`) **or** appears in the mempool's committed/staged state. It does **not** verify that the existing transaction is a `deploy_account`.

**The code comment's flawed reasoning** [3](#0-2) 

The comment claims the check is sufficient because the account "either has a deploy_account transaction or transactions with future nonces that passed validations." For a brand-new account (on-chain nonce=0), the only transaction that can legitimately be in the pool is a `deploy_account` (any invoke would fail `__validate__` since the contract doesn't exist yet). However, the attacker exploits the window **after** the victim's `deploy_account` is in the pool but **before** the victim's invoke is submitted (or by fee-escalating over it).

**Effect of the skip on the gateway's blockifier call** [4](#0-3) 

When `skip_validate=true`, `execution_flags.validate` is set to `false`, so `blockifier_validator.validate(account_tx)` returns immediately without calling `__validate__`. [5](#0-4) 

**Batcher re-enables validation unconditionally**

When the batcher later executes the transaction it calls `AccountTransaction::new_for_sequencing`, which always sets `validate: true`: [6](#0-5) 

So the fake invoke **will** have `__validate__` called during execution, will fail (invalid signature), and will revert — but the nonce has already been incremented by `perform_pre_validation_stage` before the revert, consuming the victim's nonce=1 slot.

**Fee escalation enables replacement of the victim's legitimate invoke** [7](#0-6) 

If the attacker submits a fake invoke with a tip and `max_l2_gas_price` that exceed the victim's by the configured `fee_escalation_percentage`, the mempool atomically removes the victim's legitimate invoke and inserts the attacker's fake one.

---

### Impact Explanation

**Admission of an invalid transaction (High):** The gateway admits an invoke transaction whose `__validate__` entry point has never been called. This violates the invariant that every admitted invoke must have passed account-level signature/authorization checks before entering the mempool.

**Concrete DoS on new-account first invoke:** The attacker can permanently consume a victim's nonce=1 slot:
1. Victim submits `deploy_account` (nonce=0) → enters pool.
2. Attacker submits fake invoke (nonce=1, invalid signature, fee > victim's) → `skip_stateful_validations` returns `true` → `__validate__` skipped → admitted; fee escalation replaces victim's legitimate invoke.
3. Batcher executes `deploy_account` → account deployed.
4. Batcher executes fake invoke → `__validate__` called → fails → reverts; nonce incremented to 2.
5. Victim's legitimate invoke (nonce=1) is gone; victim must resubmit with nonce=2.

The attacker's only cost is the fee charged for the reverted transaction. The attack is repeatable.

---

### Likelihood Explanation

- The attack window is the period between a `deploy_account` entering the pool and the victim's nonce=1 invoke being committed. This window is observable by anyone monitoring the mempool.
- No privileged access is required; any unprivileged account can submit a transaction for any sender address.
- The attacker must pay the fee for a reverted transaction, but this is a bounded, predictable cost.
- Fee escalation must be enabled for the replacement path; without it the attacker must race to submit before the victim's invoke.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a targeted check that verifies a `deploy_account` transaction specifically exists in the pool for the sender address. The mempool should expose a `has_deploy_account_in_pool(address)` query, and `skip_stateful_validations` should call that instead. This preserves the UX intent (allow simultaneous `deploy_account` + invoke submission) while closing the window for unsigned invoke injection.

---

### Proof of Concept

```
Preconditions:
  - fee_escalation enabled (fee_escalation_percentage = 10)
  - Victim account V has on-chain nonce = 0 (never deployed)

Step 1: Victim submits deploy_account for address V (nonce=0, tip=100, gas_price=100)
  → Gateway: stateless OK, stateful OK (deploy_account runs full execution)
  → Mempool pool: {V: deploy_account(nonce=0)}
  → account_tx_in_pool_or_recent_block(V) == true

Step 2: Victim submits invoke(nonce=1, tip=50, gas_price=50, valid_signature)
  → skip_stateful_validations: nonce==1, account_nonce==0, pool_check==true → skip=true
  → __validate__ NOT called in gateway
  → Mempool pool: {V: deploy_account(nonce=0), invoke(nonce=1, tip=50)}

Step 3: Attacker submits invoke(nonce=1, tip=56, gas_price=56, INVALID_SIGNATURE)
  → skip_stateful_validations: same conditions → skip=true
  → __validate__ NOT called in gateway
  → validate_fee_escalation: 56 >= 50 * 1.10 = 55 → replacement accepted
  → Victim's legitimate invoke(nonce=1) is REMOVED from pool
  → Mempool pool: {V: deploy_account(nonce=0), FAKE_invoke(nonce=1, tip=56)}

Step 4: Batcher executes deploy_account(nonce=0) → V deployed, on-chain nonce=1

Step 5: Batcher executes FAKE_invoke(nonce=1) with validate=true
  → __validate__ called → INVALID_SIGNATURE → REVERT
  → On-chain nonce incremented to 2

Result: Victim's legitimate invoke(nonce=1) is permanently lost.
        Victim must resubmit with nonce=2.
        Attacker paid fee for one reverted transaction.
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L760-792)
```rust
    fn validate_fee_escalation(
        &self,
        incoming_tx_reference: TransactionReference,
    ) -> MempoolResult<Option<TransactionReference>> {
        let TransactionReference { address, nonce, .. } = incoming_tx_reference;

        self.validate_no_delayed_declare_front_run(incoming_tx_reference)?;

        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
        }

        let Some(existing_tx_reference) = self.tx_pool.get_by_address_and_nonce(address, nonce)
        else {
            // Replacement irrelevant: no existing transaction with the same nonce for address.
            return Ok(None);
        };

        if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
            info!(
                "{existing_tx_reference} was not replaced by {incoming_tx_reference} due to \
                 insufficient fee escalation."
            );
            // TODO(Elin): consider adding a more specific error type / message.
            return Err(MempoolError::DuplicateNonce { address, nonce });
        }

        Ok(Some(existing_tx_reference))
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
