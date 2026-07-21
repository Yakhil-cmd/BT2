### Title
Attacker Can Inject Signature-Bypassed Invoke Into Mempool via `skip_stateful_validations` Race on Victim's Deploy-Account — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` skips the `__validate__` entry-point call (i.e., signature verification) for any Invoke with `nonce == 1` whose sender address already appears in `account_tx_in_pool_or_recent_block`. Because that check returns `true` the moment a victim's `DeployAccount` lands in the mempool, an unprivileged attacker can immediately submit an Invoke with `nonce == 1` for the victim's address carrying an **arbitrary or invalid signature**, have it admitted to the mempool without any signature check, and optionally displace the victim's own post-deploy Invoke via fee escalation.

---

### Finding Description

**Relevant code — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when:
1. The incoming tx is `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)`
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain)
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`

`account_tx_in_pool_or_recent_block` is: [2](#0-1) 

which delegates to: [3](#0-2) 

It returns `true` for **any** transaction from that address in the pool — not specifically a `DeployAccount`.

When `skip_validate == true`, `run_validate_entry_point` sets `validate: false`: [4](#0-3) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the function returns immediately after `perform_pre_validation_stage`, never calling `__validate__`: [5](#0-4) 

**Attack path:**

1. Victim broadcasts `DeployAccount` for address `A` (valid signature). It passes gateway validation and is added to the mempool. `tx_pool.contains_account(A)` is now `true`.
2. Attacker observes the mempool, computes address `A` (deterministic from `class_hash`, `salt`, `constructor_calldata`).
3. Attacker submits `Invoke(sender=A, nonce=1, calldata=<arbitrary>, signature=<invalid>)`.
4. Gateway `validate_nonce`: `account_nonce=0`, `incoming=1`, within `max_allowed_nonce_gap` → **passes**. [6](#0-5) 

5. `validate_by_mempool` → mempool checks nonce/fee/duplicate only, no signature check → **passes**.
6. `skip_stateful_validations`: `account_tx_in_pool_or_recent_block(A)` returns `true` (victim's `DeployAccount` is in pool) → returns `true`.
7. `run_validate_entry_point` with `validate=false` → `__validate__` **never called** → **passes**.
8. Attacker's Invoke (invalid signature) is added to the mempool.
9. If victim also submitted `Invoke(nonce=1)`, attacker can replace it via fee escalation (`validate_fee_escalation` only checks fee, not signature). [7](#0-6) 

**At batcher execution time**, `new_for_sequencing` always sets `validate: true`: [8](#0-7) 

So the attacker's Invoke fails `__validate__` in the batcher and is rejected. However, the victim's legitimate `Invoke(nonce=1)` was already displaced from the mempool and must be resubmitted. The attacker can repeat this indefinitely.

---

### Impact Explanation

The gateway admits an Invoke transaction whose signature was never verified. This matches:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concretely: any `DeployAccount` in the mempool becomes a trigger that lets an attacker inject signature-free Invokes for the victim's address, permanently racing and displacing the victim's first post-deploy transaction.

---

### Likelihood Explanation

- Requires no privilege: any observer of the public mempool can execute this.
- The victim's `DeployAccount` address is fully deterministic and computable from the public transaction fields.
- The attacker only needs to pay a marginally higher fee than the victim's Invoke to replace it (fee escalation threshold).
- The attack is repeatable: every time the victim resubmits, the attacker can front-run again.

---

### Recommendation

`skip_stateful_validations` must verify that the transaction in the pool for the sender address is specifically a `DeployAccount`, not just any transaction. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool` that checks `tx_pool` for a `DeployAccount` transaction at `nonce == 0` for the given address. Replace the current `account_tx_in_pool_or_recent_block` call with this stricter check so that only the legitimate deploy-account + invoke UX pattern triggers the skip, and an attacker cannot exploit an existing `DeployAccount` in the pool to bypass signature verification for their own Invoke.

---

### Proof of Concept

```
1. Victim submits:
     DeployAccount { class_hash=C, salt=S, constructor_calldata=D, signature=<valid> }
     → contract_address A = hash(C, S, D, deployer=0)
     → accepted by gateway, added to mempool

2. Attacker computes A from the public DeployAccount fields.

3. Attacker submits:
     Invoke { sender=A, nonce=1, calldata=<anything>, signature=<garbage>,
              resource_bounds=<higher than victim's Invoke> }

4. Gateway stateful validation:
     validate_nonce:          account_nonce=0, tx_nonce=1, within gap → OK
     validate_by_mempool:     no nonce=1 for A yet (or fee escalation passes) → OK
     skip_stateful_validations:
         tx.nonce()==1 && account_nonce==0 → check pool
         account_tx_in_pool_or_recent_block(A) → TRUE (victim's DeployAccount)
         → returns true (skip __validate__)
     run_validate_entry_point(skip_validate=true):
         validate=false → __validate__ NOT called → OK

5. Attacker's Invoke (garbage signature) is in the mempool at nonce=1 for address A.
   Victim's Invoke(nonce=1) is displaced (if submitted) or blocked.

6. Batcher executes DeployAccount(nonce=0) → succeeds.
   Batcher executes attacker's Invoke(nonce=1) with validate=true → __validate__ fails → rejected.
   Victim's Invoke is gone; victim must resubmit. Attacker repeats from step 3.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L286-296)
```rust
            // Other transactions must be within the allowed nonce range.
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-315)
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

**File:** crates/apollo_mempool/src/mempool.rs (L760-791)
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
