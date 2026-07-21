### Title
Gateway Admits Unsigned Invoke Transaction via `skip_stateful_validations` Bypass, Enabling Griefing of Deploying Accounts - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips `__validate__` (account signature verification) for any invoke transaction with nonce=1 when the sender's address appears in the mempool or recent block history. An unprivileged attacker can exploit this to inject an invoke transaction with an arbitrary (invalid) signature targeting any account that has a pending `deploy_account` transaction, causing the victim's account to pay fees for a reverted transaction and, via fee escalation, permanently displace the victim's legitimate nonce-1 transaction from the mempool.

### Finding Description

The `skip_stateful_validations` function at `crates/apollo_gateway/src/stateful_transaction_validator.rs` lines 429–461 returns `true` (skip `__validate__`) when all of the following hold:

1. The transaction is an `Invoke` type.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` constructs the `AccountTransaction` with `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate: false`, execution returns immediately after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check is satisfied by **any** transaction from the target address in the mempool pool or recent committed block — not specifically a `deploy_account` transaction:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The gateway's `validate_nonce` function permits nonce=1 for an invoke tx when `account_nonce=0` (within the 200-gap window), so the nonce check does not block the attack: [5](#0-4) 

`validate_by_mempool` (called before `skip_stateful_validations`) performs only duplicate-hash and fee-escalation checks — no cryptographic signature verification: [6](#0-5) 

Fee escalation is enabled by default (`fee_escalation_percentage: 10`): [7](#0-6) 

When the attacker's tx has tip and `max_l2_gas_price` ≥ 110% of the victim's existing nonce-1 tx, `validate_fee_escalation` returns `Ok(Some(existing_tx_reference))`, and the subsequent `add_tx` call removes the victim's legitimate tx and inserts the attacker's invalid one: [8](#0-7) 

During batcher execution, `__validate__` **is** called (the batcher uses `validate: true`). The invalid signature causes `__validate__` to fail, the transaction is reverted, and the victim's account is charged the revert fee. The victim's legitimate nonce-1 tx has already been evicted.

`handle_nonce` with `strict_nonce_check: false` (used during gateway validation) accepts `account_nonce <= incoming_tx_nonce`, so nonce=1 passes even though the account is not yet deployed: [9](#0-8) 

### Impact Explanation

This is a **High** impact finding matching: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concretely:
- The gateway admits a transaction with an arbitrary (attacker-controlled) signature into the mempool without any cryptographic verification.
- Via fee escalation, the attacker's invalid tx permanently displaces the victim's legitimate nonce-1 tx from the mempool.
- The batcher executes the attacker's tx against the victim's account; `__validate__` fails, the tx is reverted, and the victim's account is charged the revert fee.
- The victim's legitimate tx is gone; the victim must resubmit and pay again.
- The attacker bears zero cost: the fee is debited from the victim's account.

### Likelihood Explanation

- **Unprivileged trigger**: Any observer of the public mempool can execute this attack the moment a `deploy_account` transaction appears for any address.
- **Zero attacker cost**: The fee for the reverted transaction is charged to the victim's account, not the attacker's.
- **Deterministic**: The four conditions checked by `skip_stateful_validations` are fully observable and controllable by the attacker.
- **Single-shot per victim per deployment**: The window is nonce=1 only, but that is precisely the first user action after account deployment — a high-value target.

### Recommendation

1. **Do not skip `__validate__` entirely.** Instead, run `__validate__` with `strict_nonce_check: false` so the signature is verified even when the account is not yet on-chain. The nonce leniency is the UX accommodation needed; signature skipping is not.
2. **Alternatively**, perform a lightweight stateless signature check at the gateway level (e.g., ECDSA verification against the account's expected public key derived from the pending `deploy_account` constructor calldata) before granting the skip.
3. **At minimum**, gate the skip on the presence of a `deploy_account` transaction specifically (not any transaction) for the sender address in the mempool, and verify that the `deploy_account` tx hash matches the one provided by the user.

### Proof of Concept

```
1. Victim broadcasts:
     deploy_account_tx { sender: A, nonce: 0, class_hash: C, constructor_calldata: [pubkey], sig: valid }
   → mempool.account_tx_in_pool_or_recent_block(A) == true

2. Attacker broadcasts:
     invoke_tx { sender: A, nonce: 1, calldata: [drain_funds...],
                 sig: [0x0, 0x0],          // arbitrary invalid signature
                 tip: victim_tip * 1.2,    // beats fee escalation threshold
                 max_l2_gas_price: victim_price * 1.2 }

3. Gateway stateful validation:
     validate_nonce(nonce=1, account_nonce=0) → OK (0 ≤ 1 ≤ 200)
     validate_by_mempool → OK (no sig check; fee escalation passes)
     skip_stateful_validations → true  (A in mempool, nonce==1, account_nonce==0)
     run_validate_entry_point(validate=false) → __validate__ NOT called → OK

4. mempool.add_tx:
     fee escalation removes victim's legitimate nonce-1 tx
     attacker's tx inserted at (A, nonce=1)

5. Batcher executes block:
     deploy_account_tx(A, nonce=0) → A deployed, nonce → 1
     invoke_tx(A, nonce=1, sig=[0,0]) → __validate__ called → FAIL (bad sig)
       → tx reverted, victim's account charged revert fee
       → victim's legitimate tx is gone
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L756-792)
```rust
    /// Validates whether the incoming transaction may replace an existing one at the same
    /// `(address, nonce)` via fee escalation, without mutating any state. Returns the existing
    /// transaction to be replaced when a valid replacement exists, `None` when there is nothing to
    /// replace, or an error when a replacement is present but not permitted.
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

**File:** crates/apollo_mempool_config/src/config.rs (L85-99)
```rust
impl Default for MempoolStaticConfig {
    fn default() -> Self {
        Self {
            enable_fee_escalation: true,
            validate_resource_bounds: true,
            fee_escalation_percentage: 10,
            declare_delay: Duration::from_secs(1),
            committed_nonce_retention_block_count: 100,
            capacity_in_bytes: 1 << 30, // 1GB.
            behavior_mode: BehaviorMode::Starknet,
            recorder_url: "https://recorder_url"
                .parse::<Url>()
                .expect("recorder_url must be a valid Recorder URL"),
        }
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L478-503)
```rust
    fn handle_nonce(
        state: &mut dyn State,
        tx_info: &TransactionInfo,
        strict: bool,
    ) -> TransactionPreValidationResult<()> {
        if tx_info.is_v0() {
            return Ok(());
        }

        let address = tx_info.sender_address();
        let account_nonce = state.get_nonce_at(address)?;
        let incoming_tx_nonce = tx_info.nonce();
        let valid_nonce = if strict {
            account_nonce == incoming_tx_nonce
        } else {
            account_nonce <= incoming_tx_nonce
        };
        if valid_nonce {
            return Ok(state.increment_nonce(address)?);
        }
        Err(TransactionPreValidationError::InvalidNonce {
            address,
            account_nonce,
            incoming_tx_nonce,
        })
    }
```
