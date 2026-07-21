### Title
Signature Validation Bypass via `skip_stateful_validations` Allows Unsigned Invoke Transactions into Mempool - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (signature check) for any invoke transaction with `nonce=1` sent from an address that has **any** transaction in the mempool. An attacker who observes a victim's `deploy_account` transaction enter the mempool can immediately submit a forged invoke transaction (nonce=1, arbitrary calldata, invalid signature) from the victim's address. The gateway admits it without ever calling `__validate__`, violating the invariant that every mempool invoke transaction has passed signature verification.

### Finding Description

**Root cause — `skip_stateful_validations`:**

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
```

The function fires when three conditions hold simultaneously:

1. The incoming transaction is an `ExecutableTransaction::Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` (nonce = 1).
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).

When all three hold it calls `account_tx_in_pool_or_recent_block(sender_address)`. If that returns `true` the function returns `true` (skip validation). [1](#0-0) 

**`account_tx_in_pool_or_recent_block` is not deploy-account-specific:**

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

It returns `true` if the address has **any** transaction in the pool — not specifically a `deploy_account` transaction. The comment in `skip_stateful_validations` claims this is sufficient, but it is not: an attacker can exploit the window between the victim's `deploy_account` entering the pool and the victim's own invoke being submitted. [2](#0-1) 

**Effect of `skip_validate = true`:**

In `run_validate_entry_point`, when `skip_validate` is `true`, `execution_flags.validate` is set to `false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

This is passed to `StatefulValidator::perform_validations`, which for invoke transactions checks `if !tx.execution_flags.validate { return Ok(()); }` — the `__validate__` call is entirely skipped. [3](#0-2) [4](#0-3) 

**`validate_by_mempool` does not check signatures:**

`validate_by_mempool` is called before `skip_stateful_validations` and only checks for duplicate tx_hash and nonce ordering — it never inspects the signature. [5](#0-4) [6](#0-5) 

**Full call chain:**

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (resource bounds + nonce range — no sig)
       ├─ validate_by_mempool            (dup hash + nonce order — no sig)
       └─ skip_stateful_validations      ← returns true if address in pool
  └─ run_validate_entry_point(skip_validate=true)  ← __validate__ skipped
``` [7](#0-6) 

**Fee escalation enables victim-tx replacement:**

The mempool has `enable_fee_escalation: true` by default (10% bump required). An attacker who pays a tip and `max_l2_gas_price` at least 10% higher than the victim's legitimate invoke tx will atomically replace it in the pool. [8](#0-7) [9](#0-8) 

### Impact Explanation

An attacker can inject an invoke transaction carrying an arbitrary, attacker-chosen calldata and an invalid signature into the mempool without any signature check. This directly satisfies:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concrete consequences:

- The attacker's unsigned tx occupies the victim's nonce=1 slot in the mempool.
- Via fee escalation the attacker can evict the victim's legitimate invoke tx.
- The victim's `deploy_account` executes on-chain, but their first invoke is gone; they must resubmit.
- The attacker's tx is rejected by the batcher (which uses `AccountTransaction::new_for_sequencing` with `validate: true`), but the damage — eviction of the victim's tx — is already done. [10](#0-9) 

### Likelihood Explanation

The attack requires:

1. Monitoring the public mempool for `deploy_account` transactions (trivial).
2. Knowing the victim's sender address (embedded in the `deploy_account` tx).
3. Submitting a forged invoke (nonce=1) before the victim's own invoke is processed — a window of seconds to minutes.
4. Paying a fee 10% higher than the victim's invoke to trigger replacement.

No privileged access is needed. The attacker controls only their own RPC submission. The window is narrow but repeatable and automatable.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** for the sender address is present in the pool:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())

// Use a new mempool API:
mempool_client.deploy_account_tx_in_pool(tx.sender_address())
```

The mempool should expose a method that returns `true` only when a `deploy_account` transaction (not just any transaction) for the given address is currently pooled. This closes the window where any pooled transaction — including one submitted by an attacker — satisfies the skip condition.

Alternatively, restrict the skip to cases where the `deploy_account` tx hash is explicitly provided by the caller (as the `native_blockifier` path already does via `deploy_account_tx_hash: Option<TransactionHash>`). [11](#0-10) 

### Proof of Concept

```
Preconditions:
  - Victim address V has nonce=0 on-chain (not yet deployed).
  - Victim submits deploy_account tx D (nonce=0) to the gateway.
  - D passes full validation; V is now in tx_pool.contains_account.

Attack steps:
1. Attacker observes D in the mempool (public).
2. Attacker constructs invoke tx A:
     sender_address = V
     nonce          = 1
     calldata       = <arbitrary>
     signature      = [0x41, 0x41]   // invalid
     tip            = victim_tip * 1.11
     max_l2_gas_price = victim_price * 1.11
3. Attacker submits A to the gateway.

Gateway processing of A:
  - validate_state_preconditions: nonce 1 >= account_nonce 0 ✓
  - validate_by_mempool: no dup hash, nonce 1 >= 0 ✓
  - skip_stateful_validations:
      tx.nonce()==1 ✓, account_nonce==0 ✓
      account_tx_in_pool_or_recent_block(V) == true (D is pooled) ✓
      → returns true
  - run_validate_entry_point(skip_validate=true):
      execution_flags.validate = false
      __validate__ NOT called ✓
  - A is forwarded to mempool.add_tx.

Mempool:
  - fee escalation: A.tip > victim_invoke.tip by 11% → victim's invoke evicted.
  - A occupies nonce=1 slot for V.

Batcher:
  - Picks up A, calls AccountTransaction::new_for_sequencing (validate=true).
  - __validate__ fails (invalid signature) → A rejected.
  - Victim's deploy_account executes; their invoke is gone.
```

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

**File:** crates/native_blockifier/src/py_validator.rs (L98-121)
```rust
    pub fn should_run_stateful_validations(
        &mut self,
        account_tx: &AccountTransaction,
        deploy_account_tx_hash: Option<TransactionHash>,
    ) -> StatefulValidatorResult<bool> {
        if account_tx.tx_type() != TransactionType::InvokeFunction {
            return Ok(true);
        }
        let tx_info = account_tx.create_tx_info();
        let nonce = self.stateful_validator.get_nonce(tx_info.sender_address())?;

        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;

        Ok(!skip_validate)
    }
```
