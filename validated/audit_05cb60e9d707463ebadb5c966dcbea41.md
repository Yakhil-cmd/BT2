### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions into Mempool, Blocking Victim's Post-Deploy Invoke Slot - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` UX feature, intended to allow a user to submit a `deploy_account` + `invoke` pair atomically, can be abused by an unprivileged attacker to inject an invoke transaction with a completely invalid (or attacker-controlled) signature into the mempool without any signature verification. The attacker front-runs the victim's `deploy_account` transaction, occupies the victim's nonce-1 slot with a garbage-signature invoke, and causes the victim's legitimate invoke to be rejected with `DuplicateNonce` until the attacker's transaction is eventually executed and rejected by the blockifier.

---

### Finding Description

**Root cause — `skip_stateful_validations` in `stateful_transaction_validator.rs`**

`skip_stateful_validations` returns `true` (skip `__validate__`) when all three conditions hold:

```
tx is Invoke
tx.nonce() == Nonce(Felt::ONE)          // nonce = 1
account_nonce == Nonce(Felt::ZERO)      // account not yet deployed
account_tx_in_pool_or_recent_block(sender_address) == true
``` [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` constructs the `AccountTransaction` with `validate: false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` entry point is never called and the function returns `Ok(())` immediately:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [3](#0-2) 

**The `account_tx_in_pool_or_recent_block` check is not deploy-account-specific**

The mempool check returns `true` for *any* transaction in the pool for that address, not specifically a `deploy_account`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

For an undeployed account (nonce = 0), the only way to get a transaction into the pool is a valid `deploy_account` transaction. Once the victim submits one, the condition is satisfied for *any* attacker-crafted invoke with nonce = 1.

**Mempool blocks the victim's legitimate invoke**

When fee escalation is disabled (the default), the mempool rejects any second transaction at the same `(address, nonce)` with `DuplicateNonce`:

```rust
if !self.config.static_config.enable_fee_escalation {
    if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
        return Err(MempoolError::DuplicateNonce { address, nonce });
    };
    return Ok(None);
}
``` [5](#0-4) 

The victim's legitimate invoke (nonce = 1) is therefore rejected until the attacker's transaction is executed by the blockifier and removed via `commit_block`.

**Execution does not save the attacker — but the damage is already done**

During actual block execution the batcher uses `AccountTransaction::new_for_sequencing`, which always sets `validate: true, strict_nonce_check: true`:

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
``` [6](#0-5) 

The attacker's invalid-signature invoke will fail `__validate__` and be rejected. But the mempool slot was already occupied, and the victim's invoke was already denied admission.

---

### Impact Explanation

**Impact: High** — matches "Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."

An unprivileged attacker can:
1. Inject a signature-less (or garbage-signature) invoke transaction into the production mempool, bypassing the gateway's stateful signature-verification step.
2. Block the victim's legitimate post-deploy invoke from entering the mempool (DuplicateNonce), disrupting the deploy_account + invoke UX flow the feature was designed to enable.
3. Force the victim to wait for the attacker's transaction to be executed and rejected before resubmitting.

The attacker cannot steal funds (the tx fails `__validate__` at execution time), but the admission invariant — *only signature-valid transactions enter the mempool* — is broken.

---

### Likelihood Explanation

**Likelihood: Medium.**

- The attack requires the victim to have submitted a `deploy_account` transaction that is visible in the mempool (public state).
- The attacker needs to submit their invoke before the victim's own invoke is processed.
- No privileged access, no special knowledge of the victim's private key, and no on-chain state manipulation is required.
- The mempool is public; any observer can detect a pending `deploy_account` and immediately front-run with a nonce-1 invoke.

---

### Recommendation

1. **Restrict the skip condition to deploy-account-specific evidence.** Instead of checking `account_tx_in_pool_or_recent_block` (which matches any tx type), expose a dedicated `has_pending_deploy_account(address)` query on the mempool that returns `true` only when a `deploy_account` transaction is present for that address.

2. **Alternatively, bind the skip to the same submission batch.** Accept the deploy_account + invoke pair as a single atomic gateway request and skip validation only for the invoke submitted in that same call, rather than relying on a global mempool state check.

3. **As a defense-in-depth measure**, perform a lightweight stateless signature-length/format check before admitting any transaction to the mempool, even when `__validate__` is skipped.

---

### Proof of Concept

```
1. Victim calls gateway: add_tx(deploy_account, sender=A, nonce=0, valid_sig)
   → deploy_account passes __validate_deploy__, enters mempool for address A.

2. Attacker observes mempool: account_tx_in_pool_or_recent_block(A) == true.

3. Attacker calls gateway: add_tx(invoke, sender=A, nonce=1, signature=[0x0, 0x0])

   Gateway flow:
   a. stateless_tx_validator.validate() — passes (signature length is valid).
   b. convert_rpc_tx_to_internal_and_executable_txs() — tx hash computed, no sig check.
   c. extract_state_nonce_and_run_validations():
      - get_nonce(A) → 0  (account not deployed)
      - validate_nonce: nonce=1, account_nonce=0, max_gap=N → passes (1 ≤ N)
      - validate_by_mempool: nonce range OK
      - skip_stateful_validations:
          tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
          → returns true
      - run_validate_entry_point(skip_validate=true):
          ExecutionFlags { validate: false, ... }
          perform_validations → early return Ok(()) — __validate__ NEVER CALLED
   d. mempool.add_tx(attacker_invoke, nonce=1) → accepted.

4. Victim calls gateway: add_tx(invoke, sender=A, nonce=1, valid_sig)
   → mempool.validate_tx → DuplicateNonce { address: A, nonce: 1 } → REJECTED.

5. Batcher executes attacker's invoke:
   AccountTransaction::new_for_sequencing → validate: true
   __validate__ called → signature [0x0, 0x0] fails → tx rejected, removed from mempool.

6. Victim must resubmit their invoke.
```

Key code locations:

- `skip_stateful_validations`: [7](#0-6) 
- `run_validate_entry_point` (validate flag set to false): [8](#0-7) 
- `perform_validations` early-return when `validate==false`: [9](#0-8) 
- `DuplicateNonce` rejection in mempool: [10](#0-9) 
- `new_for_sequencing` (validate=true at execution): [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-355)
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

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L768-774)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
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
