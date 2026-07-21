### Title
Unauthenticated Invoke Transaction Bypasses Signature Validation via `skip_stateful_validations` Deploy-Account UX Path — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account has a pending deploy-account transaction. The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction in the pool for that address, not specifically a deploy-account transaction. Because the skip itself is the only signature check at the gateway level, an attacker who observes a deploy-account transaction entering the mempool for address A can immediately submit an invoke transaction with nonce=1, an arbitrary payload, and an invalid signature for A. The gateway accepts it without running `__validate__`, admitting an unauthenticated transaction into the mempool.

---

### Finding Description

**Relevant code — `skip_stateful_validations`:** [1](#0-0) 

The function returns `true` (skip validation) when all three conditions hold:
1. The transaction is an `Invoke` with `nonce == 1`.
2. The on-chain account nonce is `0` (account not yet deployed).
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

**The guard that is supposed to prove a deploy-account exists:** [2](#0-1) 

`account_tx_in_pool_or_recent_block` returns `true` if the account has **any** transaction in the pool (`tx_pool.contains_account`) or in the committed-nonce state (`state.contains_account`). It does not filter by transaction type. The inline comment in `skip_stateful_validations` acknowledges this:

> *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

The reasoning is circular: the attacker's own nonce-1 invoke transaction is the one that triggers the skip, so it never "passed validations." The comment's second branch ("transactions with future nonces that passed validations") is only true for transactions that went through the full `__validate__` path — but a nonce-1 invoke submitted while a deploy-account is pending is **itself** the transaction being evaluated, and it skips that path.

**No signature check exists at the stateless layer:** [3](#0-2) 

`StatelessTransactionValidator::validate` checks address range, empty fields, resource bounds, calldata/signature size, DA modes, and Sierra version. It performs **no cryptographic signature verification**.

**`validate_by_mempool` only checks fee/nonce, not signature:** [4](#0-3) [5](#0-4) 

`Mempool::validate_tx` calls `validate_incoming_tx` (duplicate hash + nonce range) and `validate_fee_escalation` (tip/gas-price bump). Neither checks the transaction signature.

**The full gateway admission path:** [6](#0-5) 

`extract_state_nonce_and_run_validations` calls `run_pre_validation_checks` (which calls `validate_by_mempool` then `skip_stateful_validations`) and then `run_validate_entry_point`. When `skip_validate = true`, `execution_flags.validate` is set to `false`: [7](#0-6) 

The blockifier's `StatefulValidator::perform_validations` then short-circuits before calling `__validate__`: [8](#0-7) 

**Attack sequence:**

1. Victim broadcasts `deploy_account` for address A (nonce=0). It enters the mempool.
2. Attacker observes the mempool and immediately broadcasts `invoke(sender=A, nonce=1, calldata=<anything>, signature=<garbage>)` with resource bounds ≥ the minimum.
3. Gateway stateless validation passes (no signature check).
4. `validate_by_mempool` passes: no existing nonce-1 tx for A, so `validate_fee_escalation` returns `Ok(None)`.
5. `skip_stateful_validations`: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block(A)` = `true` (deploy-account is in pool) → returns `true`.
6. `run_validate_entry_point` is called with `skip_validate=true` → `__validate__` is never invoked.
7. The attacker's transaction is forwarded to the mempool via `add_tx`.

The attacker's transaction now occupies the (A, nonce=1) slot. The victim's legitimate invoke transaction is subsequently rejected with `DuplicateNonce` (or requires a fee-escalation bump to displace the attacker's entry).

When the batcher eventually executes the attacker's transaction, `__validate__` runs with `validate=true` (the batcher does not inherit the gateway's skip flag), the invalid signature causes a validation failure, and the transaction is rejected from the block. The victim's deploy-account succeeds but their first invoke is lost from the mempool.

---

### Impact Explanation

**Impact: High — Mempool/gateway admission accepts an invalid transaction before sequencing.**

The gateway admits an invoke transaction whose signature has never been verified. The broken invariant is: *every transaction in the mempool for an undeployed account at nonce=1 must have passed `__validate__` or be the account's own deploy-account.* An attacker with no relationship to address A can insert an unauthenticated transaction into the (A, nonce=1) slot, blocking the legitimate owner's first post-deploy invoke and forcing a resubmission race.

---

### Likelihood Explanation

The attack requires only:
- Observing the public mempool for deploy-account transactions (trivially available via the gateway API or P2P gossip).
- Submitting a well-formed invoke transaction with nonce=1 and any signature before the victim's invoke arrives.
- No privileged access, no special account, no on-chain funds beyond the minimum resource-bounds fee.

The window is the time between the deploy-account entering the mempool and the victim's invoke being submitted — a window that is explicitly created by the UX feature itself (users are encouraged to send both transactions together, meaning the deploy-account will always precede the invoke in the mempool for a brief period).

---

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check with a check that specifically confirms a **deploy-account** transaction is present for the address. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type stored in `tx_pool`, rather than merely checking address presence.

Alternatively, the gateway can require the caller to supply the deploy-account transaction hash (as the legacy `PyValidator::should_run_stateful_validations` does via `deploy_account_tx_hash: Option<TransactionHash>`): [9](#0-8) 

The legacy path explicitly checks `deploy_account_tx_hash.is_some()` — a caller-supplied value that binds the skip to a specific deploy-account hash. The new gateway path dropped this binding and replaced it with the weaker pool-presence check, introducing the vulnerability.

---

### Proof of Concept

```
# Step 1 – victim submits deploy_account for address A (nonce=0)
POST /gateway/add_transaction
{ "type": "DEPLOY_ACCOUNT", "sender_address": A, "nonce": "0x0", ... valid sig ... }
# → accepted; A now appears in mempool

# Step 2 – attacker submits invoke for address A (nonce=1, garbage signature)
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": A,
  "nonce": "0x1",
  "calldata": ["0xdeadbeef"],
  "signature": ["0x1234", "0x5678"],   # invalid
  "resource_bounds": { "l2_gas": { "max_amount": "0x1000", "max_price_per_unit": "0x1" } }
}
# Gateway path:
#   stateless_tx_validator.validate()  → OK (no sig check)
#   validate_by_mempool()              → OK (no nonce-1 tx exists yet)
#   skip_stateful_validations()        → account_tx_in_pool_or_recent_block(A) = true
#                                        → returns true (skip __validate__)
#   run_validate_entry_point(skip=true)→ __validate__ NOT called
# → HTTP 200, tx_hash = H_attacker

# Step 3 – victim submits invoke for address A (nonce=1, valid sig)
POST /gateway/add_transaction { ..., "nonce": "0x1", ... valid sig ... }
# → MempoolError::DuplicateNonce  (attacker already holds the slot)
#   or requires fee escalation bump to displace attacker's entry

# Step 4 – batcher picks up attacker's tx, runs __validate__ with validate=true
# → __validate__ fails (invalid signature) → tx rejected from block
# Victim's deploy_account committed; victim's invoke lost from mempool.
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
