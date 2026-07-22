### Title
Signature Bypass via `skip_stateful_validations` Allows Unauthorized Invoke Transactions to Enter Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry point — the sole on-chain signature check — for any Invoke transaction with nonce 1 whose `sender_address` already appears in the mempool or a recent block. Because the check is on the *address* rather than on the *submitter's identity*, an unprivileged attacker can craft an Invoke transaction that names a victim's address as `sender_address`, attach an arbitrary (invalid) signature, and have it admitted to the mempool without any signature verification. The victim's own legitimate nonce-1 Invoke is then blocked by a `DuplicateNonce` error or forced into fee escalation.

---

### Finding Description

**Root cause — `skip_stateful_validations`**

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
```

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())   // ← any tx for address
                .await
                ...;
        }
    }
    Ok(false)
}
```

When this function returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```
crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 311-312
```

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

Inside `StatefulValidator::perform_validations` the `__validate__` call is then skipped entirely:

```
crates/blockifier/src/blockifier/stateful_validator.rs  lines 79-81
```

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
```

**The broken invariant**

`account_tx_in_pool_or_recent_block` returns `true` whenever *any* transaction for the address is present — not specifically a `deploy_account` submitted by the account owner:

```
crates/apollo_mempool/src/mempool.rs  lines 697-700
```

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

**Attack path**

1. Victim submits a `deploy_account` for address `V`. The mempool now contains `V`, so `account_tx_in_pool_or_recent_block(V)` returns `true`.
2. Attacker submits an `InvokeV3` with `sender_address = V`, `nonce = 1`, and an arbitrary (invalid) signature.
3. Gateway stateless validation passes (no signature check there).
4. `validate_nonce` passes: `account_nonce(0) ≤ 1 ≤ 0 + max_allowed_nonce_gap(200)`.
5. `validate_by_mempool` passes: no duplicate hash, nonce ≥ account nonce.
6. `skip_stateful_validations` returns `true` (all three conditions met).
7. `run_validate_entry_point` is called with `skip_validate = true` → `__validate__` is never executed → invalid signature is never checked.
8. The attacker's transaction is inserted into the mempool under address `V`, nonce 1.

**Consequence for the victim**

When the victim later submits their legitimate nonce-1 Invoke, `validate_fee_escalation` returns `MempoolError::DuplicateNonce` (fee escalation disabled) or demands a higher fee (fee escalation enabled):

```
crates/apollo_mempool/src/mempool.rs  lines 768-788
```

```rust
if !self.config.static_config.enable_fee_escalation {
    if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
        return Err(MempoolError::DuplicateNonce { address, nonce });
    };
    ...
}
...
if !self.should_replace_tx(&existing_tx_reference, &incoming_tx_reference) {
    return Err(MempoolError::DuplicateNonce { address, nonce });
}
```

The attacker's transaction will eventually be rejected by the batcher (blockifier runs `__validate__` during execution), but by then the victim's transaction has been blocked or forced to pay a higher fee.

---

### Impact Explanation

**Critical — Invalid or unauthorized Starknet transaction accepted through account validation / signature logic.**

An unprivileged attacker can inject a signature-less Invoke transaction into the mempool under any victim address that has a pending `deploy_account`. The gateway's admission invariant — *every accepted transaction must carry a valid signature from the account owner* — is violated. The victim's first post-deployment Invoke is denied or extorted into fee escalation. The attacker's cost is a single valid-fee transaction (the signature field is never checked).

---

### Likelihood Explanation

**High.** The precondition (victim's address visible in the mempool) is trivially observable via P2P gossip or the RPC. The attack window is the entire time the victim's `deploy_account` sits in the mempool before being committed. No privileged access, no special tooling, and no on-chain funds beyond the minimum fee are required.

---

### Recommendation

1. **Restrict the skip to deploy-account-specific evidence.** Instead of checking `account_tx_in_pool_or_recent_block` (which matches any transaction type), add a dedicated `deploy_account_in_pool(address)` query that returns `true` only when a `DeployAccount` transaction for that address is present. This closes the false-positive path that lets an attacker piggyback on the victim's deploy.

2. **Verify the submitter's identity before skipping.** Even with a deploy-account-specific check, consider whether the skip should require the incoming Invoke's transaction hash to be signed by the same key that signed the pending `deploy_account`. This would prevent a third party from injecting a nonce-1 Invoke for an address they do not control.

3. **Add a gateway-level per-address nonce-slot reservation.** Track which nonces are already occupied in the mempool during the gateway's stateful validation phase, so that a second submission for the same `(address, nonce)` is rejected before the skip logic is even reached.

---

### Proof of Concept

```rust
// Precondition: victim has submitted a deploy_account for address VICTIM_ADDR.
// The mempool now contains VICTIM_ADDR, so account_tx_in_pool_or_recent_block returns true.

// Step 1: attacker constructs an InvokeV3 with victim's address and nonce 1.
let attacker_tx = RpcTransaction::Invoke(RpcInvokeTransaction::V3(InvokeTransactionV3 {
    sender_address: VICTIM_ADDR,          // victim's address
    nonce: Nonce(Felt::ONE),              // nonce 1
    signature: TransactionSignature(vec![Felt::from(0xdeadbeefu64)].into()), // garbage
    // ... valid resource bounds, calldata, etc.
}));

// Step 2: attacker submits to the gateway.
// - StatelessTransactionValidator::validate passes (no signature check).
// - validate_nonce passes: 0 <= 1 <= 200.
// - validate_by_mempool passes: no duplicate hash, nonce >= 0.
// - skip_stateful_validations returns true:
//     tx is Invoke ✓, nonce == 1 ✓, account_nonce == 0 ✓,
//     account_tx_in_pool_or_recent_block(VICTIM_ADDR) == true ✓
// - run_validate_entry_point called with skip_validate=true → __validate__ NOT called.
// - Transaction admitted to mempool with VICTIM_ADDR, nonce 1, invalid signature.

// Step 3: victim submits their legitimate nonce-1 Invoke.
// - validate_fee_escalation finds existing tx at (VICTIM_ADDR, 1).
// - Returns MempoolError::DuplicateNonce → victim's tx rejected.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
