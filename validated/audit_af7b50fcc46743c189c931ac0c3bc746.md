### Title
Gateway Admits Signature-Unvalidated Invoke (nonce=1) for Any Account With a Pending Pool Entry — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` skips the `__validate__` entry-point call (the only signature check at the gateway level) for any Invoke transaction whose nonce is `1` and whose sender address appears in `account_tx_in_pool_or_recent_block`. Because that helper returns `true` for **any** transaction type in the pool — not exclusively a `DeployAccount` — an unprivileged attacker who observes a victim's `DeployAccount` in the mempool can immediately submit a crafted Invoke with nonce `1`, an arbitrary/invalid signature, and the victim's sender address. The gateway admits it without ever calling `__validate__`, so the mempool receives a signature-unvalidated transaction.

---

### Finding Description

**Relevant code path**

`extract_state_nonce_and_run_validations` → `run_pre_validation_checks` → `skip_stateful_validations` → `run_validate_entry_point(skip_validate=true)`. [1](#0-0) 

The guard condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
``` [2](#0-1) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

`state.contains_account` checks both `staged` and `committed` maps — it is **not** filtered to `DeployAccount` transactions: [4](#0-3) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`, which causes `StatefulValidator::perform_validations` to return `Ok(())` immediately without calling `__validate__`: [5](#0-4) [6](#0-5) 

The code comment itself acknowledges the broader-than-intended check:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**." [7](#0-6) 

The second branch ("future nonces that passed validations") is impossible for an account with on-chain nonce `0` — no Invoke for an undeployed account can pass `__validate__` because the contract does not exist. The only realistic pool entry for such an account is a `DeployAccount`. The check therefore conflates "account has a DeployAccount in the pool" with "account has any transaction in the pool," and the latter is exploitable.

---

### Impact Explanation

An attacker who observes a victim's `DeployAccount` transaction in the mempool (all mempool contents are observable via P2P propagation) can:

1. Craft an `InvokeV3` with `sender_address = victim_address`, `nonce = 1`, and an arbitrary/invalid signature.
2. Submit it to the gateway. Stateless checks (signature *length*, calldata size, DA modes) pass. Stateful nonce check passes (`0 ≤ 1 ≤ 200`). `validate_by_mempool` passes (no duplicate hash, nonce not too old). `skip_stateful_validations` returns `true` because the victim's `DeployAccount` is in the pool.
3. `run_validate_entry_point` is called with `validate=false`; `__validate__` is never invoked.
4. The gateway calls `mempool_client.add_tx`; the mempool accepts the transaction.

The mempool now holds a signature-unvalidated Invoke at `(victim_address, nonce=1)`. When the victim subsequently submits their legitimate Invoke at the same `(address, nonce)`, the mempool either rejects it as a duplicate nonce or requires the victim to pay a fee-escalation premium (≥10 % higher tip/gas price) to displace the attacker's entry. [8](#0-7) 

The attacker's transaction will eventually fail during blockifier execution (account not yet deployed, or `__validate__` reverts), but by then the victim's legitimate first post-deploy Invoke has been blocked or delayed.

---

### Likelihood Explanation

- All mempool transactions are propagated over P2P, so an attacker can observe any `DeployAccount` in near-real time.
- The attack requires only a single valid-looking `InvokeV3` RPC call with the victim's address, nonce `1`, and any bytes as the signature (subject only to the stateless length limit of 4 000 felts).
- No privileged access, no special account, no prior on-chain state is required.
- The production `transaction_ttl` is 300 seconds, giving a 5-minute window per victim `DeployAccount`. [9](#0-8) 

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `DeployAccount` transaction is present in the pool for the sender address. For example, expose a `deploy_account_in_pool(address) -> bool` query on the mempool that inspects transaction types, and use that in `skip_stateful_validations`. Alternatively, store the deploy-account tx hash alongside the pool entry and require the caller to supply it (as the `native_blockifier` path already does via `deploy_account_tx_hash: Option<TransactionHash>`). [10](#0-9) 

---

### Proof of Concept

```
# Precondition: victim has submitted DeployAccount for address A (nonce=0 on-chain).
# A is now visible in the mempool via P2P.

POST /gateway/add_transaction
{
  "type": "INVOKE",
  "version": "0x3",
  "sender_address": "<A>",          # victim's address
  "nonce": "0x1",
  "calldata": [],
  "signature": ["0xdead", "0xbeef"], # arbitrary invalid signature
  "resource_bounds": { ... valid bounds ... },
  "tip": "0x0",
  "nonce_data_availability_mode": "L1",
  "fee_data_availability_mode": "L1",
  "account_deployment_data": [],
  "paymaster_data": []
}

# Expected (correct) behaviour: rejected with ValidateFailure.
# Actual behaviour:
#   skip_stateful_validations returns true  (A is in pool via DeployAccount)
#   __validate__ is never called
#   transaction is admitted to the mempool at (A, nonce=1)
#   victim's subsequent legitimate Invoke at (A, nonce=1) is rejected as DuplicateNonce
#   or must pay ≥10% fee escalation to displace the attacker's entry.
``` [1](#0-0) [11](#0-10)

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool_config/src/config.rs (L63-67)
```rust
    pub enable_fee_escalation: bool,
    // Percentage increase for tip and max gas price to enable transaction replacement.
    #[validate(range(min = 1, max = 100))]
    pub fee_escalation_percentage: u8, // E.g., 10 for a 10% increase.
    // If true, only transactions with max L2 gas price per unit bound that are above the threshold
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
