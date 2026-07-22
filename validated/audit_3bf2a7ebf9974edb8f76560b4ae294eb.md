### Title
`skip_stateful_validations` Bypasses Signature Validation for Undeployed Accounts, Enabling Zero-Cost Mempool Displacement - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function grants a signature-validation bypass to **any** invoke transaction with nonce=1 targeting an address that has *any* pending transaction in the mempool, without verifying that the bypass requester is the same entity that submitted the deploy_account. An attacker can exploit Alice's pending deploy_account to inject an invoke with an arbitrary invalid signature into the mempool, and—via fee escalation—displace Alice's legitimate invoke at zero cost.

---

### Finding Description

The gateway's stateful validation path in `extract_state_nonce_and_run_validations` calls `skip_stateful_validations` to decide whether to skip the `__validate__` entry-point call:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       └─ skip_stateful_validations   ← returns true → validate: false
  └─ run_validate_entry_point(skip_validate=true)
       └─ ExecutionFlags { validate: !skip_validate }  ← __validate__ never called
``` [1](#0-0) 

The bypass condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
``` [2](#0-1) 

`account_tx_in_pool_or_recent_block` returns `true` if **any** transaction from that address is in the pool or a recent block — it does not check that the transaction is specifically a `deploy_account`:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

When `skip_validate = true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so the blockifier's `StatefulValidator::perform_validations` returns `Ok(())` immediately for invoke transactions without ever calling `__validate__`: [4](#0-3) [5](#0-4) 

The mempool's `validate_tx` (called via `validate_by_mempool`) only checks nonce validity and fee escalation — it never inspects the signature: [6](#0-5) 

The `ValidationArgs` struct passed to the mempool contains no signature field: [7](#0-6) 

**Attack sequence:**

1. Alice submits `deploy_account` for address X (nonce=0). It enters the mempool.
2. Alice also submits a legitimate `invoke` (nonce=1, tip=T) for address X.
3. Eve observes Alice's `deploy_account` in the mempool.
4. Eve submits `invoke(sender_address=X, nonce=1, tip=T+Δ, signature=<garbage>)`.
5. Gateway: `nonce==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(X)==true` → `skip_validate=true` → `__validate__` is never called.
6. Mempool fee-escalation: Eve's higher tip replaces Alice's legitimate invoke. [8](#0-7) 

7. Batcher executes: Alice's `deploy_account` succeeds; Eve's invoke reaches `__validate__` → fails → `ValidateTransactionError` → transaction rejected, nonce not incremented.
8. Alice's invoke is gone from the mempool; she must resubmit.

Because `__validate__` failure charges no fee, Eve can repeat this at zero cost.

---

### Impact Explanation

The gateway/mempool admits an invoke transaction with an invalid (attacker-controlled) signature for an undeployed account, satisfying the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concretely:
- Alice's legitimate nonce=1 invoke is permanently displaced from the mempool by Eve's invalid invoke via fee escalation.
- Eve pays nothing (no fee charged on `__validate__` failure).
- The attack can be repeated indefinitely, preventing Alice from ever having her first post-deploy invoke sequenced without manual intervention.
- Any account in the deploy_account + invoke UX flow is a target.

---

### Likelihood Explanation

- The mempool is observable by any network participant (transactions are broadcast).
- The attack requires only submitting a standard invoke RPC call with a higher tip — no privileged access, no special tooling.
- The `skip_stateful_validations` feature is always active (no configuration flag disables it).
- Fee escalation is enabled by default (`enable_fee_escalation: true`). [9](#0-8) 

---

### Recommendation

The bypass must be bound to the specific entity that submitted the deploy_account, mirroring the ENS fix of including `owner` in the commitment. Two options:

**Option A (preferred):** When `skip_stateful_validations` is triggered, fetch the pending deploy_account from the mempool for address X and verify that the invoke's `class_hash` and `constructor_calldata` are consistent with the expected account class — or at minimum verify the invoke's signature against the class hash declared in the pending deploy_account before skipping `__validate__`.

**Option B:** Store the `tx_hash` of the deploy_account alongside the account state in the mempool, and require the invoke to include a reference (e.g., a field in `account_deployment_data`) that matches it, so the bypass is non-transferable.

At minimum, `account_tx_in_pool_or_recent_block` should be replaced with a stricter check that confirms the pending transaction for address X is specifically a `deploy_account` transaction type, not just any transaction.

---

### Proof of Concept

```
# State: Alice's deploy_account for address X is in the mempool.
# Alice also submitted invoke(nonce=1, tip=100, valid_sig).

# Eve submits:
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "<Alice's address X>",
  "nonce": "0x1",
  "calldata": ["0xdeadbeef"],          # arbitrary
  "signature": ["0x1337", "0x1337"],   # invalid
  "tip": "0x200",                       # > Alice's tip of 100
  "resource_bounds": { ... }
}

# Gateway path:
# 1. stateless_tx_validator.validate() → passes (signature length OK)
# 2. convert_rpc_tx_to_internal() → tx_hash computed (includes sender_address, nonce, calldata)
# 3. extract_state_nonce_and_run_validations():
#    - account_nonce = 0  (X not deployed)
#    - skip_stateful_validations: nonce==1 && account_nonce==0 && pool_has_X==true → skip=true
#    - run_validate_entry_point(skip=true) → ExecutionFlags{validate:false} → returns Ok(())
# 4. mempool.add_tx() → fee escalation replaces Alice's invoke with Eve's

# Result: Alice's invoke is gone. Eve's invalid invoke is in the mempool.
# Batcher: deploy_account executes, Eve's invoke hits __validate__ → ValidateTransactionError → rejected.
# Alice must resubmit. Eve repeats at zero cost.
``` [10](#0-9) [11](#0-10)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-410)
```rust
    async fn run_pre_validation_checks(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<bool> {
        self.validate_state_preconditions(executable_tx, account_nonce).await?;
        validate_by_mempool(executable_tx, account_nonce, mempool_client.clone()).await?;
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L49-57)
```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```

**File:** crates/apollo_node/resources/config_schema.json (L3477-3480)
```json
  "mempool_config.static_config.enable_fee_escalation": {
    "description": "If true, transactions can be replaced with higher fee transactions.",
    "privacy": "Public",
    "value": true
```
