### Title
`skip_stateful_validations` admits invoke transactions with invalid signatures when any mempool entry exists for the sender — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's UX feature for the `deploy_account + invoke` flow skips `__validate__` (signature verification) for an invoke transaction with nonce=1 whenever `account_tx_in_pool_or_recent_block` returns `true` for the sender. That helper returns `true` for **any** transaction in the pool for the address — not specifically a `deploy_account` transaction. An attacker can therefore submit a `deploy_account` transaction for an arbitrary address, then immediately submit an invoke transaction with nonce=1 carrying an invalid or empty signature. The gateway admits the invoke transaction to the mempool without running `__validate__`, violating the admission invariant.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` implements the deploy-account UX bypass:

```rust
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                // ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: !skip_validate = false`, so `__validate__` is never called at the gateway:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The guard condition relies on `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction in the pool for the address:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

The code comment claims this is sufficient because the pool entry is "either a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is circular: a `deploy_account` transaction in the pool does **not** prove that the subsequent invoke transaction carries a valid signature. The check does not distinguish between a `deploy_account` entry (which proves nothing about invoke signatures) and an invoke entry with nonce=0 (which does prove the sender controls the account, because it passed `__validate__`).

The mempool's own `validate_tx` performs no signature check — it only checks for duplicate hashes and nonce ordering:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [4](#0-3) 

So once `skip_validate=true` is returned by the gateway, the invoke transaction is admitted to the mempool with no signature check at any layer before sequencing.

---

### Impact Explanation

An attacker can admit an invoke transaction carrying an arbitrary (invalid or empty) signature to the mempool for any address, bypassing the gateway's `__validate__` entry-point check. This matches the impact category:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

During actual block execution the blockifier always constructs transactions with `validate: true` via `AccountTransaction::new_for_sequencing`:

```rust
pub fn new_for_sequencing(tx: Transaction) -> Self {
    let execution_flags = ExecutionFlags {
        only_query: false,
        charge_fee: enforce_fee(&tx, false),
        validate: true,
        strict_nonce_check: true,
    };
    ...
}
``` [5](#0-4) 

So the invalid invoke transaction will fail at `__validate__` during execution and be rejected. However, it has already been admitted to the mempool, occupying pool capacity and forcing the batcher to process and discard it. An attacker who creates many accounts (different salts, same class hash) can flood the mempool with signature-less invoke transactions at the cost of only the `deploy_account` transaction fees.

---

### Likelihood Explanation

The attack requires no privileged access and no knowledge of any private key. Any external actor can:

1. Choose an arbitrary class hash (e.g., a publicly known account class) and a random salt.
2. Compute the resulting contract address deterministically.
3. Submit a `deploy_account` transaction for that address — this passes all gateway checks and enters the pool.
4. Immediately submit an invoke transaction with nonce=1 for the same address, carrying an empty or garbage signature.

Step 4 passes because `tx_pool.contains_account(address)` is now `true` (from step 3), satisfying the skip condition. The gateway never calls `__validate__`. The invoke transaction is forwarded to the mempool.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists in the pool for the sender address. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, rather than returning `true` for any pooled transaction. Alternatively, the gateway can inspect the transaction type of the pooled entry before deciding to skip `__validate__`.

The analogous fix in the external report was adding `onlyNewEpoch` to `poke`; here the fix is narrowing the skip condition from "any tx in pool" to "deploy_account tx in pool."

---

### Proof of Concept

**Step-by-step (no code execution required — follows directly from the production logic):**

1. Attacker picks `class_hash = <any known account class>`, `salt = <random>`.
2. Attacker computes `address_A = pedersen(deployer=0, salt, class_hash, constructor_calldata, CONTRACT_ADDRESS_PREFIX)`.
3. Attacker submits `RpcTransaction::DeployAccount` for `address_A`. Gateway `validate_nonce` accepts it (account nonce = 0, tx nonce = 0). `run_validate_entry_point` runs `__validate_deploy__` — this succeeds because the account does not yet exist (constructor runs). The transaction enters the mempool. Now `tx_pool.contains_account(address_A) == true`.
4. Attacker submits `RpcTransaction::Invoke` with `sender_address = address_A`, `nonce = 1`, `signature = []` (empty).
   - `validate_nonce`: `account_nonce(0) <= tx_nonce(1) <= max_allowed_nonce_gap` → passes.
   - `validate_by_mempool`: no duplicate hash, nonce ordering OK → passes.
   - `skip_stateful_validations`: `tx.nonce() == 1 && account_nonce == 0 && account_tx_in_pool_or_recent_block(address_A) == true` → returns `true`.
   - `run_validate_entry_point` is called with `skip_validate = true` → `execution_flags.validate = false` → `__validate__` is **never called**.
   - The invoke transaction is forwarded to the mempool with no signature check. [6](#0-5) 

5. The mempool now holds an invoke transaction with an invalid signature. When the batcher calls `get_txs` and the blockifier executes it with `validate: true`, `__validate__` fails, the transaction is rejected, and the mempool is notified. No fee is charged to the attacker for the failed invoke. The attacker repeats with a new salt to generate a new address, flooding the mempool.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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
