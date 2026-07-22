### Title
Gateway `skip_stateful_validations` Admits Unsigned Invoke Transactions for Any Address with a Pending Deploy-Account — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the Apollo gateway stateful validator skips the `__validate__` entry-point call (i.e., signature verification) for any Invoke transaction with `nonce=1` sent to an address whose on-chain nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true` for that address. Because `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction type in the pool — not exclusively a `DeployAccount` — an unprivileged attacker who observes a victim's pending `DeployAccount` in the mempool can immediately submit a crafted Invoke with `nonce=1` for the victim's address, carrying an arbitrary signature and arbitrary calldata, and have it admitted to the mempool without any signature check.

---

### Finding Description

**Vulnerable function:**

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When this returns `true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, which causes `StatefulValidator::perform_validations` to return `Ok(())` immediately without calling `__validate__`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs
ApiTransaction::Invoke(_) => {
    tx.perform_pre_validation_stage(self.state(), &tx_context)?;
    if !tx.execution_flags.validate {
        return Ok(());   // ← signature never checked
    }
    let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
    ...
}
``` [2](#0-1) 

The predicate that gates this bypass is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [3](#0-2) 

This returns `true` for **any** transaction type (Invoke, Declare, DeployAccount) already in the pool for that address. The code comment claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this reasoning does not hold against an external observer.

**Attack path:**

1. Alice broadcasts `DeployAccount` (nonce=0) for address `A`. The transaction enters the mempool and `account_tx_in_pool_or_recent_block(A)` now returns `true`.
2. Attacker Bob observes Alice's `DeployAccount` in the public mempool.
3. Bob constructs an `Invoke` transaction for address `A` with `nonce=1`, arbitrary `calldata`, and a garbage `signature`.
4. Bob submits it to the gateway. The gateway's stateful validator:
   - Reads on-chain nonce for `A` → `0` ✓
   - Checks `tx.nonce() == 1` ✓
   - Calls `account_tx_in_pool_or_recent_block(A)` → `true` (Alice's DeployAccount is there) ✓
   - Sets `skip_validate = true`, skips `__validate__` entirely.
5. Bob's transaction is admitted to the mempool without any signature verification. [4](#0-3) 

---

### Impact Explanation

**Admission invariant broken:** The gateway accepts an Invoke transaction whose signature has never been verified. This directly matches the allowed impact: *"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concrete consequences:

- **Mempool pollution / DoS:** Bob can submit many such transactions for any address that has a pending `DeployAccount`, filling the mempool with transactions that will fail at batcher execution time.
- **Transaction displacement:** If the mempool supports fee escalation (replacing a pending transaction at the same nonce with a higher-tip one), Bob can replace Alice's legitimate `nonce=1` Invoke with his own. Bob's transaction will fail `__validate__` at execution time (the batcher uses `validate: true` via `new_for_sequencing`), but Alice's transaction is gone from the mempool and will not execute in that block.
- **Batcher resource waste:** The batcher must execute and revert Bob's transaction, consuming block resources. [5](#0-4) 

---

### Likelihood Explanation

- **Unprivileged trigger:** Any external user can submit an RPC transaction to the gateway. No special role or key is required.
- **Observable precondition:** The `DeployAccount` transaction is visible in the public mempool as soon as it is submitted.
- **Low cost:** The attacker only needs to craft a single Invoke transaction with a garbage signature and submit it via the standard `add_tx` RPC endpoint.
- **Narrow but real window:** The window exists from the moment the victim's `DeployAccount` enters the mempool until it is committed to a block. For the deploy+invoke UX pattern this window is intentionally kept open.

---

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`DeployAccount` transaction** is pending for the sender address. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool` that only returns `true` when the pending transaction for that address is of type `DeployAccount`. This preserves the intended UX while closing the admission bypass.

Alternatively, restrict the skip condition to require that the `DeployAccount` transaction hash is explicitly provided by the submitter (as the `native_blockifier` `PyValidator` already does via the `deploy_account_tx_hash` parameter), and verify that hash is present in the mempool before skipping validation. [6](#0-5) 

---

### Proof of Concept

```
1. Alice submits DeployAccount for address 0xALICE (nonce=0, valid signature).
   → Mempool accepts it. account_tx_in_pool_or_recent_block(0xALICE) == true.

2. Bob submits Invoke for sender_address=0xALICE, nonce=1,
   calldata=[transfer all tokens to Bob], signature=[0xDEAD, 0xBEEF].

3. Gateway stateful validator:
   - get_nonce_from_state(0xALICE) → Nonce(0)          ✓ account_nonce == 0
   - tx.nonce() == Nonce(1)                              ✓
   - account_tx_in_pool_or_recent_block(0xALICE) → true ✓
   → skip_validate = true
   → run_validate_entry_point called with validate=false
   → StatefulValidator::perform_validations returns Ok(()) without __validate__

4. Bob's transaction is added to the mempool.
   If Bob's tip > Alice's tip, Bob's Invoke replaces Alice's Invoke at nonce=1.

5. Batcher executes block:
   - Alice's DeployAccount (nonce=0) executes successfully.
   - Bob's Invoke (nonce=1) runs __validate__ → signature invalid → reverted.
   - Alice's original Invoke is no longer in the mempool.
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
