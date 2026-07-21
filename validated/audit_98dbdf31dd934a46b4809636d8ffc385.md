### Title
`skip_stateful_validations` Bypasses Signature Verification via Non-Deploy-Account Seed Transaction — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` is intended to skip the `__validate__` entry-point check for a nonce-1 invoke when a `deploy_account` is pending in the mempool (UX feature for simultaneous deploy+invoke). The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction from that address, not only a `deploy_account`. An attacker who first seeds the mempool with a valid nonce-0 invoke can then submit a nonce-1 invoke with an invalid or absent signature; the gateway skips `__validate__` and admits the unsigned transaction to the mempool.

### Finding Description

In `skip_stateful_validations` the skip condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

This returns `true` whenever **any** transaction from the address is present — including a plain invoke with nonce 0. The comment in the code claims this is sufficient because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but that reasoning is incorrect: a nonce-0 invoke passes all gateway validations without being a `deploy_account`.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside the blockifier, `validate_tx` then returns `Ok(None)` immediately without executing `__validate__`:

```rust
if !self.execution_flags.validate {
    return Ok(None);
}
``` [4](#0-3) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering and duplicate detection — it does not verify the cryptographic signature: [5](#0-4) 

**Attack steps:**

1. Attacker controls fresh address `A` (account nonce = 0, no contract deployed).
2. Attacker submits `Invoke(sender=A, nonce=0, valid_signature)` → passes all gateway checks, enters mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker submits `Invoke(sender=A, nonce=1, invalid_or_empty_signature)` → `skip_stateful_validations` fires, `__validate__` is skipped, transaction is admitted to the mempool without signature verification.

The `max_nonce_for_validation_skip` config field exists in `StatefulTransactionValidatorConfig` but is **not used** in the production `skip_stateful_validations` function (it is only used in the Python-bindings path `PyValidator::should_run_stateful_validations`): [6](#0-5) [7](#0-6) 

### Impact Explanation

The gateway's admission invariant — that every transaction entering the mempool has passed `__validate__` (signature verification) or is provably exempt — is broken. An attacker can flood the mempool with nonce-1 invoke transactions bearing invalid signatures. These transactions will fail during batcher execution (since `new_for_sequencing` re-enables `validate: true`), but they consume mempool capacity, batcher execution slots, and sequencer resources without paying fees, constituting a targeted DoS against the sequencer.

This matches the **High** impact category: *Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

### Likelihood Explanation

The attack requires only two sequential RPC calls with no privileged access, no front-running, and no special contract. Any unprivileged actor who can call `add_tx` can execute it. The only constraint is that the target address must have account nonce 0 (undeployed), which the attacker trivially satisfies by choosing a fresh address they control.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is pending for the address. The mempool should expose a dedicated `deploy_account_in_pool(address)` query, or the transaction type of the pooled transaction should be inspected. Alternatively, restrict the skip to cases where the mempool contains a transaction of type `DeployAccount` for the sender address, mirroring the intent described in the code comment.

### Proof of Concept

```
// Step 1: seed the mempool with a valid nonce-0 invoke from fresh address A
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": A,
  "nonce": "0x0",
  "signature": [<valid_sig>],
  "resource_bounds": { "l2_gas": { "max_amount": "0x1", "max_price_per_unit": "0x1" } },
  ...
}
// → accepted; account_tx_in_pool_or_recent_block(A) == true

// Step 2: submit nonce-1 invoke with invalid signature
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": A,
  "nonce": "0x1",
  "signature": [],          // empty / invalid
  "resource_bounds": { "l2_gas": { "max_amount": "0x1", "max_price_per_unit": "0x1" } },
  ...
}
// → skip_stateful_validations returns true → __validate__ skipped → admitted to mempool
// → batcher later executes it with validate:true → fails, but mempool slot was consumed
``` [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-283)
```rust
    pub max_nonce_for_validation_skip: Nonce,
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-118)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
