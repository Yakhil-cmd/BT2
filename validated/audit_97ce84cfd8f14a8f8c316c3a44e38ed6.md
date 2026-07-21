### Title
Permissionless Signature-Skip Allows Attacker to Inject Unsigned Invoke at Nonce 1 for Any Deploying Account - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point (and therefore signature verification) for any invoke transaction with `nonce=1` when the on-chain account nonce is `0`, provided `account_tx_in_pool_or_recent_block` returns `true`. That check returns `true` for **any** transaction type in the pool for the target address — not exclusively a `deploy_account`. An unprivileged attacker who observes a victim's `deploy_account` entering the mempool can immediately submit an invoke with `nonce=1` for the victim's address carrying an arbitrary/fake signature. The gateway admits it without running `__validate__`, occupying the victim's `nonce=1` slot and causing the victim's legitimate first invoke to be rejected as a duplicate nonce.

### Finding Description

`skip_stateful_validations` is the UX feature that lets a user submit `deploy_account` + `invoke(nonce=1)` simultaneously without waiting for the deploy to be mined: [1](#0-0) 

The guard condition is:

```
tx.nonce() == Nonce(Felt::ONE)  &&  account_nonce == Nonce(Felt::ZERO)
```

When both hold, the function calls `account_tx_in_pool_or_recent_block(sender_address)`: [2](#0-1) 

That helper returns `true` if **any** transaction for the address is in the pool or in the mempool's committed-nonce state: [3](#0-2) 

When it returns `true`, `skip_stateful_validations` returns `true` (meaning "skip validation"), and `run_validate_entry_point` is called with `validate: false`: [4](#0-3) 

The `__validate__` entry point — which is the only place the account contract verifies the caller's signature — is therefore **never executed** for this transaction.

The code comment acknowledges the assumption but states it incorrectly: [5](#0-4) 

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."

The second branch is circular: a future-nonce transaction could itself have been admitted via this same skip path, meaning it never passed signature validation either.

**Attack steps:**

1. Victim broadcasts `deploy_account` for address `A` (nonce=0). It enters the mempool; `tx_pool.contains_account(A)` becomes `true`.
2. Attacker observes this and immediately submits `Invoke { sender_address: A, nonce: 1, calldata: <anything>, signature: <garbage> }`.
3. Gateway stateful path:
   - `validate_nonce`: `0 ≤ 1 ≤ 200` → passes. [6](#0-5) 
   - `validate_by_mempool`: no duplicate hash, nonce not too old → passes. [7](#0-6) 
   - `skip_stateful_validations`: `account_tx_in_pool_or_recent_block(A)` → `true` → returns `true`. [8](#0-7) 
   - `run_validate_entry_point(skip_validate=true)`: `__validate__` is **skipped**. Garbage signature is never checked.
4. Attacker's unsigned invoke is admitted to the mempool at `(A, nonce=1)`.
5. Victim submits their legitimate `Invoke { sender_address: A, nonce: 1, ... }`. The mempool rejects it: `DuplicateNonce` (or requires fee escalation ≥10% to replace).

### Impact Explanation

The gateway accepts an invalid transaction — one whose signature has never been verified — into the mempool. This directly satisfies the allowed impact:

> **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

The victim's first invoke after account deployment is either blocked entirely or forced through a fee-escalation race against an attacker who pays zero fees (the attacker's transaction will revert on execution, but it occupies the slot in the meantime). The attacker can repeat this indefinitely at minimal cost.

### Likelihood Explanation

- The mempool is observable (P2P gossip, RPC `get_pending_transactions`).
- The attack window opens the moment a `deploy_account` enters the mempool and closes when the victim's own `invoke(nonce=1)` is admitted. In practice users often submit these in separate RPC calls.
- No privileged access, no special funds, and no cryptographic capability are required. Any node participant can execute this.

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that is specific to `deploy_account` transactions. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool_or_recent_block(address)` that only returns `true` when a `DeployAccount` transaction for that exact address is present. This mirrors the fix in the referenced Strata report: the permissioned path must be narrowed so that only the legitimate owner's own deploy-account transaction can unlock the validation skip.

Alternatively, record the `deploy_account` transaction hash at submission time and require the invoke to reference it explicitly (as the `native_blockifier` path already does via `deploy_account_tx_hash`): [9](#0-8) 

The `PyValidator::should_run_stateful_validations` implementation requires an explicit `deploy_account_tx_hash` parameter and checks `deploy_account_tx_hash.is_some()` — a stricter guard that the gateway path should adopt.

### Proof of Concept

```
# 1. Victim submits deploy_account for address A.
POST /gateway/add_transaction
{ "type": "DEPLOY_ACCOUNT", "sender_address": "0xA", "nonce": "0x0", ... valid sig ... }

# 2. Attacker observes A in mempool, submits fake invoke.
POST /gateway/add_transaction
{
  "type": "INVOKE",
  "sender_address": "0xA",
  "nonce": "0x1",
  "calldata": ["0xdead"],
  "signature": ["0xbad", "0xbad"],   # garbage — never verified
  "resource_bounds": { ... min valid ... }
}
# → HTTP 200, transaction accepted

# 3. Victim submits legitimate invoke.
POST /gateway/add_transaction
{ "type": "INVOKE", "sender_address": "0xA", "nonce": "0x1", ... valid sig ... }
# → Error: DuplicateNonce  (or requires ≥10% fee escalation to displace attacker's tx)
```

The root cause is in `skip_stateful_validations` at: [1](#0-0) 

using the overly broad check: [2](#0-1)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L307-312)
```rust
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L414-424)
```rust
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
