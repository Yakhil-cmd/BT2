### Title
Signature Validation Bypass via `skip_stateful_validations` Race on Undeployed Account — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's UX shortcut for the deploy-account + invoke flow unconditionally skips the `__validate__` entry-point for any Invoke V3 transaction whose nonce is `1` and whose sender address appears in the mempool, regardless of whether the mempool entry is a `DeployAccount` or any other transaction type. An unprivileged attacker who observes a legitimate `DeployAccount` in the mempool can immediately submit an Invoke with nonce `1` and an arbitrary/garbage signature for the same address. The gateway admits the Invoke without running `__validate__`, the transaction is included in a block, reverts (consuming fees from the victim's pre-funded balance), and increments the victim's nonce — blocking the victim's own first post-deploy Invoke.

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip `__validate__`) when all three conditions hold:

1. The transaction is `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)`.
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

Condition 4 is satisfied by **any** transaction for the sender address in the mempool — not specifically a `DeployAccount`. The comment in the code acknowledges this ambiguity: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* The second branch ("future nonces that passed validations") is circular: those future nonces passed validation precisely because they also triggered this same skip.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `validate: !skip_validate = false`: [2](#0-1) 

This means `StatefulValidator::validate` (which calls `tx.validate_tx(...)`) is never invoked for the Invoke transaction: [3](#0-2) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering — it does not verify signatures: [4](#0-3) 

The mempool's `account_tx_in_pool_or_recent_block` checks `state.contains_account` (committed/staged map) OR `tx_pool.contains_account` (pool map): [5](#0-4) 

Both maps are populated by any successfully admitted transaction for the address, not exclusively `DeployAccount` transactions.

**Attack path:**

1. Legitimate user submits `DeployAccount(nonce=0)` for address `A`. It passes `__validate_deploy__` and enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
2. Attacker submits `Invoke(nonce=1, sender=A, signature=<garbage>)`.
3. Gateway stateless validation passes (signature length check only, not cryptographic validity).
4. `validate_nonce` passes: `account_nonce=0 ≤ tx_nonce=1 ≤ 0 + max_allowed_nonce_gap`. [6](#0-5) 

5. `validate_by_mempool` passes: nonce `1 ≥ 0`.
6. `skip_stateful_validations` returns `true` → `__validate__` is skipped.
7. Attacker's Invoke is admitted to the mempool without signature verification.
8. Block execution: `DeployAccount` runs (nonce 0→1), then Invoke runs with `validate=true` (sequencing path uses `new_for_sequencing` which sets `validate: true`), `__validate__` fails → transaction **reverts**, fees are charged from `A`'s pre-funded balance, nonce increments to 2. [7](#0-6) 

### Impact Explanation

- **Admission of invalid transaction**: An Invoke with an invalid/arbitrary signature for an undeployed account is admitted to the mempool and included in a block, violating the invariant that every admitted Invoke must have passed `__validate__` or have a legitimate reason to skip it.
- **Nonce griefing**: The victim's nonce is incremented to 2 after the reverted Invoke. The victim's own `Invoke(nonce=1)` is rejected by the mempool as `DuplicateNonce` while the attacker's transaction is pending, and the victim must use nonce 2 for their first post-deploy transaction.
- **Fee drain**: The reverted Invoke charges fees from the victim's pre-funded balance (standard Starknet behavior: reverted transactions still pay fees).

Matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

### Likelihood Explanation

- Requires no special privileges; any observer of the mempool can execute this.
- The target address is deterministic (`calculate_contract_address` from class hash + salt + constructor calldata), so the attacker can precompute it.
- The race window is the time between the legitimate `DeployAccount` entering the mempool and the block being committed — typically multiple seconds to minutes.
- The attacker needs only one valid-looking Invoke (correct nonce, any signature within the `max_signature_length` limit).

### Recommendation

In `skip_stateful_validations`, replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `DeployAccount` transaction exists for the sender address in the mempool. Alternatively, add a new mempool API `deploy_account_in_pool_or_recent_block(address)` that only returns `true` when the pending/committed transaction for that address is specifically a `DeployAccount`. This closes the gap between the intended invariant ("a deploy_account exists") and the actual check ("any transaction exists").

### Proof of Concept

```
1. Attacker observes mempool: DeployAccount(sender=A, nonce=0) is pending.
   account_tx_in_pool_or_recent_block(A) == true.

2. Attacker submits:
   Invoke V3 {
     sender_address: A,
     nonce: 1,
     signature: [0xdeadbeef],   // garbage, not a valid ECDSA signature
     calldata: [<any>],
     resource_bounds: <above min_gas_price>,
     ...
   }

3. Gateway stateless validation:
   - validate_contract_address(A): OK (valid felt)
   - validate_resource_bounds: OK
   - validate_tx_signature_size: OK (length 1 ≤ max_signature_length)
   → passes

4. Gateway stateful validation:
   - account_nonce = get_nonce_from_state(A) = 0
   - validate_nonce: 0 ≤ 1 ≤ 0+max_allowed_nonce_gap → OK
   - validate_by_mempool: nonce 1 ≥ 0 → OK
   - skip_stateful_validations:
       tx.nonce()==1 && account_nonce==0 && account_tx_in_pool_or_recent_block(A)==true
       → returns true
   - run_validate_entry_point(skip_validate=true):
       ExecutionFlags { validate: false, ... }
       → __validate__ NOT called
   → Invoke admitted to mempool

5. Block N is built:
   - DeployAccount(A, nonce=0) executes: account deployed, nonce→1
   - Invoke(A, nonce=1) executes with validate=true:
       handle_nonce: nonce 1→2
       __validate__ called → REVERT (invalid signature)
       fee charged from A's balance
       nonce remains 2

6. Victim submits Invoke(A, nonce=1) → rejected: DuplicateNonce (while attacker tx pending)
   or must use nonce=2 after block commit.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L286-296)
```rust
            // Other transactions must be within the allowed nonce range.
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
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
