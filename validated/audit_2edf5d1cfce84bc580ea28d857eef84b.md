### Title
Gateway `skip_stateful_validations` admits unauthorized invoke transactions by checking any mempool presence instead of deploy-account type — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator skips the `__validate__` entry point for invoke transactions with `nonce=1` when the account has `nonce=0` on-chain and `account_tx_in_pool_or_recent_block` returns `true`. The check `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction in the mempool from the sender's address — not only deploy-account transactions. An unprivileged attacker can exploit this by submitting an invoke with `nonce=1` using a victim's address as `sender_address`, bypassing `__validate__` at the gateway, and getting an unauthorized transaction admitted to the mempool.

### Finding Description

`skip_stateful_validations` (lines 429–461) is designed to skip the `__validate__` entry point for the first invoke after a `deploy_account`, to improve UX for users sending `deploy_account + invoke` simultaneously. The function checks `account_tx_in_pool_or_recent_block(tx.sender_address())` to verify that a `deploy_account` exists for the account. The code comment states:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

However, `account_tx_in_pool_or_recent_block` (line 697–700) returns `true` for **any** transaction in the pool or recent block from that address — it does not verify the transaction type is `deploy_account`. [1](#0-0) 

The attacker's invoke with `nonce=1` and `sender_address=victim` passes all gateway checks before the skip decision:

1. **Stateless validation** (`validate_contract_address`): only checks the address is non-zero — does not verify the signature matches the address. [2](#0-1) 

2. **`validate_state_preconditions`**: checks nonce is within `[account_nonce, account_nonce + max_allowed_nonce_gap]`. For `account_nonce=0` and `tx_nonce=1`, this passes when `max_allowed_nonce_gap >= 1`. [3](#0-2) 

3. **`validate_by_mempool`**: checks nonce gap and fee escalation only — no signature check. [4](#0-3) 

4. **`skip_stateful_validations`**: `tx.nonce()==1`, `account_nonce==0`, and `account_tx_in_pool_or_recent_block(victim_address)` returns `true` because the victim's `deploy_account` is already in the mempool. The function returns `true` (skip `__validate__`). [5](#0-4) 

5. **`run_validate_entry_point`**: sets `validate: !skip_validate = false`, so `__validate__` is **not called** at the gateway. [6](#0-5) 

The attacker's invoke is admitted to the mempool without any signature verification. When the batcher later executes the transaction, `AccountTransaction::new_for_sequencing` sets `validate: true`, so `__validate__` **is** run: [7](#0-6) 

`__validate__` fails (invalid signature), the transaction reverts, and the fee is charged to the victim's account.

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

The gateway admits an invoke transaction that carries an arbitrary/invalid signature for the victim's account. The broken invariant is: every invoke transaction admitted to the mempool must have passed `__validate__` (the account's authorization check) or have a legitimate UX-skip reason (the sender's own `deploy_account` is pending). Here, a third party can trigger the skip for any victim whose `deploy_account` is in the mempool.

Concrete consequences:
- The victim's `nonce=1` slot in the mempool is occupied by the attacker's invalid transaction. The victim must pay a fee-escalation premium to displace it.
- When executed, `__validate__` fails, the transaction reverts, and the fee (minimum gas overhead) is charged to the victim's account — funds the victim never authorized spending.

### Likelihood Explanation

The mempool is observable by any network participant. Any new account that broadcasts a `deploy_account` transaction is immediately vulnerable. The attacker needs only to:
1. Watch the mempool for `deploy_account` transactions.
2. Craft an invoke with `nonce=1`, `sender_address=victim`, and any signature within the size limit.
3. Submit it to the gateway.

No privileged access, no special knowledge of the victim's private key, and no on-chain state is required.

### Recommendation

Replace the type-agnostic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is pending for the sender's address. The mempool should expose a `has_pending_deploy_account(address)` query, or the existing check should be narrowed to only match `deploy_account` transaction types in the pool.

### Proof of Concept

```
1. Victim funds address A and submits deploy_account(nonce=0, sender=A) → admitted to mempool.

2. Attacker observes deploy_account for A in the mempool.

3. Attacker submits invoke(nonce=1, sender_address=A, signature=[0x0, 0x0]).

4. Gateway stateless check: signature length 2 ≤ max_signature_length → PASS.

5. Gateway stateful: get_nonce_from_state(A) → 0 (not yet deployed on-chain).

6. validate_state_preconditions: nonce=1 ∈ [0, max_allowed_nonce_gap] → PASS.

7. validate_by_mempool: no duplicate, nonce gap=1 ≤ max_allowed_nonce_gap → PASS.

8. skip_stateful_validations:
     tx.nonce()==1 ✓, account_nonce==0 ✓,
     account_tx_in_pool_or_recent_block(A)==true (victim's deploy_account is there) ✓
   → returns true (SKIP __validate__).

9. run_validate_entry_point: validate=false → __validate__ NOT called.

10. Attacker's invoke admitted to mempool.

--- Batcher execution ---

11. deploy_account(A, nonce=0) executed → A deployed, nonce→1.

12. invoke(A, nonce=1, sig=[0,0]) executed with validate=true (new_for_sequencing).

13. __validate__ runs → signature mismatch → REVERT.

14. Fee charged to A's balance. Victim loses funds for a transaction they never signed.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L213-221)
```rust
    async fn validate_state_preconditions(
        &self,
        executable_tx: &ExecutableTransaction,
        account_nonce: Nonce,
    ) -> StatefulTransactionValidatorResult<()> {
        self.validate_resource_bounds(executable_tx).await?;
        self.validate_nonce(executable_tx, account_nonce)?;
        Ok(())
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-461)
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
}

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

/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L90-98)
```rust
    fn validate_contract_address(tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        let sender_address = match tx {
            RpcTransaction::Declare(RpcDeclareTransaction::V3(tx)) => tx.sender_address,
            RpcTransaction::DeployAccount(_) => return Ok(()),
            RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => tx.sender_address,
        };

        Ok(sender_address.validate()?)
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
