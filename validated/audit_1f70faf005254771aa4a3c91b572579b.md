### Title
`skip_stateful_validations` Accepts Signature-Forged Invoke Transactions for Accounts with Pending Deploy-Account — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's UX shortcut for the deploy-account + invoke flow skips `__validate__` (signature verification) for any invoke with `nonce=1` from an undeployed account that has *any* transaction in the mempool. Because the mempool presence check is not restricted to deploy-account transactions, an unprivileged attacker who observes a victim's pending deploy-account can inject an invoke with an arbitrary (invalid) signature that the gateway admits without calling `__validate__`, satisfying the "High – mempool/gateway admission accepts invalid transactions" impact criterion.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` decides whether to set `validate = false` in `ExecutionFlags` before calling the blockifier's `StatefulValidator`: [1](#0-0) 

The three conditions that trigger the skip are:

1. Transaction type is `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain).
4. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [2](#0-1) 

When all four hold, `skip_validate = true` is returned, and `run_validate_entry_point` sets `validate = !skip_validate = false`: [3](#0-2) 

Inside the blockifier's `StatefulValidator::perform_validations`, `validate = false` causes an early return before `__validate__` is ever called: [4](#0-3) 

And inside `AccountTransaction::validate_tx`, the same flag short-circuits the entry-point call: [5](#0-4) 

**The broken invariant** is in condition 4. `account_tx_in_pool_or_recent_block` returns `true` whenever the address appears in the mempool's `state.committed`, `state.staged`, or `tx_pool` maps — it does **not** verify that the matching transaction is a `DeployAccount`: [6](#0-5) [7](#0-6) 

The code comment acknowledges this looseness ("either it has a deploy_account transaction **or** transactions with future nonces that passed validations") but does not guard against an attacker who exploits the window between the victim's deploy-account entering the mempool and being executed.

The preceding `validate_by_mempool` call only checks nonce ordering and fee-escalation rules — it never inspects the signature: [8](#0-7) 

---

### Impact Explanation

An attacker who observes a victim's pending deploy-account transaction can submit an invoke with `nonce=1` from the victim's address carrying an **arbitrary (invalid) signature**. The gateway admits it into the mempool without any cryptographic check. Once in the mempool, the attacker's transaction competes with the victim's legitimate first invoke via the fee-escalation replacement mechanism. If the attacker bids a higher fee, the victim's invoke is evicted. When the batcher later executes the attacker's invoke, `__validate__` is called with `validate=true` (the default for block execution), the signature check fails, and the transaction is rejected — but the victim's legitimate invoke has already been displaced from the mempool, forcing a resubmission.

This matches: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.**

---

### Likelihood Explanation

The mempool is observable by any network participant. The attacker only needs to detect a deploy-account transaction for a target address and race to submit a higher-fee invoke with `nonce=1` before the deploy-account is committed. No privileged access is required. The attack window is the time between the deploy-account entering the mempool and the batcher committing the block that contains it.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a type-specific query that returns `true` only when the account has a **pending deploy-account** transaction (not any transaction). Concretely:

- Add a `has_pending_deploy_account(address)` method to the mempool that inspects the transaction type stored in `tx_pool`.
- Use that method in `skip_stateful_validations` instead of `account_tx_in_pool_or_recent_block`.

This preserves the UX feature while closing the window for signature-bypass injection.

---

### Proof of Concept

```
1. Victim generates account address A (deterministic from class hash + salt).
2. Victim submits DeployAccount(nonce=0) for A → gateway fully executes it
   (constructor runs), tx enters mempool.
3. Attacker observes the mempool, sees DeployAccount for A.
4. Attacker submits Invoke(sender=A, nonce=1, signature=[0x0, 0x0, ...]).
   Gateway path:
     a. validate_contract_address → OK (A is a valid felt).
     b. validate_nonce: account_nonce=0, tx_nonce=1, within gap → OK.
     c. validate_by_mempool → nonce not too old, no fee-escalation conflict → OK.
     d. skip_stateful_validations:
          tx.nonce()==1 ✓, account_nonce==0 ✓,
          account_tx_in_pool_or_recent_block(A)==true ✓  (DeployAccount is there)
          → returns true.
     e. run_validate_entry_point(skip_validate=true):
          ExecutionFlags { validate: false, ... }
          StatefulValidator::perform_validations → early return, __validate__ never called.
     f. Attacker's forged invoke is accepted into the mempool.
5. Attacker re-submits with a fee higher than the victim's legitimate Invoke(nonce=1)
   → fee-escalation replaces victim's invoke.
6. Batcher executes: DeployAccount succeeds; attacker's Invoke reaches __validate__,
   signature check fails, tx is rejected — victim's invoke is gone from the mempool.
7. Victim must detect the displacement and resubmit.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L115-117)
```rust
    fn contains_account(&self, address: ContractAddress) -> bool {
        self.staged.contains_key(&address) || self.committed.contains_key(&address)
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
