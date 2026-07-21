### Title
Unsigned Invoke Transactions Admitted to Mempool via Deploy-Account Frontrunning — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function unconditionally skips the `__validate__` entry point (and therefore all signature verification) for any invoke transaction with `nonce=1` sent to an address whose on-chain nonce is `0`, whenever **any** transaction for that address already exists in the mempool or a recent block. Because the check is not restricted to the legitimate owner's deploy-account, an attacker who observes a victim's pending `deploy_account` can immediately inject an arbitrarily-signed invoke for the same address and have it admitted to the mempool without any cryptographic validation.

---

### Finding Description

`skip_stateful_validations` (lines 429–460) implements a UX shortcut: a user who broadcasts `deploy_account` + `invoke` simultaneously should not have their invoke rejected just because the account does not exist on-chain yet. [1](#0-0) 

The condition that triggers the skip is:

```
tx.nonce() == 1  &&  account_nonce == 0  &&  account_tx_in_pool_or_recent_block(sender) == true
```

When all three hold, `skip_validate` is returned as `true`. [2](#0-1) 

`run_validate_entry_point` then sets `ExecutionFlags { validate: !skip_validate, … }`, so when `skip_validate=true` the blockifier's `__validate__` entry point is never invoked and no signature check is performed. [3](#0-2) 

The critical flaw is that `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction associated with the address — it is not restricted to a deploy-account submitted by the same principal. The code comment acknowledges this explicitly: [4](#0-3) 

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

This reasoning is circular: the first unsigned invoke passes because the victim's deploy-account is in the pool; a second unsigned invoke passes because the first unsigned invoke is now in the pool.

The only prior checks that run before `skip_stateful_validations` are:

1. **Stateless validation** — checks signature *length*, not cryptographic validity.
2. **Nonce range check** — `0 ≤ 1 ≤ max_gap`, which passes trivially.
3. **`validate_by_mempool`** — mempool-level duplicate/ordering checks, not a signature check. [5](#0-4) 

None of these verify the signature content.

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can inject arbitrarily-signed (or zero-signature) invoke transactions for any address that has a pending `deploy_account` in the mempool. Concrete consequences:

- **Mempool pollution / DoS**: The attacker can flood the mempool with invalid invokes for every observed `deploy_account`, consuming mempool capacity.
- **Legitimate invoke displacement**: If the mempool enforces one transaction per `(address, nonce)` pair, the attacker's unsigned invoke can displace the victim's legitimate nonce-1 invoke, forcing the victim to resubmit and potentially miss their intended execution slot.
- **Fee griefing**: The victim's deploy-account executes, the attacker's invalid invoke is then attempted, reverts (because `__validate__` rejects the bad signature at execution time), and the victim's legitimate invoke may be absent from the block.

---

### Likelihood Explanation

**High.** The attack requires no privileged access. The attacker only needs to:

1. Monitor the public mempool for `deploy_account` transactions.
2. Craft an invoke with `sender_address = victim`, `nonce = 1`, and any two-felt signature (passes the length check in `validate_tx_signature_size`).
3. Submit it to the gateway.

No cryptographic material belonging to the victim is needed.

---

### Recommendation

Replace the broad `account_tx_in_pool_or_recent_block` check with a check that is specific to `deploy_account` transactions for the same address. The mempool should expose a dedicated query such as `deploy_account_in_pool(address) -> bool` that returns `true` only when a `DeployAccount` transaction (not any transaction) is pending for that address.

```rust
// Proposed fix
async fn skip_stateful_validations(...) -> ... {
    if let ExecutableTransaction::Invoke(...) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .deploy_account_in_pool(tx.sender_address())  // <-- specific check
                .await
                ...
        }
    }
    Ok(false)
}
```

This mirrors the fix applied to `EarnStrategyRegistry`: instead of trusting a caller-supplied (or indirectly attacker-influenced) signal, derive the authorization from the canonical source — the presence of a `deploy_account` transaction specifically, not any transaction.

---

### Proof of Concept

```
1. Alice broadcasts:
     DeployAccount { sender=X, nonce=0, class_hash=C, salt=S, signature=<valid> }

2. Attacker observes Alice's deploy_account in the mempool.

3. Attacker broadcasts:
     Invoke { sender=X, nonce=1, calldata=[drain_funds], signature=[Felt::ZERO, Felt::ZERO] }

4. Gateway stateless check:
     - signature length = 2  ≤  max_signature_length  ✓
     - resource bounds valid  ✓

5. Gateway stateful check:
     - account_nonce(X) = 0  (X not yet deployed)
     - tx.nonce() = 1
     - account_tx_in_pool_or_recent_block(X) = true  (Alice's deploy_account)
     → skip_validate = true
     → __validate__ NOT called
     → transaction admitted to mempool  ✓

6. At block execution:
     - Alice's deploy_account executes, deploying account X.
     - Attacker's invoke executes; account X's __validate__ rejects the zero signature → revert.
     - Alice's legitimate nonce-1 invoke (if displaced) is absent from the block.
``` [6](#0-5) [7](#0-6)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L180-195)
```rust
    fn validate_tx_signature_size(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```
