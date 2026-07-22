### Title
Gateway Bypasses `__validate__` Signature Verification for Invoke Transactions with Nonce=1 When Any Account Transaction Exists in Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the Apollo gateway unconditionally skips the `__validate__` entry point (which performs account signature verification) for any invoke transaction with nonce=1 when the account's on-chain nonce is 0 and `account_tx_in_pool_or_recent_block` returns `true`. Because that check returns `true` for **any** account transaction in the pool — not specifically a `deploy_account` — an unprivileged attacker can submit an invoke transaction carrying an arbitrary/invalid signature that is admitted to the mempool without any signature check.

---

### Finding Description

**Root cause — `skip_stateful_validations`:** [1](#0-0) 

When an `Invoke` transaction satisfies `tx.nonce() == 1` **and** `account_nonce == 0`, the function delegates to `account_tx_in_pool_or_recent_block`. If that returns `true`, `skip_validate = true` is returned to the caller.

**Effect on `run_validate_entry_point`:** [2](#0-1) 

`validate: !skip_validate` is set to `false`, so `StatefulValidator::perform_validations` exits immediately after `perform_pre_validation_stage` without ever calling `__validate__`: [3](#0-2) 

**The broken invariant — `account_tx_in_pool_or_recent_block` is not deploy-account-specific:** [4](#0-3) 

This returns `true` if the account has **any** transaction in the pool or any recent block. The inline comment in `skip_stateful_validations` claims "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this is not enforced. A single valid `deploy_account` submission is sufficient to make this return `true`, after which any number of invoke transactions with nonce=1 and arbitrary signatures will bypass `__validate__`.

**Attacker-controlled path:**

1. Attacker derives a fresh account address `A` (deterministic from class hash, salt, constructor calldata).
2. Attacker submits a valid `deploy_account` for `A` → passes all validations, enters mempool.
3. Attacker submits `Invoke(sender=A, nonce=1, signature=[0x0, 0x0])` (invalid signature).
4. Gateway evaluates: `tx.nonce()==1` ✓, `account_nonce==0` ✓, `account_tx_in_pool_or_recent_block(A)==true` ✓.
5. `skip_validate=true` → `validate=false` → `__validate__` is **never called**.
6. The invalid-signature invoke is admitted to the mempool. [5](#0-4) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions.**

An invoke transaction with an invalid (or entirely absent) signature is accepted by the gateway and inserted into the mempool without any cryptographic verification. This breaks the admission invariant that every transaction in the mempool has passed account-level signature validation.

Secondary consequences:
- **Mempool pollution / DoS**: An attacker can flood the mempool with signature-invalid invokes for any address that has a pending `deploy_account`, consuming mempool capacity and batcher resources.
- **Fee drain from pre-funded accounts**: If address `A` was pre-funded before deployment (common in UX flows), the batcher will execute the `deploy_account` (nonce=0), then attempt the invalid invoke (nonce=1). `__validate__` will be called during execution and will fail, but the account may still be charged fees for the failed validation step, draining its balance.

---

### Likelihood Explanation

**Medium.** The attack requires no privileged access. Any user can:
- Compute a deterministic account address.
- Submit a valid `deploy_account` (publicly documented flow).
- Immediately submit an invoke with nonce=1 and a garbage signature.

The only constraint is that the `deploy_account` must reach the mempool before the invoke is submitted, which is trivially satisfied by submitting them in order.

---

### Recommendation

1. **Verify deploy-account specifically**: Replace the generic `account_tx_in_pool_or_recent_block` check with a dedicated query that confirms a `deploy_account` transaction (not just any transaction) is pending for the address.

2. **Restrict the skip to nonce=1 only with a tighter guard**: The current hardcoded `nonce == 1` check is already narrow, but the mempool check must be made deploy-account-specific to close the gap.

3. **Do not skip `__validate__` entirely**: Instead of skipping signature verification, consider running `__validate__` against a synthetic "pre-deployment" state (the class hash is known from the `deploy_account` in the pool), so the signature is still verified before admission.

---

### Proof of Concept

```
1. Compute address A = calculate_contract_address(salt, class_hash, constructor_calldata, deployer=0)

2. Submit deploy_account:
   RpcDeployAccountTransactionV3 {
       sender: A, nonce: 0, class_hash: <valid>, salt: <salt>,
       constructor_calldata: <data>, signature: <valid ECDSA sig>,
       resource_bounds: <valid>, ...
   }
   → Gateway: passes all checks, enters mempool.
   → account_tx_in_pool_or_recent_block(A) now returns true.

3. Submit invoke with invalid signature:
   RpcInvokeTransactionV3 {
       sender_address: A, nonce: 1,
       signature: TransactionSignature([Felt::ZERO, Felt::ZERO]),
       calldata: <arbitrary>, resource_bounds: <valid>, ...
   }
   → Gateway stateless: passes (signature length ≤ max_signature_length).
   → Gateway stateful:
       account_nonce = get_nonce_from_state(A) = 0  (A not deployed)
       validate_nonce: 0 ≤ 1 ≤ 0+200 → OK
       skip_stateful_validations: nonce==1 ∧ account_nonce==0 ∧ pool_check==true → true
       run_validate_entry_point: validate=false → __validate__ NOT called → Ok(())
   → Mempool: add_tx succeeds.

4. Invalid-signature invoke is now in the mempool.

5. Batcher executes deploy_account (nonce=0) → A is deployed.
   Batcher executes invoke (nonce=1) → __validate__ called → signature [0,0] fails →
   transaction reverts; if A has balance, fees are charged.
```

The gateway admission invariant is broken at step 3: a transaction with a cryptographically invalid signature is accepted as if it were valid.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
