### Title
`skip_stateful_validations` Bypasses Signature Verification for Invoke Transactions Targeting Undeployed Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point (and therefore signature verification) for any invoke transaction whose nonce is 1 and whose sender account has a pending deploy-account transaction in the mempool. Because the check only verifies that the *account* exists in the mempool — not that the *submitter* owns the account — any third party can inject an invoke transaction with an arbitrary (invalid) signature for a victim's undeployed account. The gateway accepts the transaction, adds it to the mempool, and the attacker can use fee escalation to displace the victim's legitimate nonce-1 invoke transaction.

---

### Finding Description

`skip_stateful_validations` in `crates/apollo_gateway/src/stateful_transaction_validator.rs` returns `true` (skip validation) when three conditions hold:

1. The transaction is an `Invoke` transaction.
2. The transaction nonce equals `Nonce(Felt::ONE)`.
3. The on-chain account nonce equals `Nonce(Felt::ZERO)` (account not yet deployed).
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

With `execution_flags.validate = false`, `AccountTransaction::validate_tx` returns `Ok(None)` immediately — the account's `__validate__` entry point is never called and the signature is never verified: [3](#0-2) 

The check `account_tx_in_pool_or_recent_block` only confirms that *some* transaction for the target address exists in the mempool or a recent block — it says nothing about whether the *submitter* of the incoming invoke transaction is the account owner: [4](#0-3) 

This is the direct analog of H-03: `claimRewards` verified `_to` was authorized but not `msg.sender`. Here, `skip_stateful_validations` verifies the *account* has a deploy-account in the mempool but not that the *sender of the invoke tx* owns the account.

**Attack path:**

1. Victim broadcasts `deploy_account` for address `A` (deterministic from class hash + salt + constructor calldata) and a legitimate `invoke` with nonce=1.
2. Attacker observes the `deploy_account` in the mempool.
3. Attacker submits `invoke(sender=A, nonce=1, calldata=<arbitrary>, signature=<garbage>)`.
4. Gateway calls `skip_stateful_validations`: nonce=1 ✓, account_nonce=0 ✓, `account_tx_in_pool_or_recent_block(A)` = true ✓ → returns `true`.
5. `run_validate_entry_point` is called with `skip_validate=true`, so `execution_flags.validate=false` and `__validate__` is never invoked.
6. The attacker's transaction is accepted into the mempool.
7. The attacker pays a higher fee than the victim's legitimate nonce-1 invoke. The mempool's fee-escalation logic replaces the victim's invoke with the attacker's.
8. During block execution the batcher uses `validate: true` (via `new_for_sequencing`), so `__validate__` is called and the attacker's garbage signature fails. The attacker's tx is rejected and the victim's legitimate tx is permanently gone from the mempool. [5](#0-4) 

---

### Impact Explanation

The gateway admits an invoke transaction that carries an invalid (attacker-controlled) signature for an account the attacker does not own. This breaks the invariant that every accepted transaction must be authorized by the account's key. Via fee escalation the attacker can permanently displace the victim's legitimate nonce-1 invoke transaction from the mempool, causing it to be silently dropped. This matches the allowed impact: **"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

---

### Likelihood Explanation

The precondition — a deploy-account transaction in the mempool — is publicly observable. Account addresses are deterministic and predictable. No privileged access is required. The attacker only needs to submit a single well-formed invoke transaction (with any signature) to trigger the bypass. The `skip_stateful_validations` path is an intentional UX feature, making it permanently reachable.

---

### Recommendation

Add signature verification even when skipping the blockifier's `__validate__` entry point, or restrict the skip to transactions that were submitted together with their corresponding deploy-account (e.g., by requiring the invoke transaction to arrive in the same gateway request as the deploy-account, or by verifying the signature off-chain before granting the skip). At minimum, the skip should only be granted when the incoming invoke transaction's `tx_hash` matches a hash that was pre-registered alongside the deploy-account, preventing third-party injection.

A minimal fix is to require that the invoke transaction's signature passes a lightweight off-chain check (e.g., ECDSA verification against the expected public key derived from the deploy-account's constructor calldata) before `skip_stateful_validations` returns `true`.

---

### Proof of Concept

```
// Precondition: victim has submitted deploy_account for address A
// and a legitimate invoke(nonce=1) to the gateway.

// Attacker submits:
RpcInvokeTransactionV3 {
    sender_address: A,          // victim's undeployed account
    nonce: 1,
    calldata: [<drain_funds>],  // arbitrary calldata
    signature: [0x1337],        // garbage signature
    resource_bounds: { l2_gas: { max_amount: X, max_price_per_unit: Y+1 } },
    // Y+1 > victim's gas price → fee escalation replaces victim's tx
    ...
}

// Gateway path:
// 1. stateless_validator.validate() → passes (no signature check here)
// 2. stateful_validator.extract_state_nonce_and_run_validations():
//    - account_nonce = get_nonce(A) = 0  (not deployed)
//    - run_pre_validation_checks():
//        - validate_nonce: 0 <= 1 <= 0+gap → OK
//        - validate_by_mempool: OK
//        - skip_stateful_validations:
//            nonce==1 && account_nonce==0 && account_tx_in_pool(A)==true
//            → returns true
//    - run_validate_entry_point(skip_validate=true):
//        execution_flags.validate = false
//        validate_tx() → Ok(None)  // __validate__ never called
// 3. Transaction accepted into mempool.
// 4. Fee escalation removes victim's legitimate invoke(nonce=1).
// 5. Block execution: attacker's tx fails __validate__ → rejected.
//    Victim's tx is gone.
``` [6](#0-5) [7](#0-6) [8](#0-7) [3](#0-2)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```
