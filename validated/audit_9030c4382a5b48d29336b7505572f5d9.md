### Title
Signature Verification Bypass via Overly Broad `skip_stateful_validations` Check Admits Invalid Invoke Transactions to Mempool - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator uses `account_tx_in_pool_or_recent_block` to decide whether to skip the `__validate__` entry-point (signature verification) for an invoke transaction with nonce=1 targeting an undeployed account. Because `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from the sender address — not specifically a `deploy_account` — an unprivileged attacker who observes a victim's pending `deploy_account` in the mempool can submit an invoke transaction with an **arbitrary/invalid signature** for the victim's address and have it admitted to the mempool without signature verification.

### Finding Description

The gateway stateful path calls `skip_stateful_validations` to implement a UX feature: when a user sends `deploy_account` + `invoke` simultaneously, the invoke (nonce=1) is admitted even though the account doesn't exist yet. [1](#0-0) 

The skip condition fires when:
1. The transaction is an `Invoke` with `nonce == 1`
2. The on-chain account nonce is `0` (account not yet deployed)
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [2](#0-1) 

When `skip_validate = true`, `run_validate_entry_point` sets `validate: false` in `ExecutionFlags`, so the account's `__validate__` function — which performs signature verification — is never called: [3](#0-2) 

The mempool's `account_tx_in_pool_or_recent_block` checks whether the address has **any** transaction in the pool or any committed block entry — it does not distinguish between `deploy_account` and `invoke` transaction types: [4](#0-3) 

The code comment itself acknowledges this: *"it means that either it has a deploy_account transaction **or transactions with future nonces that passed validations**."* This second branch is the exploitable path.

### Impact Explanation

An attacker who observes victim address `X` with a pending `deploy_account` in the mempool can:

1. Submit `Invoke { sender_address: X, nonce: 1, signature: <arbitrary garbage> }`
2. Gateway checks: `nonce(1) == 1` ✓, `account_nonce(X) == 0` ✓, `account_tx_in_pool_or_recent_block(X) == true` ✓ → `skip_validate = true`
3. `run_validate_entry_point` is skipped; the invalid invoke is admitted to the mempool without signature verification

The admitted invalid transaction then:
- Occupies the nonce=1 slot for address `X`, forcing the legitimate owner to pay fee-escalation premiums to displace it
- Is executed during block building, where `__validate__` is finally called and fails, wasting sequencer execution resources
- Blocks the victim's first post-deploy invoke unless they escalate fees

This matches the impact scope: **High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.** [5](#0-4) 

### Likelihood Explanation

The mempool is public; any observer can identify addresses with pending `deploy_account` transactions. No privileged access is required. The attacker only needs to craft an `RpcInvokeTransactionV3` with the victim's `sender_address`, `nonce=1`, and any bytes as the signature. The stateless validator does not verify signatures: [6](#0-5) 

The stateless validator only checks signature **length**, not validity: [7](#0-6) 

### Recommendation

Replace the overly broad `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction exists for the sender address. The mempool should expose a dedicated `has_pending_deploy_account(address)` query that inspects the transaction type, rather than returning `true` for any transaction type from that address.

Alternatively, restrict the skip condition to only apply when the gateway itself submitted the `deploy_account` in the same request batch (i.e., track the pairing explicitly), eliminating the reliance on the mempool's address-presence check.

### Proof of Concept

```
// Precondition: victim Alice has submitted deploy_account for address X.
// X is now visible in the mempool. account_nonce(X) == 0 on-chain.

// Attacker constructs:
let attacker_invoke = RpcInvokeTransactionV3 {
    sender_address: X,          // victim's address
    nonce: 1,                   // triggers skip_stateful_validations
    signature: vec![0xDEAD],    // invalid signature
    calldata: vec![],
    resource_bounds: valid_bounds,
    // ... other fields
};

// Gateway stateless validation passes (signature length <= max).
// Gateway stateful validation:
//   account_nonce(X) == 0  ✓
//   tx.nonce() == 1        ✓
//   account_tx_in_pool_or_recent_block(X) == true  ✓  (deploy_account is there)
//   → skip_validate = true → __validate__ NOT called
//   → attacker's invalid invoke admitted to mempool

// Alice's legitimate invoke with nonce=1 is now rejected as DuplicateNonce,
// or Alice must pay fee-escalation premium to displace the attacker's tx.
// When executed in a block, the attacker's invoke fails __validate__,
// wasting sequencer execution resources.
``` [8](#0-7) [4](#0-3)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-314)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L33-54)
```rust
    pub fn validate(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        // TODO(Arni, 1/5/2024): Add a mechanism that validate the sender address is not blocked.
        // TODO(Arni, 1/5/2024): Validate transaction version.

        Self::validate_contract_address(tx)?;
        Self::validate_empty_account_deployment_data(tx)?;
        Self::validate_empty_paymaster_data(tx)?;
        self.validate_resource_bounds(tx)?;
        self.validate_tx_size(tx)?;
        self.validate_nonce_data_availability_mode(tx)?;
        self.validate_fee_data_availability_mode(tx)?;

        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_client_side_proving_allowed(invoke_tx)?;
            self.validate_proof_facts_and_proof_consistency(invoke_tx)?;
        }

        if let RpcTransaction::Declare(declare_tx) = tx {
            self.validate_declare_tx(declare_tx)?;
        }
        Ok(())
    }
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
