### Title
Gateway Skips `__validate__` Signature Check for Invoke Transactions with Nonce=1 from Undeployed Accounts — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point (which performs account signature verification) for any Invoke transaction with `nonce == 1` submitted against an account whose on-chain nonce is still `0`, provided *any* transaction from that address exists in the mempool or a recent block. Because the check is on address presence rather than on the type or validity of the pending transaction, an unprivileged attacker can inject an Invoke transaction carrying an arbitrary (invalid) signature into the mempool for any not-yet-deployed account that has a pending deploy-account transaction.

### Finding Description

`skip_stateful_validations` is the Sequencer-native analog of the `withdrawGiveaway` bug: just as `withdrawGiveaway` accepted a user-supplied `allocation` without checking a whitelist, `skip_stateful_validations` accepts a user-supplied Invoke transaction without verifying its signature, relying solely on a loose membership check.

The relevant code path is:

**`extract_state_nonce_and_run_validations`** calls `run_pre_validation_checks`, which calls `skip_stateful_validations`, and then passes the result as `skip_validate` to `run_validate_entry_point`: [1](#0-0) 

Inside `run_validate_entry_point`, `validate: !skip_validate` is set on the `ExecutionFlags`, so when `skip_validate == true` the `__validate__` entry point is never called: [2](#0-1) 

The skip decision is made in `skip_stateful_validations`: [3](#0-2) 

The condition is:
1. Transaction type is Invoke.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)`.
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

Condition 4 checks only whether *any* transaction from the sender address is known to the mempool — it does **not** verify that the pending transaction is a `DeployAccount`, nor does it verify the incoming Invoke's signature in any way. The comment acknowledges this looseness:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

The mempool's own `validate_tx` only checks for duplicate hashes and stale nonces — it performs no signature verification: [4](#0-3) [5](#0-4) 

The stateless validator checks signature *length* but not signature *validity*: [6](#0-5) 

Note also that `StatefulTransactionValidatorConfig` carries a `max_nonce_for_validation_skip` field (default `Nonce(Felt::ONE)`), but `skip_stateful_validations` in the gateway **never reads it** — the nonce bound is hardcoded to `== Nonce(Felt::ONE)`: [7](#0-6) 

### Impact Explanation

An attacker who observes a `DeployAccount` transaction for address `A` in the mempool (on-chain nonce of `A` is still 0) can immediately submit an Invoke transaction with `nonce=1`, `sender_address=A`, and a completely invalid (e.g., zeroed) signature. The gateway will:

1. Pass stateless validation (signature length ≤ limit).
2. Pass nonce validation (nonce 1 ≥ account nonce 0, within `max_allowed_nonce_gap`).
3. Pass mempool validation (no duplicate hash, nonce not stale).
4. Call `skip_stateful_validations` → returns `true` because `A` is in the mempool.
5. Skip `__validate__` entirely.
6. Admit the transaction to the mempool.

The invalid transaction is now queued for sequencing. When the batcher executes it, `__validate__` will run and fail, causing a revert. However, the attacker can repeat this indefinitely, polluting the mempool with invalid transactions, wasting sequencer execution resources, and potentially evicting legitimate transactions when the mempool reaches capacity.

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

### Likelihood Explanation

The attack requires no special privilege. Any observer of the public mempool can identify undeployed accounts with pending `DeployAccount` transactions and immediately submit forged Invoke transactions. The window is open for the entire duration that the `DeployAccount` transaction remains unconfirmed (potentially many blocks). The attack is cheap (only gas for the forged Invoke submission) and repeatable.

### Recommendation

Replace the loose `account_tx_in_pool_or_recent_block` membership check with a check that specifically confirms a `DeployAccount` transaction for the sender address is pending. Alternatively, store the deploy-account transaction hash alongside the pending Invoke (as the `PyValidator` path does via `deploy_account_tx_hash`) and verify it before skipping `__validate__`. At minimum, the `max_nonce_for_validation_skip` config field that already exists in `StatefulTransactionValidatorConfig` should be wired into `skip_stateful_validations` so the skip window is bounded by operator configuration rather than hardcoded.

### Proof of Concept

```
1. Alice submits DeployAccount(address=A, nonce=0, valid_sig) → mempool accepts it.
   On-chain nonce of A = 0; mempool state contains A.

2. Attacker submits Invoke(sender=A, nonce=1, calldata=<anything>, signature=[0x0]) to gateway.

3. Gateway stateless check: signature length 1 ≤ max_signature_length → PASS.

4. Gateway stateful check:
   - get_nonce_from_state(A) → Nonce(0)
   - validate_nonce: 0 ≤ 1 ≤ 0+200 → PASS
   - validate_resource_bounds: PASS (valid bounds supplied)
   - validate_by_mempool: nonce 1 ≥ resolved nonce 0 → PASS
   - skip_stateful_validations:
       tx.nonce() == Nonce(1) ✓
       account_nonce == Nonce(0) ✓
       account_tx_in_pool_or_recent_block(A) == true ✓  ← Alice's DeployAccount is there
     → returns true (skip __validate__)
   - run_validate_entry_point: validate=false → __validate__ NOT called

5. Attacker's Invoke(sig=[0x0]) is admitted to the mempool.

6. Batcher picks it up, runs __validate__ → signature invalid → transaction reverted.
   Attacker repeats from step 2 with a new tx_hash.
``` [3](#0-2) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

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

**File:** crates/apollo_mempool/src/mempool.rs (L162-174)
```rust
    fn validate_incoming_tx(
        &self,
        tx_reference: TransactionReference,
        incoming_account_nonce: Nonce,
    ) -> MempoolResult<()> {
        let TransactionReference { address, nonce: tx_nonce, .. } = tx_reference;
        let account_nonce = self.resolve_nonce(address, incoming_account_nonce);
        if tx_nonce < account_nonce {
            return Err(MempoolError::NonceTooOld { address, tx_nonce, account_nonce });
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L142-150)
```rust
    fn validate_tx_size(&self, tx: &RpcTransaction) -> StatelessTransactionValidatorResult<()> {
        self.validate_tx_extended_calldata_size(tx)?;
        self.validate_tx_signature_size(tx)?;
        if let RpcTransaction::Invoke(invoke_tx) = tx {
            self.validate_proof_size(invoke_tx)?;
        }

        Ok(())
    }
```

**File:** crates/apollo_gateway_config/src/config.rs (L283-299)
```rust
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```
