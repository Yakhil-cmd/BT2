### Title
`skip_stateful_validations` Uses Incomplete Proxy Check to Bypass `__validate__` for Arbitrary Accounts - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`skip_stateful_validations` is designed to skip the `__validate__` entry-point call for an invoke transaction with nonce=1 when the account's deploy_account has not yet been processed. The guard it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction in the pool for that address, not specifically a deploy_account transaction. An unprivileged attacker who observes that a deployed account (on-chain nonce=0) has any pending transaction in the mempool can submit a crafted invoke with nonce=1 and an invalid signature for that account. The gateway skips `__validate__` and admits the transaction to the mempool.

### Finding Description

`skip_stateful_validations` at lines 429–461 of `crates/apollo_gateway/src/stateful_transaction_validator.rs` fires when:

1. The incoming transaction is an `Invoke` with `tx.nonce() == Nonce(Felt::ONE)`, and
2. The on-chain account nonce is `Nonce(Felt::ZERO)`, and
3. `mempool_client.account_tx_in_pool_or_recent_block(sender)` returns `true`. [1](#0-0) 

The comment at line 440–443 states the intent: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is circular and incorrect for deployed accounts. A deployed account with on-chain nonce=0 can have a valid nonce=0 invoke in the pool (submitted by its legitimate owner). That single fact causes `account_tx_in_pool_or_recent_block` to return `true`, satisfying condition 3 above for any subsequent nonce=1 transaction — regardless of who submitted it or whether its signature is valid. [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` is called with `validate: false`: [3](#0-2) 

The `__validate__` entry point is therefore never invoked at the gateway for the attacker's transaction. The transaction passes all remaining checks (nonce range, resource bounds, mempool duplicate/fee-escalation) and is admitted to the mempool.

The analog to the external report is exact: `verifyState` checked only one entry of a large structure (a single mapping slot) and used a type cast, so the check passed even when the memory layout had changed. Here, `skip_stateful_validations` checks only one property of the account's pool state (presence of *any* transaction) rather than the specific property required (presence of a *deploy_account* transaction), so the check passes even when no deploy_account exists.

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

An attacker can inject an invoke transaction with an arbitrary (invalid) signature for any deployed account whose on-chain nonce is 0 and that has any pending transaction in the mempool. The transaction bypasses the `__validate__` entry point at the gateway and is admitted to the mempool. The batcher will later call `__validate__` (via `AccountTransaction::new_for_sequencing`, which always sets `validate: true`): [4](#0-3) 

The batcher's `validate_tx` will reject the transaction (no fee charged), but the attacker's transaction occupies the nonce=1 slot in the mempool. This enables a griefing attack: the attacker can repeatedly front-run the legitimate nonce=1 transaction, forcing the victim to pay escalating tips to displace the attacker's invalid transaction, or causing the victim's nonce=1 transaction to be delayed or dropped.

### Likelihood Explanation

The trigger conditions are observable from public mempool state: the attacker only needs to know the target account's address and that it has a pending nonce=0 transaction. No privileged access to the account is required. The attack is cheap (only resource bounds need to be valid; the signature can be arbitrary) and repeatable.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` proxy with a check that specifically verifies a **deploy_account** transaction exists for the account. The mempool should expose a dedicated query such as `deploy_account_tx_in_pool(address) -> bool` that inspects the transaction type, not merely account presence. Alternatively, the gateway can inspect the type of the lowest-nonce transaction in the pool for the account before deciding to skip `__validate__`.

### Proof of Concept

1. Deploy account `A` (on-chain nonce becomes 0 after deployment; or use a freshly deployed account whose first invoke has not yet been sequenced).
2. Legitimate owner of `A` submits `invoke_v3` with `nonce=0`. This passes `__validate__` and enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.
3. Attacker (no knowledge of `A`'s private key) constructs `invoke_v3` for `A` with `nonce=1`, valid resource bounds, and a garbage signature (e.g., `[Felt::ONE, Felt::TWO]`).
4. Gateway stateless checks pass (valid address, empty paymaster/deployment data, valid resource bounds, valid DA modes, signature length within limit).
5. Stateful checks: `validate_nonce` passes (`0 ≤ 1 ≤ max_allowed_nonce_gap`); `validate_by_mempool` passes (no duplicate nonce=1 tx, no fee escalation needed); `skip_stateful_validations` returns `true` because `account_tx_in_pool_or_recent_block(A)` is `true`. [5](#0-4) 

6. `run_validate_entry_point` is called with `validate: false` → `__validate__` is never invoked.
7. The attacker's invalid transaction is sent to the mempool via `mempool_client.add_tx`. [6](#0-5) 

8. The nonce=1 slot for account `A` is now occupied by the attacker's invalid transaction. The legitimate owner must pay a higher tip to replace it (fee escalation) or wait for the batcher to reject it.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-456)
```rust
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

**File:** crates/apollo_gateway/src/gateway.rs (L263-286)
```rust
        let nonce = stateful_transaction_validator
            .extract_state_nonce_and_run_validations(&executable_tx, self.mempool_client.clone())
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let proof_archive_handle = self
            .store_proof_and_spawn_archiving(proof_data, internal_tx.tx_hash, is_p2p)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let gateway_output = create_gateway_output(&internal_tx);

        let add_tx_args = AddTransactionArgsWrapper {
            args: AddTransactionArgs::new(internal_tx, nonce),
            p2p_message_metadata,
        };

        // Await as late as possible for proof archiving before sending the transaction to the
        // mempool.
        Self::await_proof_archiving(proof_archive_handle)
            .await
            .inspect_err(|e| metric_counters.record_add_tx_failure(e))?;

        let mempool_client_result = self.mempool_client.add_tx(add_tx_args).await;
```
