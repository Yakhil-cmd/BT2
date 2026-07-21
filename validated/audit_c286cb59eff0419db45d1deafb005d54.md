### Title
Gateway Skips `__validate__` for Invoke Transactions at Nonce 1 When Any Prior Transaction Exists for the Sender Address — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call for any Invoke V3 transaction with `tx_nonce == 1` when `account_nonce == 0` and `account_tx_in_pool_or_recent_block` returns `true`. The mempool's `account_tx_in_pool_or_recent_block` check is keyed only on the **sender address**, not on whether the pending transaction is actually a `DeployAccount` for that address. An attacker can exploit this by first submitting a valid transaction from their own account at the target address (or any address that happens to share the same address), causing the mempool to record that address as "known", and then submitting a crafted Invoke with `nonce=1` for the victim's not-yet-deployed account — bypassing signature/`__validate__` entirely and getting the transaction admitted to the mempool without any cryptographic authorization check.

### Finding Description

The `skip_stateful_validations` function is designed to improve UX for the deploy-account + invoke pattern: when a user sends a `DeployAccount` and an `Invoke` (nonce=1) simultaneously, the account doesn't exist yet, so `__validate__` would fail. The gateway skips `__validate__` if:

1. The transaction is an Invoke with `tx_nonce == Nonce(Felt::ONE)`
2. The on-chain `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
3. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

The critical flaw is in condition 3. `account_tx_in_pool_or_recent_block` returns `true` if **any** transaction from that address is in the pool or was recently committed — it does not verify that the pending transaction is specifically a `DeployAccount`: [2](#0-1) 

The mempool state retains an address permanently after any transaction from it is committed, as confirmed by the test comment: *"Note that in the future, the Mempool's state may be periodically cleared from records of old committed transactions."* [3](#0-2) 

When `skip_validate` is `true`, `run_validate_entry_point` is called with `validate: false`, meaning the blockifier's `validate_tx` returns `Ok(None)` immediately without executing `__validate__`: [4](#0-3) [5](#0-4) 

The attack path:

1. Attacker identifies a target address `A` that has `account_nonce == 0` on-chain (not yet deployed).
2. Attacker ensures `account_tx_in_pool_or_recent_block(A)` returns `true`. This can happen if:
   - The attacker previously submitted any transaction from address `A` that was committed (the mempool state retains the address indefinitely after commit).
   - Or the attacker submits a valid transaction from `A` (e.g., a `DeployAccount` that they control, or any other transaction that passes nonce validation) to seed the mempool state.
3. Attacker submits an Invoke transaction with `sender_address = A`, `nonce = 1`, arbitrary calldata, and an **invalid or empty signature**.
4. The gateway sees: `tx_nonce == 1`, `account_nonce == 0`, `account_tx_in_pool_or_recent_block(A) == true` → sets `skip_validate = true`.
5. The `__validate__` entry point is never called. The transaction is admitted to the mempool and will be executed during block production.

The nonce check in `validate_nonce` passes because `nonce=1` is within the allowed gap range (`account_nonce=0 <= 1 <= 0 + max_allowed_nonce_gap`): [6](#0-5) 

### Impact Explanation

**Critical / High.** An attacker can submit an Invoke transaction with an arbitrary signature (or no signature) for any account address that has ever appeared in the mempool, as long as the account's on-chain nonce is still 0. The transaction bypasses the `__validate__` entry point entirely and is admitted to the mempool. When the batcher sequences it, the blockifier will execute it with `strict_nonce_check=false` and the transaction will run the account's `__execute__` function with attacker-controlled calldata — enabling unauthorized fund transfers, storage manipulation, or other state changes on behalf of the victim account.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing"* and potentially **Critical**: *"Invalid or unauthorized Starknet transaction accepted through account validation, signature … logic."*

### Likelihood Explanation

The precondition — that `account_tx_in_pool_or_recent_block` returns `true` for the target address — is easy to satisfy:
- Any address that has ever had a transaction committed to a block will permanently satisfy this condition (the mempool state is never cleared).
- An attacker can also seed the condition by submitting a valid `DeployAccount` for a fresh address they control, then immediately submitting the malicious Invoke for the same address.
- The window is not time-limited; the mempool state persists indefinitely.

### Recommendation

The `skip_stateful_validations` check must verify that the pending transaction in the mempool is specifically a `DeployAccount` for the same sender address, not merely that **any** transaction from that address exists. The fix should query the mempool for a pending `DeployAccount` transaction specifically:

```rust
// Instead of:
mempool_client.account_tx_in_pool_or_recent_block(tx.sender_address())

// Use a dedicated check:
mempool_client.has_pending_deploy_account(tx.sender_address())
```

Alternatively, the gateway could check whether the account contract code exists at the sender address before deciding to skip validation — if the class hash at the address is zero (undeployed), only skip `__validate__` if a `DeployAccount` with matching address is confirmed pending.

### Proof of Concept

```
1. Let target_address = 0xDEAD (account_nonce = 0 on-chain, never deployed)
2. Attacker submits any valid transaction from 0xDEAD that gets committed
   (e.g., a DeployAccount that the attacker controls, then lets it commit)
   → mempool.state.contains_account(0xDEAD) == true permanently
3. Attacker crafts:
     RpcInvokeTransactionV3 {
       sender_address: 0xDEAD,
       nonce: 1,
       calldata: [transfer_all_funds_to_attacker],
       signature: [],   // empty / invalid
       resource_bounds: valid_bounds,
       ...
     }
4. Gateway stateless validation passes (no signature format check enforced)
5. Gateway stateful validation:
   - account_nonce = 0 (from state)
   - validate_nonce: 0 <= 1 <= 0+gap → OK
   - skip_stateful_validations:
       tx_nonce == 1 ✓, account_nonce == 0 ✓,
       account_tx_in_pool_or_recent_block(0xDEAD) == true ✓
       → returns true (skip __validate__)
   - run_validate_entry_point called with validate=false → no __validate__ call
6. Transaction admitted to mempool with tx_hash H
7. Batcher sequences H → blockifier executes __execute__ with attacker calldata
   → unauthorized state change on victim account
``` [1](#0-0) [2](#0-1) [7](#0-6)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L286-297)
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
        }
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

**File:** crates/apollo_mempool/src/mempool_flow_tests.rs (L338-344)
```rust
    let nonces = [(address, 1)];
    commit_block(&mut mempool, nonces, []);
    // Assert: Mempool state still contains the address, even though the transaction was committed.
    // Note that in the future, the Mempool's state may be periodically cleared from records of old
    // committed transactions. Mirroring this behavior may require a modification of this test.
    assert!(mempool.account_tx_in_pool_or_recent_block(account_address));
}
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L992-1001)
```rust
impl ValidatableTransaction for AccountTransaction {
    fn validate_tx(
        &self,
        state: &mut dyn State,
        tx_context: Arc<TransactionContext>,
        remaining_gas: &mut GasCounter,
    ) -> TransactionExecutionResult<Option<CallInfo>> {
        if !self.execution_flags.validate {
            return Ok(None);
        }
```
