### Title
Gateway Admits Invoke Transactions with Arbitrary Signatures via `skip_stateful_validations` Bypass — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point (i.e., signature verification) for any invoke transaction whose nonce is exactly `1` and whose sender account has nonce `0` on-chain, provided the mempool reports that the account already has a transaction in the pool or a recent block. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a second invoke transaction for the same address with a completely arbitrary (invalid) signature and a higher fee. The gateway admits this transaction without ever verifying the signature. The attacker's transaction then displaces the victim's legitimate post-deploy invoke via fee escalation, and when the batcher later executes it, the `__validate__` entry point fails, burning the victim's fee balance and permanently removing the victim's legitimate invoke from the queue.

### Finding Description

**Two-step UX feature and its gap**

The gateway implements a UX shortcut so that users can broadcast `deploy_account` + `invoke(nonce=1)` simultaneously without waiting for the deploy to be mined. The shortcut lives in `skip_stateful_validations`: [1](#0-0) 

The condition is:
- transaction type is `Invoke`
- `tx.nonce() == Nonce(Felt::ONE)` (nonce = 1)
- `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed on-chain)
- `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

When all four hold, `skip_validate` is set to `true`, and `run_validate_entry_point` is called with `validate: false`: [2](#0-1) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is entirely skipped and the function returns `Ok(())`: [3](#0-2) 

**What `account_tx_in_pool_or_recent_block` actually checks**

The mempool check is: [4](#0-3) 

It returns `true` if the address appears in `state.staged`, `state.committed`, or `tx_pool`. The `deploy_account` transaction submitted by the victim satisfies `tx_pool.contains_account` the moment it is added to the mempool — before it is ever executed. [5](#0-4) 

**Attacker-controlled fields that bypass the invariant**

Because `skip_validate=true` suppresses the `__validate__` call, the `signature` field of the attacker's invoke transaction is never verified at admission time. The attacker can supply any byte string as the signature. The only checks that still run are stateless size/format checks and the nonce-range check: [6](#0-5) 

**Fee escalation displaces the victim's legitimate transaction**

The mempool allows a transaction at `(address, nonce)` to be replaced by a new one with a higher fee (fee escalation). The attacker submits the invalid invoke with a tip/fee higher than the victim's legitimate invoke. The mempool replaces the victim's transaction with the attacker's: [7](#0-6) 

**Execution-time failure burns victim's fee**

At sequencing time, `AccountTransaction::new_for_sequencing` always sets `validate: true`: [8](#0-7) 

The attacker's transaction therefore reaches `__validate__` during block execution, fails signature verification, reverts, and the victim's newly-deployed account is charged the validation fee. The victim's legitimate invoke, having been evicted from the mempool by fee escalation, is gone.

### Impact Explanation

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

Concretely:
- An invalid transaction (one whose `__validate__` will always fail) is admitted to the mempool.
- The victim's valid transaction is evicted via fee escalation.
- The victim's account is charged fees for the attacker's failed validation.
- The victim's intended post-deploy action never executes.

### Likelihood Explanation

- The attack requires no privileged access; any network participant can submit transactions to the gateway.
- The victim's `deploy_account` transaction is publicly visible in the mempool and broadcast via P2P to all sequencer nodes.
- The attack window is the entire time between the victim's `deploy_account` entering the mempool and being included in a block — typically multiple seconds to minutes.
- The attacker only needs to know the victim's contract address (derivable from the public `deploy_account` fields: `class_hash`, `salt`, `constructor_calldata`).
- The only cost to the attacker is the gas fee paid for the invalid transaction, which is zero because the attacker's account is never charged (the fee is charged to the victim's newly-deployed account).

### Recommendation

1. **Do not skip signature verification unconditionally.** The `skip_stateful_validations` shortcut should be removed or replaced with a mechanism that still verifies the signature without requiring the account to be deployed. One approach: run `__validate__` against a simulated state that includes the result of the pending `deploy_account` (i.e., apply the deploy_account's state diff before validating the invoke).

2. **Alternatively, restrict the skip to transactions submitted in the same request/bundle as the deploy_account**, so the gateway can cryptographically associate the two. This prevents a third party from injecting a fake invoke.

3. **At minimum, add a mempool-level guard** that rejects any incoming transaction at `(address, nonce=1)` when the account is not yet deployed and the existing nonce-1 transaction in the pool was admitted under `skip_validate=true`, preventing fee-escalation replacement by unauthenticated transactions.

### Proof of Concept

```
1. Victim calls gateway.add_tx(deploy_account for address A, class_hash=C, salt=S)
   → deploy_account enters mempool; account_tx_in_pool_or_recent_block(A) = true

2. Attacker observes the deploy_account in the mempool (public P2P broadcast).
   Attacker derives address A from (C, S, constructor_calldata).

3. Attacker calls gateway.add_tx(invoke {
       sender_address: A,
       nonce: 1,
       signature: [0xdeadbeef],   // arbitrary invalid signature
       tip: victim_tip + 1,       // higher fee to trigger fee escalation
       calldata: [drain_calldata]
   })

4. Gateway stateful validator:
   - get_nonce_from_state(A) → Nonce(0)          // account not deployed
   - validate_nonce: 0 <= 1 <= max_gap → OK
   - validate_by_mempool → OK (nonce not too old)
   - skip_stateful_validations:
       tx.nonce() == 1 ✓, account_nonce == 0 ✓,
       account_tx_in_pool_or_recent_block(A) == true ✓
       → skip_validate = true
   - run_validate_entry_point(skip_validate=true):
       ExecutionFlags { validate: false, ... }
       → __validate__ NOT called
       → Ok(())
   → Transaction admitted to mempool.

5. Mempool fee escalation: attacker's tip > victim's tip
   → victim's legitimate invoke(nonce=1) is evicted.

6. Batcher sequences the block:
   - deploy_account(A) executes → A is deployed, nonce becomes 1.
   - attacker's invoke(A, nonce=1) executes:
       new_for_sequencing → ExecutionFlags { validate: true }
       __validate__ called → signature [0xdeadbeef] fails
       → transaction reverts, A is charged validation fee.

7. Victim's legitimate invoke is gone from the mempool.
   Victim's account has lost funds to the validation fee.
   Victim's intended action never executes.
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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

**File:** crates/apollo_mempool/src/mempool.rs (L756-758)
```rust
    /// Validates whether the incoming transaction may replace an existing one at the same
    /// `(address, nonce)` via fee escalation, without mutating any state. Returns the existing
    /// transaction to be replaced when a valid replacement exists, `None` when there is nothing to
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
