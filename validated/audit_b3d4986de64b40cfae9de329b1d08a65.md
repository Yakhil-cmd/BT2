### Title
Gateway `skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures When Sender Has a Pending Deploy-Account Transaction - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator skips the `__validate__` entry-point call for invoke transactions with nonce=1 when the sender address has any transaction in the mempool or a recent block. Because `__validate__` is the only place where the transaction signature is verified, an attacker can submit an invoke transaction with an **invalid signature** for any account that has a pending deploy-account transaction in the mempool, and the gateway will admit it without signature verification.

### Finding Description

`extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which calls `skip_stateful_validations`: [1](#0-0) 

`skip_stateful_validations` returns `true` (skip validation) when all four conditions hold: [2](#0-1) 

1. Transaction is `Invoke`
2. `tx.nonce() == 1`
3. `account_nonce == 0` (account not yet deployed in committed state)
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`

When `skip_validate = true`, `run_validate_entry_point` constructs `ExecutionFlags { validate: false }`: [3](#0-2) 

This propagates into `StatefulValidator::perform_validations`, which short-circuits before calling `__validate__`: [4](#0-3) 

And into `AccountTransaction::validate_tx`, which also short-circuits: [5](#0-4) 

`__validate__` is the account contract's signature-verification entry point. With `validate: false`, the signature is **never checked** at the gateway.

The mempool check `account_tx_in_pool_or_recent_block` only verifies that the sender address has *any* transaction in the pool or a recent block — not specifically a deploy-account transaction, and certainly not that the incoming invoke transaction carries a valid signature: [6](#0-5) 

**Attack path:**

1. Victim submits a `deploy_account` tx (`sender_address = victim_addr`, nonce=0). The victim's address now appears in the mempool.
2. Attacker submits an `invoke` tx with `sender_address = victim_addr`, `nonce = 1`, and an **arbitrary/invalid signature**.
3. Gateway: `account_nonce == 0`, `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(victim_addr) == true` → `skip_validate = true` → `__validate__` is **not called** → transaction is admitted to the mempool.
4. Batcher retrieves the transaction and wraps it with `new_for_sequencing`, which always sets `validate: true`: [7](#0-6) 

5. At execution time `__validate__` is called and the transaction fails (invalid signature), but it has already consumed a mempool slot and block space.

The critical asymmetry: the gateway checks whether the *sender address* has a pending deploy-account tx, but does **not** verify the *signature* of the incoming invoke tx. This is the direct analog of the StakedToken bug — the gateway validates one party (the existence of a deploy-account tx for the address) but not the other (the authenticity of the invoke tx itself).

### Impact Explanation

**High — Mempool/gateway admission accepts invalid transactions before sequencing.**

- Any invoke transaction with an invalid signature can be admitted to the mempool as long as the target account has a pending deploy-account transaction.
- The attacker can submit such a transaction with a **higher fee** than the victim's legitimate nonce-1 invoke tx. The mempool's fee-escalation logic will then replace the victim's valid tx with the attacker's invalid one, permanently blocking the victim's first post-deployment invoke until the attacker's tx is executed and fails.
- Block space is wasted on transactions that are guaranteed to fail at execution.
- The attack is repeatable: after the invalid tx fails and is evicted, the attacker can immediately submit another one.

### Likelihood Explanation

The mempool is observable. Any participant can watch for deploy-account transactions and immediately submit a spoofed nonce-1 invoke for the same sender address. No privileged access is required. The only precondition is that the victim's account address is pre-funded (which is always true for a valid deploy-account flow). Likelihood is **medium-high**.

### Recommendation

`skip_stateful_validations` should verify that the transaction in the mempool for the sender address is specifically a **deploy-account** transaction, not just any transaction. Alternatively, even when skipping the `__validate__` entry-point call (because the account contract does not yet exist on-chain), the gateway should perform an off-chain signature pre-check using the expected public key from the deploy-account transaction's constructor calldata, or reject the skip entirely and rely on the mempool's fee-escalation ordering to sequence the deploy-account before the invoke.

### Proof of Concept

```
// Setup: victim pre-funds their account address and submits deploy_account tx
victim_addr = compute_contract_address(class_hash, salt, ctor_calldata)
fund(victim_addr, 1000 STRK)
gateway.add_tx(DeployAccount { sender_address: victim_addr, nonce: 0, signature: valid_sig, ... })
// mempool now contains victim_addr → deploy_account(nonce=0)

// Attacker submits invoke with invalid signature
gateway.add_tx(Invoke {
    sender_address: victim_addr,
    nonce: 1,
    signature: [0xdead, 0xbeef],   // invalid
    resource_bounds: { l2_gas: { max_amount: 1e6, max_price_per_unit: 1e9 } },
    calldata: [...],
})

// Gateway path:
//   account_nonce = state.get_nonce(victim_addr) = 0   ✓
//   tx.nonce() = 1                                      ✓
//   account_tx_in_pool_or_recent_block(victim_addr) = true  ✓
//   → skip_validate = true
//   → ExecutionFlags { validate: false }
//   → __validate__ NOT called
//   → transaction admitted to mempool  ← BUG

// Batcher execution:
//   1. execute deploy_account(nonce=0)  → account deployed
//   2. execute attacker's invoke(nonce=1) with validate=true
//      → __validate__ called → INVALID_SIGNATURE → tx reverts
//      → victim's legitimate nonce-1 tx was displaced by fee escalation
//         and is never executed
```

The root cause is in `skip_stateful_validations` at: [8](#0-7) 

which checks the sender's mempool presence but never validates the incoming transaction's signature, mirroring the StakedToken pattern of checking the caller while ignoring the owner.

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
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
