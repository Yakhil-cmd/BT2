### Title
`skip_stateful_validations` admits invoke transactions with arbitrary signatures for accounts with pending `deploy_account` — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the account's `__validate__` entry point (the only signature-verification step at the gateway layer) for any invoke transaction with `nonce = 1` targeting an account that has *any* transaction in the mempool. Because the check does not verify that the submitter is the account owner, any unprivileged attacker can inject invoke transactions with arbitrary signatures for any pre-funded account that has a pending `deploy_account` transaction, bypassing signature verification entirely at the admission layer.

### Finding Description

In `crates/apollo_gateway/src/stateful_transaction_validator.rs`, `skip_stateful_validations` (lines 429–461) returns `true` (skip validation) when all three conditions hold:

1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)`.
3. `account_nonce == Nonce(Felt::ZERO)`.
4. `mempool_client.account_tx_in_pool_or_recent_block(sender_address)` returns `true`. [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [2](#0-1) 

This causes `StatefulValidator::perform_validations` to return `Ok(())` after `perform_pre_validation_stage` without ever calling the account's `__validate__` entry point: [3](#0-2) 

The `account_tx_in_pool_or_recent_block` check is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

This returns `true` for any account that has **any** transaction in the pool — it does **not** verify that the submitter is the account owner, nor that the pooled transaction is specifically a `deploy_account`.

The remaining pre-validation checks (`validate_nonce`, `validate_by_mempool`) verify nonce range and duplicate detection but perform **no signature check**: [5](#0-4) 

**Attack scenario (step-by-step):**

1. Alice pre-funds account `A` with STRK (standard Starknet deploy flow) and submits a `deploy_account` transaction. The `deploy_account` enters the mempool; the on-chain nonce for `A` is `0`.
2. Attacker observes the mempool, sees Alice's `deploy_account` for `A`.
3. Attacker submits `Invoke(sender_address=A, nonce=1, signature=[0xdead, 0xbeef])` — an arbitrary, invalid signature.
4. Gateway stateless validation passes (valid format, valid resource bounds).
5. `validate_nonce`: `0 ≤ 1 ≤ max_allowed_nonce_gap` — passes.
6. `validate_by_mempool`: no duplicate hash, nonce in range — passes.
7. `skip_stateful_validations`: `nonce==1`, `account_nonce==0`, `account_tx_in_pool_or_recent_block(A)==true` → returns `true`.
8. `run_validate_entry_point` sets `validate=false`; `__validate__` is **never called**.
9. `perform_pre_validation_stage` runs: nonce incremented, fee bounds checked against Alice's pre-funded balance — passes.
10. Attacker's invoke is **admitted to the mempool** without any signature verification.

When the batcher later executes the attacker's transaction (after the `deploy_account` is committed), `__validate__` is called with `validate=true` (via `new_for_sequencing`), the invalid signature causes a revert, and the validation-step fee is charged to Alice's account — an unauthorized fee deduction Alice never authorized. [6](#0-5) 

### Impact Explanation

**Admission impact (High):** The gateway admits transactions with arbitrary, unverified signatures into the mempool. This directly satisfies: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

**Authorization/fee impact (Critical):** The admitted transaction is executed by the batcher against Alice's account. `__validate__` fails (invalid signature), the transaction reverts, and the validation-step fee is charged to Alice's pre-funded balance — an unauthorized transaction accepted through account validation logic, satisfying: *"Critical. Invalid or unauthorized Starknet transaction accepted through account validation, signature, nonce, chain id, fee/resource bound, paymaster, or account-deployment logic."*

Additionally, if the attacker submits with a higher tip/fee than Alice's legitimate invoke, the mempool's fee-escalation mechanism replaces Alice's transaction, causing her legitimate invoke to be dropped.

### Likelihood Explanation

The standard Starknet account deployment flow requires pre-funding the account address before submitting `deploy_account`. This means the pre-condition (pre-funded account + pending `deploy_account` in mempool) is met for **every new account deployment**. The attack window is the time between the `deploy_account` entering the mempool and being committed to a block. No special privileges are required — any actor who can observe the mempool can execute this attack.

### Recommendation

The `skip_stateful_validations` function should not skip `__validate__` based solely on the presence of *any* account transaction in the mempool. Concrete options:

1. **Restrict the skip to deploy_account transactions only:** Query the mempool for whether the pending transaction for `sender_address` at nonce `0` is specifically a `deploy_account`, not just any transaction.
2. **Run `__validate__` against the declared class hash:** When the account is not yet deployed, retrieve the `class_hash` from the pending `deploy_account` transaction and run `__validate__` against that class in a simulated context.
3. **Remove the skip entirely:** Accept the UX regression (users must submit `deploy_account` and wait for confirmation before submitting the first invoke) in exchange for correct authorization semantics.

### Proof of Concept

```
// Precondition: Alice has pre-funded account A and submitted deploy_account(A) to the mempool.
// account_nonce(A) == 0 in on-chain state.

// Attacker submits:
RpcInvokeTransactionV3 {
    sender_address: A,          // Alice's account
    nonce: 1,
    signature: [0xdead, 0xbeef], // arbitrary, invalid
    resource_bounds: { l2_gas: { max_amount: X, max_price_per_unit: Y } }, // valid bounds
    calldata: [...],
    ...
}

// Gateway flow:
// 1. stateless_tx_validator.validate() -> Ok(())  [format/size checks pass]
// 2. convert_rpc_tx_to_internal() -> Ok(internal_tx)  [tx_hash computed with chain_id + A + nonce=1]
// 3. extract_state_nonce_and_run_validations():
//    a. get_nonce_from_state(A) -> Nonce(0)
//    b. validate_nonce: 0 <= 1 <= max_gap -> Ok(())
//    c. validate_by_mempool: no dup hash, nonce valid -> Ok(())
//    d. skip_stateful_validations: nonce==1, account_nonce==0,
//       account_tx_in_pool_or_recent_block(A)==true -> returns true
//    e. run_validate_entry_point(skip_validate=true):
//       execution_flags.validate = false
//       perform_pre_validation_stage: nonce bumped, fee bounds ok, balance ok -> Ok(())
//       __validate__ NOT called -> Ok(())
// 4. mempool.add_tx(attacker_invoke) -> Ok(())  [ADMITTED]

// Later, batcher executes:
// deploy_account(A) executed -> A deployed, nonce(A) = 1
// attacker_invoke executed:
//   perform_pre_validation_stage: nonce==1 ok
//   __validate__(signature=[0xdead,0xbeef]) -> FAILS (invalid signature)
//   transaction reverted, validation fee charged to Alice's account A
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L310-312)
```rust
        let strict_nonce_check = false;
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-94)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;

                // Post validations.
                PostValidationReport::verify(
                    &tx_context,
                    &actual_cost,
                    tx.execution_flags.charge_fee,
                )?;

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
