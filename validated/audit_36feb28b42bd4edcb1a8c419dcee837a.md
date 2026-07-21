### Title
`skip_stateful_validations` Admits Invoke Transactions with Invalid Signatures When Any Account Transaction Exists in Mempool — (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator is designed to skip `__validate__` (signature verification) for the first post-deploy-account invoke transaction. However, the check it uses — `account_tx_in_pool_or_recent_block` — returns `true` for **any** transaction for the account, not only a `deploy_account` transaction. An attacker who observes a victim's pending nonce-0 invoke transaction in the mempool can submit a nonce-1 invoke transaction with an arbitrary/invalid signature for the same account and have it admitted to the mempool without signature verification.

### Finding Description

`skip_stateful_validations` is called from `run_pre_validation_checks` and returns `true` (skip `__validate__`) when all three conditions hold:

1. The incoming transaction is an `Invoke` with `nonce == 1`
2. The account's on-chain nonce is `0`
3. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

The code comment states: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."*

This reasoning is flawed. `account_tx_in_pool_or_recent_block` checks whether the account has **any** transaction in the pool or recent block: [2](#0-1) 

A deployed account with on-chain nonce `0` that has submitted a valid nonce-0 **invoke** transaction satisfies condition 3. The attacker's nonce-1 invoke transaction is the one currently being submitted — it has not "passed validations" — yet the check returns `true` and `__validate__` is skipped.

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`: [3](#0-2) 

`validate_tx` in the blockifier immediately returns `Ok(None)` when `execution_flags.validate` is `false`, so the `__validate__` entry point (which performs signature verification) is never called: [4](#0-3) 

The mempool's own `validate_tx` only checks for duplicate hashes and nonce ordering — it does not verify signatures: [5](#0-4) 

The attacker's transaction therefore passes all gateway checks and is inserted into the mempool without any signature verification.

**Attack scenario:**

1. Alice deploys an account (on-chain nonce = 0).
2. Alice submits a valid invoke transaction with nonce = 0; it passes all validations and enters the mempool.
3. Attacker observes Alice's pending transaction (mempool is observable).
4. Attacker submits an invoke transaction for Alice's address with nonce = 1 and an arbitrary/invalid signature.
5. Gateway evaluates: `nonce == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(Alice) == true` ✓ → `skip_validate = true`.
6. `__validate__` is skipped; the attacker's transaction is admitted to the mempool.

### Impact Explanation

This matches the **High** impact scope: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

The gateway's admission invariant — every invoke transaction must pass `__validate__` unless it is the first post-deploy-account transaction for a brand-new account — is broken. Transactions with invalid signatures enter the mempool. The batcher will reject them at execution time (it creates `AccountTransaction` via `new_for_sequencing` which sets `validate: true`), so no unauthorized state changes occur. However, the attacker can flood the mempool with signature-invalid transactions for any account that has a pending nonce-0 invoke, consuming mempool capacity and potentially delaying legitimate transactions. [6](#0-5) 

### Likelihood Explanation

The preconditions are easily met in practice:

- Any deployed account that has never had a confirmed transaction (nonce = 0 on-chain) and has submitted its first invoke transaction is a valid target.
- The attacker only needs to observe the public mempool to identify such accounts and their addresses.
- No privileged access is required.

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **deploy_account** transaction is pending for the account. One approach is to expose a `deploy_account_tx_in_pool` query on the mempool that only returns `true` when the account's pending transaction is of type `DeployAccount`. Alternatively, the mempool state can track whether the account's first-ever transaction was a `DeployAccount`, and only set the skip flag in that case.

### Proof of Concept

```
// Precondition: Alice's account is deployed, on-chain nonce = 0.
// Step 1: Alice submits a valid invoke tx (nonce=0) → enters mempool.
// Step 2: Attacker constructs:
let attacker_tx = RpcInvokeTransactionV3 {
    sender_address: alice_address,
    nonce: Nonce(Felt::ONE),          // nonce = 1
    signature: TransactionSignature(vec![Felt::from(0xdeadbeef_u64)]), // invalid
    calldata: Calldata(vec![/* arbitrary */].into()),
    resource_bounds: valid_bounds,
    // ... other fields
};
// Step 3: Attacker submits attacker_tx to the gateway.
// Gateway path:
//   validate_state_preconditions → nonce 1 within gap ✓
//   validate_by_mempool          → no duplicate, nonce gap ok ✓
//   skip_stateful_validations    → nonce==1, account_nonce==0,
//                                  account_tx_in_pool_or_recent_block(alice)==true
//                                  → returns true (skip __validate__)
//   run_validate_entry_point     → execution_flags.validate = false
//                                  → __validate__ NOT called
// Result: attacker_tx admitted to mempool without signature check.
``` [7](#0-6) [8](#0-7)

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

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
```

**File:** crates/apollo_mempool/src/fee_mempool_test.rs (L1106-1128)
```rust
fn tx_from_address_exists(mut mempool: Mempool) {
    const ACCOUNT_ADDRESS: &str = "0x1";
    let account_address = contract_address!(ACCOUNT_ADDRESS);

    // Account is not known to the mempool.
    assert_eq!(mempool.account_tx_in_pool_or_recent_block(account_address), false);

    // The account has a tx in the mempool.
    add_tx(
        &mut mempool,
        &add_tx_input!(tx_hash: 1, address: ACCOUNT_ADDRESS, tx_nonce: 0, account_nonce: 0),
    );
    assert_eq!(mempool.account_tx_in_pool_or_recent_block(account_address), true);

    // The account has a staged tx in the mempool.
    let get_tx_response = mempool.get_txs(1).unwrap();
    assert_eq!(get_tx_response.first().unwrap().contract_address(), account_address);
    assert_eq!(mempool.account_tx_in_pool_or_recent_block(account_address), true);

    // The account has no txs in the pool, but is known through a committed block.
    commit_block(&mut mempool, [(ACCOUNT_ADDRESS, 1)], []);
    MempoolTestContentBuilder::new().with_pool([]).build().assert_eq(&mempool.content());
    assert_eq!(mempool.account_tx_in_pool_or_recent_block(account_address), true);
```
