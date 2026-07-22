### Title
Signature Verification Bypass via `skip_stateful_validations` — Any Attacker Can Inject an Unsigned Invoke Transaction for Any Undeployed Account - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`skip_stateful_validations` in the gateway's stateful validator skips the `__validate__` entry point (which performs signature verification) for any invoke transaction with `nonce == 1` when `account_nonce == 0` and `account_tx_in_pool_or_recent_block` returns `true`. The mempool check returns `true` for **any** transaction from that address — not specifically a `deploy_account`. An attacker who observes a victim's pending `deploy_account` in the mempool can submit a nonce=1 invoke for the victim's address with an arbitrary/invalid signature, and the gateway will admit it without ever calling `__validate__`.

### Finding Description

The UX feature is implemented in `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs, lines 429-461
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            // ...
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                // ...
        }
    }
    Ok(false)
}
``` [1](#0-0) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`, which causes `validate_tx` to return `Ok(None)` immediately without executing `__validate__`: [2](#0-1) [3](#0-2) 

The mempool check `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from that address — it does not filter for `deploy_account` specifically:

```rust
// crates/apollo_mempool/src/mempool.rs, lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [4](#0-3) 

The `validate_by_mempool` call that precedes the skip check only validates nonce ordering and fee escalation — it never checks signatures: [5](#0-4) 

### Impact Explanation

An attacker can submit an invoke transaction with an arbitrary/invalid signature for any address that has a pending `deploy_account` in the mempool. The transaction is admitted without signature verification. This occupies the victim's nonce=1 slot in the mempool. If fee escalation is disabled (`enable_fee_escalation = false`), the victim's legitimate nonce=1 invoke is then rejected with `MempoolError::DuplicateNonce`, effectively blocking the victim from executing their first post-deploy transaction. Even with fee escalation enabled, the victim is forced to pay a higher fee to displace the attacker's transaction.

This matches the **High** impact: "Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."

### Likelihood Explanation

The attack requires only:
1. Observing a pending `deploy_account` transaction in the mempool (publicly visible).
2. Submitting an invoke with `sender_address = victim`, `nonce = 1`, and any signature.

No privileged access, special keys, or on-chain funds are required. The condition (`nonce == 1 && account_nonce == 0 && any_tx_in_pool`) is trivially satisfiable whenever a new account is being deployed.

### Recommendation

Replace the generic `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** for the sender address is pending in the mempool. Add a dedicated mempool query such as `deploy_account_tx_in_pool(sender_address)` that only returns `true` when the pending transaction for that address at nonce=0 is of type `DeployAccount`. This closes the gap between the intended invariant ("the account's own deploy is pending") and the actual check ("any transaction from that address exists").

### Proof of Concept

1. Alice submits `deploy_account` for address `X` (nonce=0). It is accepted and sits in the mempool. `account_tx_in_pool_or_recent_block(X)` now returns `true`.

2. Attacker submits `invoke` with `sender_address = X`, `nonce = 1`, `calldata = [drain_alice_funds]`, `signature = [0x0, 0x0]`.

3. Gateway stateful validator evaluates `skip_stateful_validations`:
   - `tx.nonce() == 1` ✓
   - `account_nonce == 0` ✓
   - `account_tx_in_pool_or_recent_block(X)` → `true` ✓ (Alice's deploy_account is there)
   - Returns `true` → `execution_flags.validate = false`

4. `run_validate_entry_point` is called; `blockifier_validator.validate(account_tx)` is invoked with `validate = false`. `validate_tx` returns `Ok(None)` immediately. [3](#0-2) 

5. Attacker's invoke with invalid signature is admitted to the mempool at nonce=1 for address `X`.

6. Alice's legitimate nonce=1 invoke is subsequently rejected with `DuplicateNonce` (or must pay escalated fees to replace it). [6](#0-5)

### Citations

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

**File:** crates/apollo_mempool/src/mempool.rs (L768-773)
```rust
        if !self.config.static_config.enable_fee_escalation {
            if self.tx_pool.get_by_address_and_nonce(address, nonce).is_some() {
                return Err(MempoolError::DuplicateNonce { address, nonce });
            };

            return Ok(None);
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-69)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}

impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
        }
    }
```
