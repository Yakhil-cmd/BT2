### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary
The `skip_stateful_validations` function unconditionally bypasses the `__validate__` entry-point call (the only on-chain signature check) for any invoke transaction whose nonce is 1 and whose sender address appears anywhere in the mempool. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a second invoke with nonce=1 from the same address carrying an **arbitrary/invalid signature**. The gateway admits it without signature verification, placing it in the mempool where it can displace the victim's legitimate invoke via fee escalation.

### Finding Description

**Validation flow** (`extract_state_nonce_and_run_validations`):

```
account_nonce = get_nonce_from_state(sender)
skip_validate = run_pre_validation_checks(tx, account_nonce, mempool)
run_validate_entry_point(tx, skip_validate)   // ← skipped when true
```

`run_pre_validation_checks` calls `skip_stateful_validations`, which returns `true` when all three conditions hold:

1. Transaction type is `Invoke`
2. `tx.nonce() == Nonce(Felt::ONE)` (nonce = 1)
3. `account_nonce == Nonce(Felt::ZERO)` (account not yet deployed)
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true` [1](#0-0) 

When `skip_validate = true`, `run_validate_entry_point` sets `ExecutionFlags { validate: false }`: [2](#0-1) 

Inside the blockifier, `validate_tx` returns `Ok(None)` immediately when `execution_flags.validate == false`, so the `__validate__` entry point — the only place the account contract checks the ECDSA signature — is never called: [3](#0-2) 

**The mempool's `validate_tx` does not check signatures either.** `ValidationArgs` carries only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price`: [4](#0-3) 

The mempool's `validate_tx` only checks for duplicate hashes and nonce/fee-escalation rules: [5](#0-4) 

**`account_tx_in_pool_or_recent_block` is not deploy-account-specific.** It returns `true` for any transaction from the address, including a deploy_account submitted by the victim: [6](#0-5) 

The comment in `skip_stateful_validations` claims "it is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations." This reasoning is correct for the legitimate UX case but does not prevent a third party from submitting an invalid invoke for the same address.

### Impact Explanation

**Broken invariant**: The gateway must not admit transactions whose signatures have not been verified.

**Attack path**:
1. Victim Alice broadcasts `deploy_account` (nonce 0). It enters the mempool.
2. Attacker Bob submits `invoke` (nonce 1, sender = Alice's address, **garbage signature**, fee > Alice's planned invoke fee).
3. Gateway: `account_nonce == 0`, `tx.nonce() == 1`, `account_tx_in_pool_or_recent_block(Alice) == true` → `skip_validate = true` → `__validate__` is never called → Bob's invalid invoke is **admitted to the mempool**.
4. Alice submits her legitimate invoke (nonce 1). The mempool's fee-escalation rule requires her fee to exceed Bob's. If she cannot or does not, her invoke is rejected.
5. The batcher later executes Bob's invalid invoke with `validate = true`; `__validate__` fails; the transaction is rejected. **No fee is charged** for transactions that fail at the validate stage in Starknet.
6. Alice's valid invoke was never included; she must resubmit at a higher fee.

The attack is **economically free** for the attacker: because the invalid invoke fails at `__validate__` (not `__execute__`), no fee is deducted from Bob's account. Bob can repeat this for every new `deploy_account` he observes, systematically griefing new account deployments.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

- Requires no privileges; any observer of the public mempool can execute this.
- The triggering condition (`deploy_account` in mempool + nonce=0 on-chain) is the normal state for every new account deployment.
- The attack is trivially scripted: watch for `deploy_account` transactions, immediately submit a spoofed invoke with a higher fee.

### Recommendation

1. **Verify the mempool entry is specifically a `deploy_account`**: `account_tx_in_pool_or_recent_block` is not type-aware. The check should be replaced with a dedicated `deploy_account_tx_in_pool(sender_address)` query that only returns `true` when a `DeployAccount` transaction for that address is present.

2. **Alternatively, perform a lightweight signature check even when skipping `__validate__`**: The gateway already has the account's class hash and constructor arguments (from the deploy_account in the mempool). A stateless ECDSA check against the expected public key could be performed without running the full entry point.

### Proof of Concept

```
// Step 1: Alice submits deploy_account (nonce=0).
// Mempool now contains: { Alice: deploy_account(nonce=0) }

// Step 2: Bob submits invoke with garbage signature.
let attacker_invoke = InvokeTransactionV3 {
    sender_address: alice_address,
    nonce: Nonce(Felt::ONE),          // nonce = 1
    signature: TransactionSignature(vec![Felt::ZERO, Felt::ZERO]), // invalid
    resource_bounds: AllResourceBounds {
        l2_gas: ResourceBounds {
            max_price_per_unit: alice_planned_fee * 2, // outbid Alice
            ..
        },
        ..
    },
    ..
};
gateway.add_invoke_transaction(attacker_invoke).await; // succeeds

// Gateway path:
//   account_nonce = 0  (Alice not deployed yet)
//   tx.nonce() = 1
//   account_tx_in_pool_or_recent_block(alice) = true  (deploy_account is there)
//   → skip_validate = true
//   → run_validate_entry_point called with validate=false
//   → __validate__ never executed
//   → invalid invoke admitted to mempool

// Step 3: Alice submits her legitimate invoke (nonce=1).
// Mempool rejects it: Bob's invalid invoke already occupies (Alice, nonce=1)
// with a higher fee; Alice must escalate her fee to displace it.

// Step 4: Batcher executes Bob's invalid invoke with validate=true.
// __validate__ fails → transaction rejected, no fee charged to Bob.
// Alice's invoke was never included.
```

The root cause is in `skip_stateful_validations` at: [1](#0-0) 

combined with `run_validate_entry_point` setting `validate: !skip_validate`: [7](#0-6)

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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L999-1001)
```rust
        if !self.execution_flags.validate {
            return Ok(None);
        }
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
