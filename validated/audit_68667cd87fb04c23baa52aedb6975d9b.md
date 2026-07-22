### Title
`skip_stateful_validations` Admits Invoke Transactions with Arbitrary Signatures by Skipping `__validate__` for Nonce-1 Transactions - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point call (which is the only place signature verification occurs) for any Invoke transaction with `nonce == 1` whose sender address appears in the mempool or a recent block. An unprivileged attacker who observes a victim's `deploy_account` transaction in the mempool can immediately submit a crafted Invoke with `nonce = 1`, an arbitrary/empty signature, and arbitrary calldata targeting the victim's address. The gateway admits this transaction without ever verifying the signature, violating the invariant that every admitted Invoke must carry a valid signature.

---

### Finding Description

The gateway stateful validation path in `extract_state_nonce_and_run_validations` calls `run_pre_validation_checks`, which in turn calls `skip_stateful_validations`. If that function returns `true`, `run_validate_entry_point` is called with `validate: false`, meaning the blockifier's `StatefulValidator::validate` path is bypassed entirely. [1](#0-0) 

The skip condition is: [2](#0-1) 

The three conditions that trigger the skip are:
1. The transaction is an `Invoke`.
2. `tx.nonce() == Nonce(Felt::ONE)` — hardcoded to nonce 1.
3. `account_nonce == Nonce(Felt::ZERO)` — the account is not yet deployed on-chain.
4. `account_tx_in_pool_or_recent_block(sender_address)` returns `true`.

The fourth check is implemented as: [3](#0-2) 

This returns `true` if the address has **any** transaction in the pool or is known from a committed block. It does **not** verify that the existing transaction is a `deploy_account`, nor does it verify any relationship between the existing transaction's signer and the incoming Invoke's signer.

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce ordering, duplicate hashes, and fee-escalation rules — it performs no signature verification: [4](#0-3) 

When `skip_validate = true`, the `ExecutionFlags` are set with `validate: false`: [5](#0-4) 

And the blockifier's `StatefulValidator::perform_validations` returns immediately without calling `__validate__`: [6](#0-5) 

---

### Impact Explanation

An attacker can submit an Invoke transaction with a completely fake signature for any account address that has a `deploy_account` (or any other transaction) in the mempool. The gateway admits this transaction without signature verification. Once admitted, the attacker's Invoke occupies the `(address, nonce=1)` slot in the mempool. If fee escalation is disabled, the victim's legitimate nonce-1 Invoke is subsequently rejected with `DuplicateNonce`. If fee escalation is enabled, the attacker can outbid the victim's legitimate Invoke and replace it. In either case, the victim's first post-deploy transaction is blocked or displaced. The attacker's Invoke will fail during batcher execution (the batcher creates its own `AccountTransaction` with `validate: true`), but the damage — blocking the victim's nonce-1 slot — has already occurred.

This matches: **High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

---

### Likelihood Explanation

The trigger is fully unprivileged. Any observer of the public mempool can see a `deploy_account` transaction and immediately race to submit a crafted Invoke. The conditions are deterministic and require no special knowledge beyond the victim's account address (which is derivable from the `deploy_account` parameters). The default configuration has `max_nonce_for_validation_skip: Nonce(Felt::ONE)`, confirming this path is active in production. [7](#0-6) 

---

### Recommendation

The `skip_stateful_validations` function must verify that the existing mempool transaction for the sender address is specifically a `deploy_account` transaction, not just any transaction. Additionally, the check should confirm that the `deploy_account`'s computed contract address matches the Invoke's `sender_address`. This prevents an attacker from exploiting the skip window using a victim's `deploy_account` as the qualifying anchor.

Concretely, `account_tx_in_pool_or_recent_block` should be replaced with a stricter query such as `deploy_account_tx_in_pool(sender_address)` that returns `true` only when a `deploy_account` transaction for exactly that address is pending.

---

### Proof of Concept

1. Victim submits `deploy_account` for address `A` (nonce 0, valid signature). It enters the mempool. `account_tx_in_pool_or_recent_block(A)` now returns `true`.

2. Attacker submits `Invoke { sender_address: A, nonce: 1, calldata: <arbitrary>, signature: [] }`.

3. Gateway stateful validation:
   - `get_nonce_from_state(A)` → `Nonce(0)` (account not yet on-chain). ✓
   - `validate_nonce`: `0 <= 1 <= 0 + 200` ✓
   - `validate_by_mempool`: nonce gap check passes (nonce 1 > account nonce 0, within gap). ✓
   - `skip_stateful_validations`: `nonce == 1` ✓, `account_nonce == 0` ✓, `account_tx_in_pool_or_recent_block(A)` → `true` ✓ → returns `true`.
   - `run_validate_entry_point` called with `skip_validate = true` → `validate: false` → `__validate__` is **never called**.

4. Attacker's Invoke is admitted to the mempool at slot `(A, nonce=1)`.

5. Victim submits their legitimate `Invoke { sender_address: A, nonce: 1, calldata: <real>, signature: <valid> }`. Mempool rejects it: `DuplicateNonce { address: A, nonce: 1 }`.

6. Batcher executes `deploy_account` (nonce 0) → account `A` deployed. Then tries attacker's Invoke (nonce 1) → `__validate__` called → fails (empty signature) → transaction rejected by batcher.

7. Victim's nonce-1 Invoke was never executed. Victim must resubmit, racing the attacker again.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L175-178)
```rust
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
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
