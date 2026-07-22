### Title
Gateway `skip_stateful_validations` Bypasses `__validate__` Signature Check for Invoke Transactions When Any Mempool Entry Exists for the Sender - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`skip_stateful_validations` in the gateway's stateful validation path skips the `__validate__` entry-point (signature verification) for any invoke transaction with `nonce == 1` when `account_nonce == 0` and `account_tx_in_pool_or_recent_block` returns `true`. The proxy check `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction in the pool for that address — not exclusively a `deploy_account`. An attacker who observes a victim's pending `deploy_account` in the mempool can immediately submit an invoke with `nonce = 1` carrying an arbitrary/invalid signature. The gateway skips `__validate__`, admits the transaction, and the victim's legitimate `nonce = 1` invoke is subsequently rejected with `DuplicateNonce`.

### Finding Description

`skip_stateful_validations` is called inside `run_pre_validation_checks` after `validate_state_preconditions` and `validate_by_mempool` have already passed:

```
run_pre_validation_checks
  └─ validate_state_preconditions   (nonce range, resource bounds)
  └─ validate_by_mempool            (duplicate hash / nonce-too-old only)
  └─ skip_stateful_validations      ← decides whether __validate__ runs
``` [1](#0-0) 

The skip condition is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
}
``` [2](#0-1) 

When `skip_validate = true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is entirely skipped:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [4](#0-3) 

The proxy check `account_tx_in_pool_or_recent_block` is:

```rust
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [5](#0-4) 

`tx_pool.contains_account` returns `true` for **any** transaction in the pool for that address — including the victim's own `deploy_account` (nonce = 0). The code comment claims this is safe because "it means that either it has a deploy_account transaction or transactions with future nonces that passed validations," but this reasoning is circular: the skip mechanism itself is what allows future-nonce transactions to pass without `__validate__`, so the presence of any pool entry is not a reliable proxy for a legitimate `deploy_account`.

`validate_by_mempool` (called before the skip check) only rejects duplicate tx hashes and nonce-too-old; it does not verify signatures or require the account to exist:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [6](#0-5) 

`validate_nonce` in the gateway allows `nonce = 1` when `account_nonce = 0` because `max_allowed_nonce_gap = 200`: [7](#0-6) [8](#0-7) 

### Impact Explanation

An attacker can inject an unsigned/invalidly-signed invoke transaction (nonce = 1) for any victim address that has a pending `deploy_account` in the mempool. The gateway admits it without running `__validate__`. The victim's legitimate invoke (nonce = 1) is then rejected by the mempool with `DuplicateNonce`. After the batcher executes the `deploy_account` and then the attacker's invalid invoke, the invalid invoke fails at `__validate__` (the batcher always sets `validate: true` via `new_for_sequencing`), the transaction is rejected, and the mempool removes it. The attacker can immediately repeat the injection, creating a persistent denial-of-service against any new account's first post-deploy invoke. The broken invariant is: **every transaction admitted to the mempool must have passed account signature verification**. [9](#0-8) 

### Likelihood Explanation

Any new Starknet account that submits a `deploy_account` transaction is immediately vulnerable for the window between mempool admission of the `deploy_account` and its inclusion in a block. This window is observable on-chain (mempool is public). The attack requires no privileged access, no special contract, and no funds beyond the gas to submit the invalid invoke. The `max_allowed_nonce_gap = 200` config ensures the nonce-range check never blocks the attacker. [10](#0-9) 

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` proxy with a type-specific check: only skip `__validate__` when the pool contains a **`deploy_account`** transaction for the sender address (not any transaction). Alternatively, add a dedicated `deploy_account_in_pool(address)` query to the mempool that inspects the transaction type before returning `true`. This preserves the UX intent (deploy + invoke in one shot) while closing the signature-bypass path.

### Proof of Concept

```
1. Victim submits:
     deploy_account { sender: V, nonce: 0, valid_sig }
   → Gateway admits it; mempool pool now contains V's deploy_account.
   → account_tx_in_pool_or_recent_block(V) == true

2. Attacker submits (before victim's invoke):
     invoke { sender: V, nonce: 1, sig: [0xdeadbeef] }  ← invalid signature

3. Gateway stateful validation for attacker's invoke:
   a. validate_nonce:  0 <= 1 <= 200  ✓
   b. validate_by_mempool: no dup hash, nonce 1 >= 0  ✓
   c. skip_stateful_validations:
        tx.nonce == 1  ✓
        account_nonce == 0  ✓
        account_tx_in_pool_or_recent_block(V) == true  ✓  (victim's deploy_account is in pool)
        → returns true (skip __validate__)
   d. run_validate_entry_point with validate=false → __validate__ NOT called
   → Attacker's invalid invoke admitted to mempool.

4. Victim submits:
     invoke { sender: V, nonce: 1, valid_sig }
   → mempool.validate_tx → DuplicateNonce (nonce 1 already taken by attacker)
   → Victim's legitimate invoke REJECTED.

5. Batcher executes deploy_account(V) → V deployed, nonce = 1.
   Batcher executes attacker's invoke(V, nonce=1):
     - perform_pre_validation_stage: nonce 1 >= 1 ✓, fee bounds ✓
     - run_or_revert → validate_tx → __validate__ called → FAILS (invalid sig)
     - Transaction rejected; mempool notified; attacker's invoke removed.

6. Attacker repeats step 2 → persistent DoS on V's nonce-1 slot.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L287-296)
```rust
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
```

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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L17-18)
```json
  "gateway_config.static_config.stateful_tx_validator_config.max_allowed_nonce_gap": 200,
  "gateway_config.static_config.stateful_tx_validator_config.max_nonce_for_validation_skip": "0x1",
```
