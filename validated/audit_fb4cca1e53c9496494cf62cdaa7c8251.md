### Title
Gateway Signature Validation Bypass via `skip_stateful_validations` Front-Running — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator skips the blockifier `__validate__` entry point (account signature check) for any invoke transaction with `nonce == 1` when `account_tx_in_pool_or_recent_block` returns `true` for the sender address. Because that check returns `true` for **any** transaction from the address in the mempool — not exclusively a `deploy_account` — an attacker who observes a victim's `deploy_account` in the mempool can front-run the victim's paired invoke by submitting an invoke with an **invalid signature** that bypasses gateway-level signature validation and is admitted to the mempool.

---

### Finding Description

`skip_stateful_validations` is designed to improve UX for the `deploy_account + invoke` pattern: when a new account's `deploy_account` is pending, the immediately following invoke (nonce=1) cannot be validated by the account's `__validate__` function because the account does not yet exist on-chain. The gateway therefore skips the blockifier validation step when it believes a `deploy_account` is in flight.

The guard used is:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 437–456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

`account_tx_in_pool_or_recent_block` is implemented as:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 697–700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

This returns `true` whenever **any** transaction from `account_address` is in the pool — including the victim's own `deploy_account`. The code comment acknowledges the assumption:

> "It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."

The assumption is broken: the transaction currently being validated has **not** yet passed validations. An attacker can exploit the presence of the victim's `deploy_account` to satisfy the check for their own malicious invoke.

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 310–312
let strict_nonce_check = false;
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

Inside `StatefulValidator::perform_validations`, when `validate == false` the `__validate__` call is skipped entirely:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs  lines 79–81
if !tx.execution_flags.validate {
    return Ok(());
}
``` [4](#0-3) 

The stateless validator only checks **signature length**, not signature validity:

```rust
// crates/apollo_gateway/src/stateless_transaction_validator.rs  lines 186–194
let signature_length = signature.0.len();
if signature_length > self.config.max_signature_length {
    return Err(StatelessTransactionValidatorError::SignatureTooLong { ... });
}
``` [5](#0-4) 

The mempool's `validate_tx` checks only duplicate hash, nonce ordering, and fee escalation — not signature content:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 402–408
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [6](#0-5) 

`ValidationArgs` carries no signature field:

```rust
// crates/apollo_mempool_types/src/mempool_types.rs  lines 50–57
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
``` [7](#0-6) 

---

### Impact Explanation

**High — Mempool/gateway admission accepts an invalid transaction before sequencing.**

An invoke transaction carrying an attacker-controlled, cryptographically invalid signature is admitted to the mempool without any signature check. The legitimate user's paired invoke (nonce=1) is then either rejected as `DuplicateNonce` or must outbid the attacker via fee escalation. The attacker's invalid invoke will fail during block execution (the OS-level `__validate__` is not skipped), but the damage is already done: the victim's intended invoke is displaced or delayed, and the victim's account is deployed without the intended first action executing.

---

### Likelihood Explanation

The attack requires only:
1. Monitoring the public mempool for `deploy_account` transactions (trivially observable).
2. Computing the deterministic contract address from the `deploy_account` parameters (class_hash, constructor_calldata, salt, deployer_address — all visible in the transaction).
3. Submitting an invoke with nonce=1 from that address with an invalid signature and a fee high enough to win fee escalation.

No privileged access is required. The window is the time between the victim's `deploy_account` entering the mempool and the victim's invoke being submitted.

---

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** exists in the mempool for the sender address. The mempool should expose a dedicated `deploy_account_in_pool(address)` query, or the gateway should inspect the transaction type of the pooled transaction before granting the validation skip.

Alternatively, restrict the skip to cases where the gateway itself accepted the `deploy_account` in the same request batch (e.g., by passing a `deploy_account_tx_hash` as the Python validator does in `native_blockifier/src/py_validator.rs`), binding the skip to a specific, verified deploy transaction rather than to any pool membership. [8](#0-7) 

---

### Proof of Concept

```
1. Victim submits RpcDeployAccountTransaction for address A (nonce=0, valid signature).
   → Gateway admits it; mempool pool now contains A.

2. Attacker observes deploy_account in mempool, extracts class_hash + constructor_calldata + salt,
   computes address A = calculate_contract_address(...).

3. Attacker constructs RpcInvokeTransactionV3:
     sender_address = A
     nonce          = 1
     signature      = [0xdead, 0xbeef]   // invalid, but length ≤ max_signature_length
     resource_bounds = (high tip + high max_l2_gas_price to win fee escalation)

4. Attacker submits invoke to gateway.

5. Gateway stateless validation:
   - validate_contract_address: A is valid ✓
   - validate_tx_signature_size: length 2 ≤ max ✓
   - validate_resource_bounds: non-zero, above min_gas_price ✓

6. Gateway stateful validation (extract_state_nonce_and_run_validations):
   a. get_nonce_from_state(A) → Nonce(0)   (account not yet deployed)
   b. validate_state_preconditions:
      - validate_nonce: 0 ≤ 1 ≤ max_allowed_nonce_gap  ✓
   c. validate_by_mempool: no duplicate nonce for (A, 1)  ✓
   d. skip_stateful_validations:
      - tx.nonce() == 1 && account_nonce == 0  → true
      - account_tx_in_pool_or_recent_block(A)  → true  (victim's deploy_account is pooled)
      → returns true  (skip __validate__)
   e. run_validate_entry_point(skip_validate=true):
      - execution_flags.validate = false
      - __validate__ entry point NOT called  ← signature never checked

7. Attacker's invalid-signature invoke admitted to mempool at (A, nonce=1).

8. Victim submits their legitimate invoke (nonce=1, valid signature).
   → validate_by_mempool: DuplicateNonce for (A, 1)  → REJECTED
     (unless victim pays higher fees; attacker can keep escalating)

9. Block built:
   - deploy_account(A, nonce=0) executes → account A deployed ✓
   - attacker's invoke(A, nonce=1) executes → __validate__ called → FAILS (invalid sig)
   - victim's invoke never included
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L434-458)
```rust
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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L184-195)
```rust
        let signature = tx.signature();

        let signature_length = signature.0.len();
        if signature_length > self.config.max_signature_length {
            return Err(StatelessTransactionValidatorError::SignatureTooLong {
                signature_length,
                max_signature_length: self.config.max_signature_length,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L50-57)
```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```

**File:** crates/native_blockifier/src/py_validator.rs (L109-118)
```rust
        let deploy_account_not_processed =
            deploy_account_tx_hash.is_some() && nonce == Nonce(Felt::ZERO);
        let tx_nonce = tx_info.nonce();
        let is_post_deploy_nonce = Nonce(Felt::ONE) <= tx_nonce;
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```
