### Title
Attacker-Controlled `sender_address` Bypasses `__validate__` for Undeployed Accounts in `skip_stateful_validations` — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point check for any invoke transaction whose `sender_address` has a pending deploy-account in the mempool and whose nonce equals 1. Because `sender_address` is a freely attacker-supplied field in the RPC transaction, an adversary can craft an invoke with a victim's address, an invalid signature, and a higher tip, have it admitted to the mempool without signature verification, and evict the victim's legitimate first invoke via fee escalation.

---

### Finding Description

The gateway's stateful validation path is:

```
extract_state_nonce_and_run_validations
  └─ run_pre_validation_checks
       ├─ validate_state_preconditions   (nonce range, resource bounds)
       ├─ validate_by_mempool            (duplicate / fee-escalation check only)
       └─ skip_stateful_validations      ← decides whether __validate__ runs
  └─ run_validate_entry_point(skip_validate)
```

`skip_stateful_validations` returns `true` (skip) when all three conditions hold:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 437-456
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await
        ...
}
``` [1](#0-0) 

All three inputs — `tx.nonce()`, `account_nonce`, and `tx.sender_address()` — are either taken directly from the attacker-supplied RPC transaction or derived from the victim's address that the attacker chose to impersonate. None of them is bound to the submitting party (there is no `msg.sender` equivalent enforced here).

When `skip_validate = true`, `run_validate_entry_point` sets `validate: false`:

```rust
// lines 308-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [2](#0-1) 

The blockifier's `StatefulValidator::perform_validations` then returns `Ok(())` immediately without calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
``` [3](#0-2) 

The only guard between the attacker's transaction and mempool admission is `validate_by_mempool`, which calls `Mempool::validate_tx`. That function only checks for duplicate tx-hash and fee-escalation rules — it does not verify the signature:

```rust
pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
    let tx_reference = (&args).into();
    self.validate_incoming_tx(tx_reference, args.account_nonce)?;
    self.validate_fee_escalation(tx_reference)?;
    Ok(())
}
``` [4](#0-3) 

**Attack scenario:**

1. Victim submits `deploy_account` (nonce=0) + `invoke` (nonce=1, valid signature, tip=T).
2. Victim's `deploy_account` lands in the mempool; `account_tx_in_pool_or_recent_block(victim)` returns `true`.
3. Attacker crafts an invoke with `sender_address=victim`, `nonce=1`, arbitrary calldata, invalid signature, `tip=T+1`.
4. Gateway: `account_nonce=0`, `tx_nonce=1`, `account_in_pool=true` → `skip_validate=true` → `__validate__` is not called → transaction admitted.
5. Mempool: attacker's invoke replaces victim's invoke via fee escalation (higher tip).
6. Block execution: `deploy_account` runs (nonce 0→1), then attacker's invoke runs. Now `__validate__` IS called and fails (invalid signature). The transaction reverts; the victim's newly deployed account is charged a fee for a transaction it never authorized.
7. Victim's legitimate invoke has been permanently evicted from the mempool.

The `max_nonce_for_validation_skip` field present in `StatefulTransactionValidatorConfig` is never consulted by `skip_stateful_validations` in the gateway path (it is only used in `PyValidator`), so there is no configurable guard: [5](#0-4) 

---

### Impact Explanation

- **Admission of invalid transactions**: An unsigned (or arbitrarily signed) invoke transaction targeting any undeployed account that has a pending deploy-account in the mempool is admitted to the mempool without signature verification. This directly matches "Mempool/gateway/RPC admission accepts invalid transactions."
- **Eviction of valid transactions**: The victim's legitimate, correctly signed invoke is replaced by the attacker's invalid one via fee escalation, matching "rejects valid transactions before sequencing."
- **Unauthorized fee charge**: When the attacker's invoke fails `__validate__` during block execution, the victim's account is charged a fee for a transaction it never signed, constituting an economic impact.

---

### Likelihood Explanation

The attack requires only that the victim's `deploy_account` be visible in the mempool (which is public) and that the attacker submit an invoke before the block is sealed. The attacker pays nothing at submission time; the fee is charged to the victim during execution. The window is the entire time the deploy-account sits in the mempool before being included in a block. No privileged access is required.

---

### Recommendation

Bind the skip-validation decision to the transaction's own hash/signature rather than to the freely attacker-supplied `sender_address`. Concretely, `skip_stateful_validations` should only return `true` when the gateway can confirm that the submitting party is the same entity that submitted the deploy-account — for example, by requiring the invoke to carry a valid signature over the transaction hash even in the skip path, or by checking that the invoke's tx-hash was pre-registered alongside the deploy-account submission. At minimum, the `max_nonce_for_validation_skip` config field that already exists in `StatefulTransactionValidatorConfig` should be wired into `skip_stateful_validations` so operators can disable the feature entirely.

---

### Proof of Concept

```
1. Victim calls gateway.add_tx(deploy_account{sender=V, nonce=0, sig=valid})
   → deploy_account admitted; mempool.account_tx_in_pool_or_recent_block(V) == true

2. Victim calls gateway.add_tx(invoke{sender=V, nonce=1, calldata=X, sig=valid, tip=10})
   → skip_stateful_validations: nonce==1, account_nonce==0, in_pool==true → skip=true
   → admitted to mempool

3. Attacker calls gateway.add_tx(invoke{sender=V, nonce=1, calldata=DRAIN, sig=GARBAGE, tip=20})
   → stateless validator: passes (signature length within bounds)
   → validate_state_preconditions: nonce 1 in [0, 0+200] → passes
   → validate_by_mempool: no duplicate hash, tip 20 > 10*fee_escalation_factor → passes
   → skip_stateful_validations: nonce==1, account_nonce==0, in_pool==true → skip=true
   → __validate__ NOT called → admitted
   → fee escalation: attacker's invoke replaces victim's invoke in mempool

4. Block built:
   - deploy_account(V) executes → V deployed, nonce=1
   - attacker's invoke(V, nonce=1) executes → __validate__ called → FAILS (garbage sig)
   - V charged fee; victim's legitimate invoke gone from mempool
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L308-312)
```rust
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-81)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
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

**File:** crates/apollo_gateway_config/src/config.rs (L276-299)
```rust
#[derive(Clone, Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct StatefulTransactionValidatorConfig {
    // If true, ensures the max L2 gas price exceeds (a configurable percentage of) the base gas
    // price of the previous block.
    pub validate_resource_bounds: bool,
    pub max_allowed_nonce_gap: u32,
    pub reject_future_declare_txs: bool,
    pub max_nonce_for_validation_skip: Nonce,
    pub versioned_constants_overrides: Option<VersionedConstantsOverrides>,
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
}

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
