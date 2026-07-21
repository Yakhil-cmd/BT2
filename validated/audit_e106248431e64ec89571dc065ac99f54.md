### Title
`skip_stateful_validations` ignores `max_nonce_for_validation_skip` config, making the signature-skip guard permanently active and un-disableable — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `StatefulTransactionValidatorConfig` struct carries a documented, serialized field `max_nonce_for_validation_skip` whose stated purpose is to bound the nonce range for which the `__validate__` entry-point (signature check) may be skipped. The legacy `PyValidator` path correctly consults this field. The production Rust gateway's `skip_stateful_validations` function never reads it, hardcoding `Nonce(Felt::ONE)` instead. An operator who sets `max_nonce_for_validation_skip = 0` to disable the skip entirely cannot do so; the gateway still admits invoke transactions with invalid signatures for nonce == 1.

### Finding Description

**Config field defined but never consumed in the new gateway**

`StatefulTransactionValidatorConfig` declares:

```rust
pub max_nonce_for_validation_skip: Nonce,
```

with default `Nonce(Felt::ONE)` and description *"Maximum nonce for which the validation is skipped."* [1](#0-0) 

The field is serialized, appears in every deployment config file, and is wired into the old `PyValidator`:

```rust
let nonce_small_enough_to_qualify_for_validation_skip =
    tx_nonce <= self.max_nonce_for_validation_skip;
let skip_validate = deploy_account_not_processed
    && is_post_deploy_nonce
    && nonce_small_enough_to_qualify_for_validation_skip;
``` [2](#0-1) 

Setting `max_nonce_for_validation_skip = 0` in `PyValidator` makes `nonce_small_enough` false for every nonce ≥ 1, fully disabling the skip.

**The new Rust gateway ignores the field entirely**

`run_pre_validation_checks` calls the free function `skip_stateful_validations`, which receives no reference to `self.config`:

```rust
let skip_validate =
    skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
``` [3](#0-2) 

Inside `skip_stateful_validations` the nonce bound is hardcoded:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await ...
``` [4](#0-3) 

`max_nonce_for_validation_skip` does not appear anywhere in `stateful_transaction_validator.rs`. A grep across the whole repo confirms the field is only read in `native_blockifier/src/py_validator.rs` and the config/schema files.

**What the skip actually bypasses**

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [5](#0-4) 

`StatefulValidator::perform_validations` then returns `Ok(())` before calling `__validate__`:

```rust
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
``` [6](#0-5) 

The account's `__validate__` entry point — which verifies the transaction signature — is never executed.

### Impact Explanation

An attacker can bypass gateway signature validation for an invoke transaction:

1. Submit a valid `deploy_account` for an address the attacker controls (nonce 0, valid signature). This lands in the mempool.
2. Submit an `invoke` with `nonce = 1` from the same address, carrying an **arbitrary/invalid signature**.
3. Gateway evaluates: `tx.nonce() == 1`, `account_nonce == 0`, `account_tx_in_pool_or_recent_block` → `true` → skip validation.
4. The invoke is admitted to the mempool without signature verification.

Even if an operator has set `max_nonce_for_validation_skip = 0` in the config to disable this UX shortcut (e.g., for a security-sensitive deployment), the hardcoded check overrides the config and the skip remains active. The gateway accepts an invalid transaction, violating the admission invariant.

**Matched impact:** *High — Mempool/gateway/RPC admission accepts invalid transactions before sequencing.*

### Likelihood Explanation

- Requires no privileged access; any user can submit `deploy_account` + `invoke`.
- The config field `max_nonce_for_validation_skip` is publicly documented and present in every deployment config, making it a natural knob for operators to turn.
- The discrepancy between `PyValidator` (which respects the field) and the new Rust gateway (which ignores it) is invisible to operators inspecting config alone.

### Recommendation

Pass `self.config.max_nonce_for_validation_skip` into `skip_stateful_validations` (or make it a method on `StatefulTransactionValidator`) and replace the hardcoded `Nonce(Felt::ONE)` comparison with a range check mirroring `PyValidator`:

```rust
// proposed fix inside skip_stateful_validations
if account_nonce == Nonce(Felt::ZERO)
    && tx.nonce() >= Nonce(Felt::ONE)
    && tx.nonce() <= config.max_nonce_for_validation_skip
{
    ...
}
```

Setting `max_nonce_for_validation_skip = 0` would then correctly disable the skip.

### Proof of Concept

1. Deploy a fresh sequencer node with `max_nonce_for_validation_skip = 0x0` in `gateway_config.stateful_tx_validator_config`.
2. Generate a new account keypair; compute the `deploy_account` contract address.
3. Submit a valid `deploy_account` transaction (nonce 0, correct signature) via the gateway → accepted.
4. Submit an `invoke` transaction (nonce 1, **zeroed/garbage signature**) from the same address via the gateway.
5. Observe: the gateway returns a transaction hash (accepted), not a `ValidateFailure` error.
6. With the fix applied (field respected), step 5 returns `ValidateFailure` because `max_nonce_for_validation_skip = 0` disables the skip.

### Citations

**File:** crates/apollo_gateway_config/src/config.rs (L283-295)
```rust
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
```

**File:** crates/native_blockifier/src/py_validator.rs (L113-118)
```rust
        let nonce_small_enough_to_qualify_for_validation_skip =
            tx_nonce <= self.max_nonce_for_validation_skip;

        let skip_validate = deploy_account_not_processed
            && is_post_deploy_nonce
            && nonce_small_enough_to_qualify_for_validation_skip;
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L311-312)
```rust
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L407-409)
```rust
        let skip_validate =
            skip_stateful_validations(executable_tx, account_nonce, mempool_client.clone()).await?;
        Ok(skip_validate)
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L437-456)
```rust
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
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L79-84)
```rust
                if !tx.execution_flags.validate {
                    return Ok(());
                }

                // `__validate__` call.
                let (_optional_call_info, actual_cost) = self.validate(&tx, tx_context.clone())?;
```
