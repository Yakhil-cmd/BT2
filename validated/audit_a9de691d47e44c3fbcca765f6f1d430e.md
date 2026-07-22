### Title
Overly Broad `skip_stateful_validations` Check Allows Signature-Bypass Admission of Unauthorized Invoke Transactions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function skips the `__validate__` entry-point (signature verification) for any Invoke transaction with `nonce=1` when `account_tx_in_pool_or_recent_block` returns `true`. That helper returns `true` for **any** pending transaction from the address — not exclusively a `deploy_account`. An attacker who observes a victim's pending `deploy_account` in the mempool can submit a nonce=1 Invoke for the victim's address with an arbitrary/invalid signature, have it admitted to the mempool without signature verification, and thereby block the victim's legitimate first Invoke.

### Finding Description

The UX feature for simultaneous `deploy_account + invoke` submission is implemented in `skip_stateful_validations`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:429-461
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

The comment claims: *"It is sufficient to check if the account exists in the mempool since it means that either it has a deploy_account transaction or transactions with future nonces that passed validations."* This reasoning is incorrect. `account_tx_in_pool_or_recent_block` returns `true` for **any** transaction from the address:

```rust
// crates/apollo_mempool/src/mempool.rs:697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
``` [2](#0-1) 

When `skip_stateful_validations` returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs:311-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
``` [3](#0-2) 

This is passed to `StatefulValidatorTrait::validate` → `perform_validations`, which explicitly short-circuits before calling `__validate__` when `validate=false`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs:79-81
if !tx.execution_flags.validate {
    return Ok(());
}
// `__validate__` call.
``` [4](#0-3) 

The `validate_by_mempool` call that precedes `skip_stateful_validations` only checks nonce gaps and duplicate tx hashes — `ValidationArgs` carries no signature field:

```rust
// crates/apollo_mempool_types/src/mempool_types.rs:50-57
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
``` [5](#0-4) 

The `validate_nonce` check for Invoke transactions allows any nonce in `[account_nonce, account_nonce + max_allowed_nonce_gap]` (default gap = 200), so nonce=1 with account_nonce=0 passes: [6](#0-5) 

### Impact Explanation

An attacker who observes a victim's `deploy_account` transaction in the public mempool can submit a nonce=1 Invoke for the victim's address with an arbitrary signature. All gateway checks pass:

1. **Stateless**: no signature length/format check beyond size limits.
2. **`validate_nonce`**: nonce=1 ∈ [0, 200] → passes.
3. **`validate_by_mempool`**: no duplicate nonce, no duplicate hash → passes.
4. **`skip_stateful_validations`**: nonce=1, account_nonce=0, `account_tx_in_pool_or_recent_block` = `true` (victim's deploy_account is in pool) → returns `true`.
5. **`run_validate_entry_point`**: `validate=false` → `__validate__` is **not called**.

The attacker's transaction is admitted to the mempool. If fee escalation is disabled (the default), the victim's legitimate nonce=1 Invoke is subsequently rejected with `DuplicateNonce`. When the batcher executes the attacker's transaction, it reverts (blockifier always calls `__validate__` during execution), but the victim's first Invoke was never sequenced.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

### Likelihood Explanation

The mempool is publicly observable. Any attacker can monitor for `deploy_account` transactions and race to submit a nonce=1 Invoke with an invalid signature before the victim's legitimate Invoke is processed. The attack requires no privileged access, no special contract, and no on-chain funds. The race window is the time between the victim's `deploy_account` being admitted and their nonce=1 Invoke being processed — a window that exists by design (the UX feature assumes both are submitted simultaneously but they are processed sequentially).

### Recommendation

Replace the `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a `deploy_account` transaction is pending for the address. The mempool should expose a dedicated method such as `deploy_account_in_pool(address: ContractAddress) -> bool` that inspects the transaction type of the pending transaction at nonce=0 for the given address. The current comment's reasoning — that any pending transaction implies a prior `__validate__` was run — is incorrect because the attacker can seed the mempool with their own nonce=0 Invoke for a fresh address they control, then use that to bypass signature verification for a nonce=1 Invoke targeting a victim.

### Proof of Concept

**Setup:** Victim V has a fresh address `A` (on-chain nonce = 0). V submits `deploy_account(A, nonce=0, sig=valid)` to the gateway. It passes all checks and enters the mempool.

**Attack:**

1. Attacker observes `deploy_account` for address `A` in the mempool.
2. Attacker constructs `invoke(sender=A, nonce=1, calldata=[arbitrary], sig=[0xff, 0xff, ...])`.
3. Attacker submits to gateway:
   - `validate_contract_address`: passes (A is a valid address).
   - `validate_resource_bounds`: attacker sets valid gas price/amount.
   - `validate_nonce`: nonce=1, account_nonce=0, 0 ≤ 1 ≤ 200 → passes.
   - `validate_by_mempool`: no duplicate hash, nonce=1 not yet in pool → passes.
   - `skip_stateful_validations`: nonce=1 ✓, account_nonce=0 ✓, `account_tx_in_pool_or_recent_block(A)` = `true` (deploy_account is in pool) → returns `true`.
   - `run_validate_entry_point`: `validate=false` → `__validate__` skipped → returns `Ok(())`.
4. Attacker's `invoke(A, nonce=1, sig=invalid)` is now in the mempool.
5. Victim submits `invoke(A, nonce=1, sig=valid)` → rejected: `MempoolError::DuplicateNonce`.
6. Batcher sequences: `deploy_account(A)` succeeds; attacker's `invoke(A, nonce=1)` reverts (blockifier calls `__validate__`, signature fails).
7. Victim's first Invoke was never executed. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L399-461)
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
}

/// Perform transaction validation by the mempool.
async fn validate_by_mempool(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<()> {
    let validation_args = ValidationArgs::new(tx, account_nonce);
    mempool_client
        .validate_tx(validation_args)
        .await
        .map_err(|err| mempool_client_err_to_deprecated_gw_err(&tx.signature(), err))
}

/// Check if validation of an invoke transaction should be skipped due to deploy_account not being
/// processed yet. This feature is used to improve UX for users sending deploy_account + invoke at
/// once.
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

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L44-54)
```rust
#[cfg_attr(any(test, feature = "mocks"), mockall::automock)]
pub trait StatefulValidatorTrait {
    #[allow(clippy::result_large_err)]
    fn validate(&mut self, account_tx: AccountTransaction) -> StatefulValidatorResult<()>;
}

impl<S: StateReader> StatefulValidatorTrait for StatefulValidator<S> {
    fn validate(&mut self, account_tx: AccountTransaction) -> StatefulValidatorResult<()> {
        self.perform_validations(account_tx)
    }
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
