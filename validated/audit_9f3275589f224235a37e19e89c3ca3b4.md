### Title
Signature Verification Bypass via `skip_stateful_validations` Admits Unsigned Invoke Transactions into Mempool — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's `skip_stateful_validations` function unconditionally skips the `__validate__` entry-point call (the only place where an account contract verifies the transaction signature) for any Invoke transaction with `nonce == 1` whose sender address has a pending `deploy_account` transaction in the mempool. Because the mempool's own `validate_tx` path carries no signature field and performs no cryptographic check, an attacker can inject an Invoke transaction with an arbitrary (invalid) signature for any account that is being deployed, and the gateway will admit it without any signature verification.

### Finding Description

**Trigger path**

`StatefulTransactionValidator::extract_state_nonce_and_run_validations`
→ `run_pre_validation_checks`
→ `skip_stateful_validations` (returns `true`)
→ `run_validate_entry_point(executable_tx, skip_validate = true)`
→ `ExecutionFlags { validate: false, … }`
→ `AccountTransaction::validate_tx` returns `Ok(None)` immediately — `__validate__` is never called. [1](#0-0) 

The condition that triggers the skip is:

```rust
if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
    return mempool_client
        .account_tx_in_pool_or_recent_block(tx.sender_address())
        .await …;
}
``` [2](#0-1) 

When `account_tx_in_pool_or_recent_block` returns `true`, `skip_validate = true` propagates to `run_validate_entry_point`, which sets `execution_flags.validate = false`: [3](#0-2) 

Inside the blockifier, `validate_tx` short-circuits immediately:

```rust
if !self.execution_flags.validate {
    return Ok(None);
}
``` [4](#0-3) 

**The mempool's `validate_tx` carries no signature**

`ValidationArgs` contains only `address`, `account_nonce`, `tx_hash`, `tx_nonce`, `tip`, and `max_l2_gas_price`. There is no signature field, and the mempool checks only nonce ordering and fee escalation: [5](#0-4) [6](#0-5) 

Therefore, when `skip_stateful_validations` returns `true`, **no component in the gateway-to-mempool path verifies the transaction signature**.

**`max_nonce_for_validation_skip` config field is dead code in this path**

The `StatefulTransactionValidatorConfig` declares `max_nonce_for_validation_skip`, but `skip_stateful_validations` never reads it — it hardcodes `Nonce(Felt::ONE)`. The field is only consumed by the legacy Python-binding path (`native_blockifier/src/py_validator.rs`). [7](#0-6) 

### Impact Explanation

An attacker who observes a `deploy_account` transaction for address A in the mempool can:

1. Craft an Invoke transaction for address A with `nonce = 1`, arbitrary `calldata`, and a random/empty signature.
2. Submit it to the gateway. All checks pass: nonce is in the allowed gap, resource bounds are valid, mempool accepts it (nonce/fee checks only).
3. The `__validate__` entry point is never called; the transaction is admitted to the mempool.

**Consequence 1 — Replacement attack (fee escalation enabled):** If the attacker's tx offers a higher tip/gas price than the legitimate user's nonce-1 invoke, the mempool replaces the legitimate tx with the attacker's invalid one. The legitimate user's intended first post-deploy action is silently evicted.

**Consequence 2 — Fee drain:** When the batcher later executes the block, `__validate__` is called with `validate = true`. The invalid signature causes `__validate__` to fail; the transaction reverts but the account is still charged a fee for the validation gas consumed. Repeated injection drains the newly deployed account.

**Consequence 3 — Mempool pollution / DoS:** The attacker can continuously inject unsigned nonce-1 transactions for every observable pending `deploy_account`, filling the mempool with transactions that will always fail on-chain.

### Likelihood Explanation

- `deploy_account` transactions are publicly visible in the mempool.
- The attacker needs no privileged access, no special key, and no on-chain funds of their own.
- The only cost is the gas price of the injected transaction (which the attacker sets to the minimum threshold).
- Fee escalation is enabled by default (`enable_fee_escalation: true` in production config), making the replacement attack straightforward.

### Recommendation

1. **Enforce the config parameter**: Read `self.config.max_nonce_for_validation_skip` inside `skip_stateful_validations` and reject the skip if `tx.nonce() > max_nonce_for_validation_skip`, mirroring the logic in `py_validator.rs`.

2. **Require a deploy-account hash match**: Instead of checking only that *any* account tx exists in the mempool, verify that the pending deploy-account transaction hash was explicitly provided by the submitter (as the Python-binding path does via `deploy_account_tx_hash`), so the skip is tied to a specific deploy-account the user controls.

3. **Alternatively, remove the UX shortcut entirely** and require users to wait for the deploy-account to be confirmed before submitting the invoke, eliminating the bypass surface.

### Proof of Concept

```
1. Alice submits deploy_account for address 0xALICE (nonce=0, valid signature).
   → Mempool accepts it; account_tx_in_pool_or_recent_block(0xALICE) == true.

2. Attacker submits Invoke for 0xALICE:
     nonce          = 1
     calldata       = [transfer_all_to_attacker]
     signature      = [0x0, 0x0]   ← invalid
     tip/gas_price  = Alice's tip + 1%  ← triggers fee escalation replacement

3. Gateway stateful validation:
   - validate_nonce: 0 <= 1 <= 200  ✓
   - validate_resource_bounds: gas price ≥ threshold  ✓
   - validate_by_mempool: nonce ordering OK  ✓
   - skip_stateful_validations:
       tx.nonce() == 1  ✓
       account_nonce == 0  ✓
       account_tx_in_pool_or_recent_block(0xALICE) == true  ✓
       → returns true (skip __validate__)
   - run_validate_entry_point(skip_validate=true):
       execution_flags.validate = false
       validate_tx returns Ok(None)  ← NO signature check

4. Attacker's tx replaces Alice's legitimate nonce-1 invoke in the mempool.

5. Block production:
   - deploy_account(nonce=0) executes → 0xALICE deployed.
   - Attacker's invoke(nonce=1) executes → __validate__ called → signature fails
     → tx reverts, 0xALICE charged fee.
   - Alice's intended invoke was evicted; her account is drained of fee.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-355)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );

        // Move state into the blocking task and run CPU-heavy validation.
        let state_reader_and_contract_manager = self.take_state_reader_and_contract_manager();

        let cur_span = Span::current();
        #[allow(clippy::result_large_err)]
        tokio::task::spawn_blocking(move || {
            cur_span.in_scope(|| {
                let state = CachedState::new(state_reader_and_contract_manager);
                let mut blockifier_validator = StatefulValidator::create(state, block_context);
                blockifier_validator.validate(account_tx)
            })
        })
        .await
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::UnknownErrorCode(
                "StarknetErrorCode.InternalError".to_string(),
            ),
            message: format!("Blocking task join error when running the validate entry point: {e}"),
        })?
        .map_err(|e| StarknetError {
            code: StarknetErrorCode::KnownErrorCode(KnownStarknetErrorCode::ValidateFailure),
            message: e.to_string(),
        })?;
        Ok(())
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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L429-460)
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
