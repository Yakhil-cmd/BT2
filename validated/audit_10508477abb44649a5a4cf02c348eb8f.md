### Title
Gateway Admits Invoke Transactions with Invalid Signatures via `skip_stateful_validations` UX Bypass - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful validator unconditionally skips the `__validate__` entry-point call (the only on-chain signature check at gateway time) for any invoke transaction whose nonce is `1` and whose sender's on-chain nonce is `0`, provided the sender address appears in the mempool. The check used to decide whether to skip is `account_tx_in_pool_or_recent_block`, which returns `true` for **any** transaction from that address — not specifically a `deploy_account` transaction. An unprivileged attacker who observes a pending `deploy_account` transaction for address A can immediately submit a second invoke transaction from address A carrying an arbitrary/invalid signature; the gateway admits it without ever calling `__validate__`, inserting an invalid transaction into the mempool.

### Finding Description

In `run_pre_validation_checks`, after the nonce and resource-bounds checks pass, `skip_stateful_validations` is called:

```rust
// crates/apollo_gateway/src/stateful_transaction_validator.rs  lines 429-461
async fn skip_stateful_validations(
    tx: &ExecutableTransaction,
    account_nonce: Nonce,
    mempool_client: SharedMempoolClient,
) -> StatefulTransactionValidatorResult<bool> {
    if let ExecutableTransaction::Invoke(ExecutableInvokeTransaction { tx, .. }) = tx {
        if tx.nonce() == Nonce(Felt::ONE) && account_nonce == Nonce(Felt::ZERO) {
            return mempool_client
                .account_tx_in_pool_or_recent_block(tx.sender_address())
                .await
                ...
        }
    }
    Ok(false)
}
```

When it returns `true`, `run_validate_entry_point` sets `execution_flags.validate = false`:

```rust
// lines 308-312
let execution_flags =
    ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };
```

`StatefulValidator::perform_validations` then short-circuits before calling `__validate__`:

```rust
// crates/blockifier/src/blockifier/stateful_validator.rs  lines 79-81
if !tx.execution_flags.validate {
    return Ok(());
}
```

The mempool's `account_tx_in_pool_or_recent_block` returns `true` for **any** address that has a transaction in the pool or a recent committed block — it does not distinguish a `deploy_account` transaction from an ordinary invoke:

```rust
// crates/apollo_mempool/src/mempool.rs  lines 697-700
pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
    self.state.contains_account(account_address)
        || self.tx_pool.contains_account(account_address)
}
```

**Concrete attack path:**

1. Legitimate user broadcasts a `deploy_account` transaction for address A (valid signature, passes full gateway validation including `__validate_deploy__`). Address A is now tracked in the mempool's `tx_pool`.
2. Attacker computes address A (deterministic from class hash + salt + constructor calldata — all visible in the pending `deploy_account` tx).
3. Attacker submits an invoke transaction: `sender_address = A`, `nonce = 1`, `signature = [0x0, 0x0]` (arbitrary invalid bytes).
4. Gateway stateless checks pass (signature length ≤ 4000, resource bounds non-zero, DA modes L1, etc.).
5. `convert_rpc_tx_to_internal` computes the tx hash — no signature verification here.
6. `extract_state_nonce_and_run_validations`:
   - `get_nonce_from_state(A)` → `0` (account not yet deployed).
   - `validate_nonce`: `0 ≤ 1 ≤ 200` → passes.
   - `validate_by_mempool`: no duplicate, nonce gap OK → passes.
   - `skip_stateful_validations`: `nonce==1 && account_nonce==0` → calls `account_tx_in_pool_or_recent_block(A)` → `true` (deploy_account is in pool) → returns `true`.
   - `run_validate_entry_point(skip_validate=true)` → `__validate__` is **never called**.
7. Invalid invoke tx is inserted into the mempool.
8. Batcher executes `deploy_account` first (account deployed, funded).
9. Batcher executes the invalid invoke tx: `perform_pre_validation_stage` passes (nonce now 1, fee bounds OK), then `__validate__` is called and **fails** (invalid signature). Transaction reverts; account is charged a fee.

The same path applies when the account is already deployed (nonce = 0 in state) and has a legitimate nonce-0 invoke in the mempool: the attacker can race in a nonce-1 invoke with an invalid signature before the nonce-0 tx is executed.

### Impact Explanation

The gateway admits an invalid transaction — one whose `__validate__` entry point would reject it — into the mempool. This satisfies the **High** impact criterion: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."*

Secondary effect: the legitimate account owner is griefed. After the `deploy_account` executes and funds the account, the batcher runs the attacker-injected invalid invoke, `__validate__` fails, and the account is charged a fee for the failed validation. An attacker can repeat this for every new account that broadcasts a `deploy_account` + invoke pair, draining small amounts from each victim.

### Likelihood Explanation

- `deploy_account` transactions are publicly visible in the mempool.
- Address A is fully deterministic and computable from the public `deploy_account` fields.
- Submitting a nonce-1 invoke with a garbage signature requires no privileged access — any RPC client can do it.
- The race window is the time between the `deploy_account` entering the mempool and the batcher committing it; this is typically multiple seconds to minutes.
- The `max_nonce_for_validation_skip` default is `Nonce(Felt::ONE)`, so the bypass is active in the default production configuration.

### Recommendation

Replace the coarse `account_tx_in_pool_or_recent_block` check with a check that specifically verifies a **`deploy_account` transaction** for address A is pending in the mempool. Introduce a dedicated mempool query such as `has_pending_deploy_account(address)` that inspects the transaction type, rather than merely checking address presence. This preserves the intended UX (deploy + invoke in one batch) while closing the griefing vector for arbitrary addresses.

### Proof of Concept

```
# 1. Observe pending deploy_account tx for address A in the mempool.
#    Compute A = pedersen(class_hash, salt, constructor_calldata, chain_id).

# 2. Craft an invoke tx:
#    sender_address = A
#    nonce          = 1
#    signature      = [0x0, 0x0]          # invalid
#    resource_bounds = { l2_gas: { max_amount: 1000, max_price_per_unit: 8_000_000_001 } }
#    calldata        = []

# 3. POST to gateway /add_transaction → HTTP 200, tx_hash returned.
#    (Gateway skips __validate__ because account_tx_in_pool_or_recent_block(A) == true)

# 4. Wait for batcher to commit the deploy_account block.

# 5. In the next block the batcher picks up the invalid invoke:
#    - perform_pre_validation_stage passes (nonce=1 matches state, fee bounds OK)
#    - __validate__ executes → ECDSA verify fails → transaction reverts
#    - Account A is charged fee = actual_gas_used * gas_price
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-312)
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

**File:** crates/apollo_mempool/src/mempool.rs (L697-700)
```rust
    pub fn account_tx_in_pool_or_recent_block(&self, account_address: ContractAddress) -> bool {
        self.state.contains_account(account_address)
            || self.tx_pool.contains_account(account_address)
    }
```

**File:** crates/blockifier/src/blockifier/stateful_validator.rs (L76-81)
```rust
            ApiTransaction::Invoke(_) => {
                let tx_context = Arc::new(self.tx_executor.block_context.to_tx_context(&tx));
                tx.perform_pre_validation_stage(self.state(), &tx_context)?;
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
