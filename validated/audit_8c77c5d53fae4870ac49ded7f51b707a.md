The code evidence is conclusive. Let me trace the full path.

**Step 1 — `TryFrom<BroadcastedTransaction>` hardcodes `only_query=false`** [1](#0-0) 

```rust
impl TryFrom<BroadcastedTransaction> for ExecutableTransactionInput {
    // TODO(yair): pass the right value for only_query field.
    fn try_from(value: BroadcastedTransaction) -> Result<Self, Self::Error> {
        match value {
            BroadcastedTransaction::Invoke(tx) => Ok(Self::Invoke(tx.into(), false)),  // ← hardcoded
            BroadcastedTransaction::DeployAccount(tx) => Ok(Self::DeployAccount(tx.into(), false)),
            ...
        }
    }
}
```

**Step 2 — `calc_tx_hash` uses the stored `only_query` flag** [2](#0-1) 

`calc_tx_hash` calls `apply_on_transaction` which passes the `only_query` field from the `ExecutableTransactionInput` variant directly to `get_transaction_hash`. Since step 1 hardcoded it to `false`, the hash is always computed without the query version bit.

**Step 3 — `to_blockifier_tx` also passes the same `only_query=false` to `ExecutionFlags`** [3](#0-2) 

The blockifier therefore executes the transaction with `only_query=false`, meaning `get_execution_info()` inside `__validate__` returns the non-query hash and a non-query version.

**Step 4 — The TODO confirms this is a known gap** [4](#0-3) 

> `// TODO(yair): support only_query version bit (enable in the RPC v0.6 and use the correct value).`

**Step 5 — The existing test does NOT cover accounts that inspect the query bit** [5](#0-4) 

`simulate_with_query_bit_outputs_same_as_no_query_bit` uses a deprecated V1 invoke against a contract that does not inspect `get_execution_info().tx_info.transaction_hash`. It only proves the two paths produce the same output for that specific contract, not that the hash value itself is correct.

---

### Title
`simulate_transactions` always computes and exposes the non-query transaction hash to `__validate__` instead of the query-version hash — (`crates/apollo_rpc/src/v0_8/api/api_impl.rs`, `crates/apollo_rpc/src/v0_8/api/mod.rs`)

### Summary
`starknet_simulateTransactions` is specified to execute transactions with the query version bit set (`only_query=true`). The conversion from `BroadcastedTransaction` to `ExecutableTransactionInput` hardcodes `only_query=false` for every Invoke and DeployAccount transaction. As a result, `calc_tx_hashes` computes the non-query hash, and the blockifier runs `__validate__` with `ExecutionFlags { only_query: false }`. Any account contract that reads `get_execution_info().tx_info.transaction_hash` or checks the version field inside `__validate__` will observe a hash that differs from the query-version hash the caller would independently compute, producing an authoritative-looking but wrong simulation result.

### Finding Description
`TryFrom<BroadcastedTransaction> for ExecutableTransactionInput` at `mod.rs:336` hardcodes `false` for the `OnlyQuery` tuple field of every `Invoke` and `DeployAccount` variant. This value propagates unchanged through:

1. `calc_tx_hashes` → `calc_tx_hash` → `get_transaction_hash(..., &TransactionOptions { only_query: false })` — the hash stored and passed to the blockifier lacks the query version bit.
2. `to_blockifier_tx` → `ExecutionFlags { only_query: false, ... }` — the blockifier executes `__validate__` without the query flag, so `get_execution_info()` inside the account returns the non-query hash and non-query version.

The Starknet specification requires that simulated transactions carry the query version bit so that account contracts can distinguish simulation from real execution. The codebase acknowledges this with two TODO comments but has not implemented it.

### Impact Explanation
Any account that calls `get_execution_info().tx_info.transaction_hash` inside `__validate__` (e.g., to verify a user-supplied signature over the query hash, or to gate simulation-only logic) will receive the wrong hash. The RPC response — including `validate_invocation` call data and return values — reflects execution under the wrong hash, making the simulation result misleading for callers who rely on it to pre-validate transactions or estimate whether `__validate__` will pass on-chain.

### Likelihood Explanation
The trigger requires no privilege: any caller of `starknet_simulateTransactions` with a transaction targeting an account that inspects the query bit will observe the wrong result. The Starknet ecosystem increasingly uses the query bit for simulation-aware account logic (e.g., Argent, Braavos). The bug is unconditional — it fires for every Invoke and DeployAccount simulation.

### Recommendation
In `TryFrom<BroadcastedTransaction> for ExecutableTransactionInput`, set `only_query=true` for all variants (Invoke, DeployAccount, Declare). `simulate_transactions` is a read-only RPC endpoint; every transaction it processes is by definition a query transaction. The same fix is needed in `TryFrom<BroadcastedDeclareTransaction>` at `mod.rs:507`.

### Proof of Concept
1. Deploy an account whose `__validate__` reads `get_execution_info().tx_info.transaction_hash` and asserts it equals the query-version hash (i.e., version with the high bit set).
2. Call `starknet_simulateTransactions` with a valid Invoke from that account.
3. Observe that `validate_invocation` shows a revert or wrong return value, because the hash passed to `__validate__` is the non-query hash.
4. Independently compute `get_transaction_hash(invoke_v1, chain_id, TransactionOptions { only_query: true })` and confirm it differs from the hash the simulation used.

### Citations

**File:** crates/apollo_rpc/src/v0_8/api/mod.rs (L329-338)
```rust
impl TryFrom<BroadcastedTransaction> for ExecutableTransactionInput {
    type Error = ErrorObjectOwned;
    fn try_from(value: BroadcastedTransaction) -> Result<Self, Self::Error> {
        // TODO(yair): pass the right value for only_query field.
        match value {
            BroadcastedTransaction::Declare(tx) => Ok(tx.try_into()?),
            BroadcastedTransaction::DeployAccount(tx) => Ok(Self::DeployAccount(tx.into(), false)),
            BroadcastedTransaction::Invoke(tx) => Ok(Self::Invoke(tx.into(), false)),
        }
    }
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L469-476)
```rust
    fn calc_tx_hash(self, chain_id: &ChainId) -> ExecutionResult<(Self, TransactionHash)> {
        match self.apply_on_transaction(|tx, only_query| {
            get_transaction_hash(tx, chain_id, &TransactionOptions { only_query })
        }) {
            (original_tx, Ok(tx_hash)) => Ok((original_tx, tx_hash)),
            (_, Err(err)) => Err(ExecutionError::TransactionHashCalculationFailed(err)),
        }
    }
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L811-812)
```rust
    // TODO(yair): support only_query version bit (enable in the RPC v0.6 and use the correct
    // value).
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L815-817)
```rust
        ExecutableTransactionInput::Invoke(invoke_tx, only_query) => {
            let execution_flags =
                ExecutionFlags { only_query, charge_fee, validate, strict_nonce_check };
```

**File:** crates/apollo_rpc_execution/src/execution_test.rs (L751-772)
```rust
fn simulate_with_query_bit_outputs_same_as_no_query_bit() {
    let ((storage_reader, storage_writer), _temp_dir) = get_test_storage();
    prepare_storage(storage_writer);

    // A tx with only_query=true.
    let tx = TxsScenarioBuilder::default()
        .invoke_deprecated(*ACCOUNT_ADDRESS, *DEPRECATED_CONTRACT_ADDRESS, None, true)
        .collect();

    let res_only_query =
        execute_simulate_transactions(storage_reader.clone(), None, tx, None, false, false);

    // A tx with only_query=false.
    let tx = TxsScenarioBuilder::default()
        .invoke_deprecated(*ACCOUNT_ADDRESS, *DEPRECATED_CONTRACT_ADDRESS, None, false)
        .collect();

    let res_regular =
        execute_simulate_transactions(storage_reader.clone(), None, tx, None, false, false);

    assert_eq!(res_only_query, res_regular);
}
```
