The code path is real and the fallback is confirmed. Here is the full analysis:

---

### Title
Pending-block `simulateTransactions`/`estimateFee` silently uses `StarknetVersion::LATEST` VersionedConstants instead of the parent block's version — (`crates/apollo_rpc_execution/src/lib.rs`)

### Summary

When `block_id = Pending` is passed to `simulateTransactions` or `estimateFee`, `create_block_context` sets `block_number = block_context_number.unchecked_next()` (the not-yet-committed pending block number N+1), then calls `get_starknet_version(N+1)`. Because N+1 equals the storage header marker, `get_starknet_version` returns `None`, and the code falls back to `StarknetVersion::LATEST`. The resulting `VersionedConstants` (step limits, fee weights, resource bounds) are those of the latest known protocol version, not those of the parent committed block. Any caller of `simulateTransactions` or `estimateFee` with `block_id=Pending` receives results computed under the wrong execution rules.

### Finding Description

**Step 1 — RPC handler resolves `block_number` for pending:**

In `simulate_transactions` and `estimate_fee`, `get_accepted_block_number` is called with `BlockId::Tag(Tag::Pending)`. [1](#0-0) 

This returns the latest *committed* block number N (not N+1).

**Step 2 — `create_block_context` advances to N+1 for pending:** [2](#0-1) 

When `maybe_pending_data` is `Some`, `block_number` is set to `block_context_number.unchecked_next()` = N+1.

**Step 3 — `get_starknet_version(N+1)` returns `None`:** [3](#0-2) 

`get_starknet_version` immediately returns `Ok(None)` for any block number ≥ the header marker: [4](#0-3) 

Since the header marker is N+1 (the first block that does not yet exist), `N+1 >= N+1` is true and `None` is returned.

**Step 4 — Silent fallback to `StarknetVersion::LATEST`:**

The `.unwrap_or(StarknetVersion::LATEST)` on line 373 silently substitutes the latest known protocol version. `VersionedConstants::get(&starknet_version)` then loads the LATEST constants: [5](#0-4) 

**Step 5 — Concrete constant divergence:**

The test in the repo confirms the magnitude of the difference: [6](#0-5) 

- `0.13.0`: `invoke_tx_max_n_steps = 3_000_000`
- `0.13.2`: `invoke_tx_max_n_steps = 10_000_000`
- `LATEST` (currently `V0_14_4`): even higher limits

The blockifier defines constants from V0_13_0 through V0_14_4: [7](#0-6) 

### Impact Explanation

Any unprivileged user calling `starknet_simulateTransactions` or `starknet_estimateFee` with `block_id = "pending"` receives results computed under `StarknetVersion::LATEST` VersionedConstants regardless of what version the parent committed block actually uses. Concretely:

- A transaction consuming between 3 M and 10 M steps simulates as **succeeding** under LATEST (10 M limit) but would **fail** when the actual block is committed under 0.13.0 (3 M limit).
- Fee estimates are wrong: resource weights, gas costs, and step-to-gas conversion factors all differ between versions.
- The returned simulation trace and fee estimation are authoritative-looking but incorrect.

This fits: **High — RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value.**

### Likelihood Explanation

The condition is triggered on every `simulateTransactions`/`estimateFee` call with `block_id=Pending` whenever the latest committed block's `starknet_version` differs from `StarknetVersion::LATEST`. This is the normal state during any protocol upgrade window, and also for any RPC node syncing a chain that has not yet upgraded to the code's LATEST version. No special privileges are required; any unprivileged user can trigger it.

### Recommendation

In `create_block_context`, when `maybe_pending_data` is `Some`, look up the starknet version using the *parent* block number (`block_context_number`, i.e., N), not the pending block number (`block_context_number.unchecked_next()`, i.e., N+1):

```rust
// Use block_context_number (the parent committed block) for version lookup,
// regardless of whether we are in pending mode.
let starknet_version = storage_reader
    .begin_ro_txn()?
    .get_starknet_version(block_context_number)?  // N, not N+1
    .unwrap_or(StarknetVersion::LATEST);
```

This ensures the pending block simulation uses the same VersionedConstants as the parent block, which is the correct baseline until the sequencer explicitly signals a version upgrade.

### Proof of Concept

1. Commit block N with `starknet_version = "0.13.0"` (confirmed `invoke_tx_max_n_steps = 3_000_000`).
2. Set up a valid pending block on top of it (parent hash matches block N's hash).
3. Call `starknet_simulateTransactions` with `block_id = "pending"` and an invoke transaction whose execution consumes between 3 M and 10 M steps.
4. Observe: simulation **succeeds** (LATEST constants allow it).
5. Verify: the same transaction submitted to a node that commits the block under 0.13.0 rules **fails** with step-limit exceeded.
6. The fee estimate returned in step 4 is also wrong — it is computed under LATEST gas/resource weights, not 0.13.0 weights.

### Citations

**File:** crates/apollo_rpc/src/v0_8/block.rs (L129-131)
```rust
        BlockId::Tag(Tag::Latest | Tag::Pending) => {
            get_latest_block_number(txn)?.ok_or_else(|| ErrorObjectOwned::from(BLOCK_NOT_FOUND))?
        }
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L340-349)
```rust
    ) = match maybe_pending_data {
        Some(pending_data) => (
            block_context_number.unchecked_next(),
            pending_data.timestamp,
            pending_data.l1_gas_price,
            pending_data.l1_data_gas_price,
            pending_data.l2_gas_price,
            pending_data.sequencer,
            pending_data.l1_da_mode,
        ),
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L370-373)
```rust
    let starknet_version = storage_reader
        .begin_ro_txn()?
        .get_starknet_version(block_number)?
        .unwrap_or(StarknetVersion::LATEST);
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L408-408)
```rust
    let versioned_constants = VersionedConstants::get(&starknet_version)?;
```

**File:** crates/apollo_storage/src/header.rs (L256-258)
```rust
        if block_number >= self.get_header_marker()? {
            return Ok(None);
        }
```

**File:** crates/apollo_rpc_execution/src/execution_test.rs (L839-851)
```rust
// Test that we retrieve the correct versioned constants.
#[test]
fn test_get_versioned_constants() {
    let starknet_version_13_0 = StarknetVersion::try_from("0.13.0".to_string()).unwrap();
    let starknet_version_13_1 = StarknetVersion::try_from("0.13.1".to_string()).unwrap();
    let starknet_version_13_2 = StarknetVersion::try_from("0.13.2".to_string()).unwrap();
    let versioned_constants = VersionedConstants::get(&starknet_version_13_0).unwrap();
    assert_eq!(versioned_constants.invoke_tx_max_n_steps, 3_000_000);
    let versioned_constants = VersionedConstants::get(&starknet_version_13_1).unwrap();
    assert_eq!(versioned_constants.invoke_tx_max_n_steps, 4_000_000);
    let versioned_constants = VersionedConstants::get(&starknet_version_13_2).unwrap();
    assert_eq!(versioned_constants.invoke_tx_max_n_steps, 10_000_000);
}
```

**File:** crates/blockifier/src/blockifier_versioned_constants.rs (L40-60)
```rust
define_versioned_constants!(
    VersionedConstants,
    RawVersionedConstants,
    VersionedConstantsError,
    StarknetVersion::V0_13_0,
    "resources/versioned_constants_diff_regression",
    (V0_13_0, "../resources/blockifier_versioned_constants_0_13_0.json"),
    (V0_13_1, "../resources/blockifier_versioned_constants_0_13_1.json"),
    (V0_13_1_1, "../resources/blockifier_versioned_constants_0_13_1_1.json"),
    (V0_13_2, "../resources/blockifier_versioned_constants_0_13_2.json"),
    (V0_13_2_1, "../resources/blockifier_versioned_constants_0_13_2_1.json"),
    (V0_13_3, "../resources/blockifier_versioned_constants_0_13_3.json"),
    (V0_13_4, "../resources/blockifier_versioned_constants_0_13_4.json"),
    (V0_13_5, "../resources/blockifier_versioned_constants_0_13_5.json"),
    (V0_13_6, "../resources/blockifier_versioned_constants_0_13_6.json"),
    (V0_14_0, "../resources/blockifier_versioned_constants_0_14_0.json"),
    (V0_14_1, "../resources/blockifier_versioned_constants_0_14_1.json"),
    (V0_14_2, "../resources/blockifier_versioned_constants_0_14_2.json"),
    (V0_14_3, "../resources/blockifier_versioned_constants_0_14_3.json"),
    (V0_14_4, "../resources/blockifier_versioned_constants_0_14_4.json"),
);
```
