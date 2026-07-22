### Title
Wrong `VersionedConstants` Loaded for Pending Fee Estimation Due to Off-by-One Block Number in `get_starknet_version` — (`crates/apollo_rpc_execution/src/lib.rs`)

---

### Summary

`create_block_context` always queries `get_starknet_version` using the **pending** block number (`block_context_number.unchecked_next()` = N+1), which does not yet exist in storage. The storage guard in `get_starknet_version` returns `None` for any block number ≥ the header marker, so the call unconditionally falls back to `StarknetVersion::LATEST`. When the node's latest committed block carries a starknet_version older than `LATEST`, the wrong `VersionedConstants` are loaded, corrupting every `estimateFee` and `simulateTransactions` response for `block_id=Tag::Pending`.

---

### Finding Description

In `create_block_context`, when `maybe_pending_data` is `Some`, the local variable `block_number` is set to the **next** (pending) block number: [1](#0-0) 

That value is then passed directly to `get_starknet_version`: [2](#0-1) 

Inside `get_starknet_version`, the very first thing the function does is compare the requested block number against the header marker (the first block that does **not** yet exist): [3](#0-2) 

Because `block_context_number.unchecked_next()` equals exactly the header marker, the condition `block_number >= header_marker` is always `true` for a pending request, and the function returns `Ok(None)`. The `unwrap_or(StarknetVersion::LATEST)` fallback then silently substitutes `LATEST` regardless of what version the latest committed block actually carries.

`VersionedConstants::get` is subsequently called with this wrong version: [4](#0-3) 

The resulting `BlockContext` — and every fee/gas value derived from it — is built on the wrong constants.

---

### Impact Explanation

`VersionedConstants` controls step costs, builtin costs, `invoke_tx_max_n_steps`, L1/L2 gas weights, and other execution parameters. Any difference between the version stored for the latest committed block and `StarknetVersion::LATEST` causes `estimateFee` and `simulateTransactions` to return wrong `overall_fee` and `gas_consumed` values for all `block_id=Tag::Pending` calls. This is a concrete, authoritative-looking wrong value returned to every caller of those RPC endpoints — matching the **High** impact category: *"RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."*

---

### Likelihood Explanation

The condition is triggered on **every** node that has not yet upgraded its chain to the version represented by `StarknetVersion::LATEST` in the binary — a normal state during any network upgrade window. Any unprivileged user calling `starknet_estimateFee` or `starknet_simulateTransactions` with `block_id = "pending"` hits this path. No special privileges or unusual inputs are required.

---

### Recommendation

When `maybe_pending_data` is `Some`, query the starknet version using the **latest committed** block number (`block_context_number`), not the pending block number (`block_context_number.unchecked_next()`):

```rust
// Correct: use the committed block's version as the basis for the pending block.
let version_query_number = if maybe_pending_data.is_some() {
    block_context_number          // N  — exists in storage
} else {
    block_number                  // also N when no pending data
};
let starknet_version = storage_reader
    .begin_ro_txn()?
    .get_starknet_version(version_query_number)?
    .unwrap_or(StarknetVersion::LATEST);
```

Alternatively, include `starknet_version` as an explicit field in `PendingData` so the caller can supply the correct value without a storage round-trip.

---

### Proof of Concept

```rust
// Pseudocode for a Rust unit test in crates/apollo_rpc_execution/src/execution_test.rs

// 1. Write block N=0 with starknet_version = V0_13_2 to storage.
let mut writer = ...;
writer.append_header(BlockNumber(0), &header_with_version(StarknetVersion::V0_13_2)).commit();

// 2. Build PendingData (simulates a pending block on top of N=0).
let pending_data = PendingData { ... };

// 3. Call estimate_fee with block_context_block_number=0, maybe_pending_data=Some(pending_data).
let result = estimate_fee(txs, &chain_id, storage_reader, Some(pending_data),
                          StateNumber::right_after_block(BlockNumber(0)),
                          BlockNumber(0), &config, false, false, None);

// 4. Inspect the BlockContext returned.
// BUG: block_context.versioned_constants() matches StarknetVersion::LATEST constants,
//      NOT V0_13_2 constants (e.g. invoke_tx_max_n_steps differs).
assert_eq!(
    block_context.versioned_constants().invoke_tx_max_n_steps,
    VersionedConstants::get(&StarknetVersion::V0_13_2).unwrap().invoke_tx_max_n_steps
    // This assertion FAILS — LATEST value is used instead.
);
```

The root cause is confirmed at: [5](#0-4) [6](#0-5)

### Citations

**File:** crates/apollo_rpc_execution/src/lib.rs (L340-373)
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
        None => {
            let header = storage_reader
                .begin_ro_txn()?
                .get_block_header(block_context_number)?
                .expect("Should have block header.")
                .block_header_without_hash;
            (
                header.block_number,
                header.timestamp,
                header.l1_gas_price,
                header.l1_data_gas_price,
                header.l2_gas_price,
                header.sequencer,
                header.l1_da_mode,
            )
        }
    };
    let ten_blocks_ago = get_10_blocks_ago(&block_context_number, cached_state)?;

    let use_kzg_da = if override_kzg_da_to_false { false } else { l1_da_mode.is_use_kzg_da() };
    let starknet_version = storage_reader
        .begin_ro_txn()?
        .get_starknet_version(block_number)?
        .unwrap_or(StarknetVersion::LATEST);
```

**File:** crates/apollo_rpc_execution/src/lib.rs (L408-408)
```rust
    let versioned_constants = VersionedConstants::get(&starknet_version)?;
```

**File:** crates/apollo_storage/src/header.rs (L252-275)
```rust
    fn get_starknet_version(
        &self,
        block_number: BlockNumber,
    ) -> StorageResult<Option<StarknetVersion>> {
        if block_number >= self.get_header_marker()? {
            return Ok(None);
        }

        let starknet_version_table = self.open_table(&self.tables().starknet_version)?;
        let mut cursor = starknet_version_table.cursor(self.txn())?;
        let Some(next_block_number) = block_number.next() else {
            return Ok(None);
        };
        cursor.lower_bound(&next_block_number)?;
        let res = cursor.prev()?;

        match res {
            Some((_block_number, starknet_version)) => Ok(Some(starknet_version)),
            None => unreachable!(
                "Since block_number >= self.get_header_marker(), starknet_version_table should \
                 have at least a single mapping."
            ),
        }
    }
```
