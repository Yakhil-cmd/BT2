[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/scratch.move (L4-9)
```text
/// `sui::scratch` is an ephemeral, per-transaction key-value store. Unlike `sui::dynamic_field`,
/// scratch entries are not attached to any object, and are instead dropped at the end of the
/// transaction.
///
/// Each entry is identified by the pair of its key type and key value, hashed together in the same
/// way as a dynamic field name (see `sui::dynamic_field::hash_type_and_key`).
```

**File:** crates/sui-framework/packages/sui-framework/sources/scratch.move (L97-106)
```text
public fun replace<K: copy + drop, VNew: drop, VOld: drop>(
    ctx: &mut TxContext,
    permit: Permit<K>,
    key: K,
    value: VNew,
): Option<VOld> {
    let old = remove_opt<K, VOld>(ctx, permit, key);
    add(ctx, permit, key, value);
    old
}
```

**File:** sui-execution/latest/sui-move-natives/src/scratch/mod.rs (L84-90)
```rust
        // Per-transaction capacity limit exceeded.
        AddResult::LimitExceeded => Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED)
            .with_message("Per-transaction scratch size limit was exceeded".to_string())
            .with_sub_status(
                VMMemoryLimitExceededSubStatusCode::SCRATCH_SIZE_LIMIT_EXCEEDED as u64,
            )),
    }
```

**File:** sui-execution/latest/sui-move-natives/src/scratch/runtime.rs (L19-26)
```rust
/// Per-transaction, in-memory scratch store. Entries are keyed by the address derived from the
/// `(key type, key value)` pair and live only for the duration of the transaction: a fresh
/// `ScratchRuntime` is installed per transaction, and the map is dropped at the end of it.
#[derive(Tid)]
pub struct ScratchRuntime<'a> {
    protocol_config: &'a ProtocolConfig,
    entries: BTreeMap<AccountAddress, ScratchEntry>,
}
```
