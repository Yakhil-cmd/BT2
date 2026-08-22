No vulnerability found for this question.

**Analysis:**

The premise that re-execution under `ApplyChunkReason::UpdateTrackedShard` uses a different `RuntimeConfig` than at original application time is incorrect. The `RuntimeConfig` fee schedule used to apply a chunk is always looked up via the **epoch's protocol version**, not the node's current/binary protocol version at replay time: [1](#0-0) 

Here `protocol_version` is derived from `self.epoch_manager.get_epoch_protocol_version(&epoch_id)`, where `epoch_id` is computed from `block.prev_block_hash` — a fixed, historical fact recorded when that epoch began, immutable regardless of when or by which node binary the chunk is later replayed (state sync catchup, `UpdateTrackedShard`, `tools/state-viewer`, etc.). The same pattern is used in the normal apply path: [2](#0-1) 

Both the original chunk application and any later catchup/`UpdateTrackedShard` re-application resolve the epoch id from the same block context and therefore resolve to the **same historical epoch protocol version** and thus the same `RuntimeConfigStore::get_config(...)` fee schedule. This is exactly the invariant needed for deterministic replay across upgrades — it is not "the protocol version active at replay time" but "the protocol version of the epoch the chunk belongs to," which never changes once the epoch has occurred, e.g. in `chain/chain/src/chain_update.rs` `set_state_finalize_on_height` (catchup path) the block/epoch_id used to derive `apply_chunk`'s config comes from the historical `block_header`, not from any "current" node state: [3](#0-2) 

Regarding the `view_config` gate in `execute_function_call`, the `distribute_gas(...)` call is skipped only when `context.view_config.is_some()`, which is only ever set for `ApplyChunkReason::ViewTrackedShard` (RPC view calls via `runtime/runtime/src/state_viewer/mod.rs::call_function`), not for `UpdateTrackedShard`: [4](#0-3) [5](#0-4) 

So for both the original apply and any `UpdateTrackedShard` re-execution/catchup, `view_config` is `None` in both cases, and `distribute_gas` executes identically in both. There is no code path where an unprivileged attacker can force the same chunk to be applied once with a view config and once without it under `UpdateTrackedShard`, nor can they force a different `RuntimeConfig` fee schedule to be selected for replay versus original application, since both derive the config from the same immutable epoch protocol version. The scenario described (config pinned to replay-time protocol version rather than original) does not match how `RuntimeConfig` selection actually works in this codebase.

### Citations

**File:** chain/chain/src/runtime/mod.rs (L275-282)
```rust
        let epoch_height = self.epoch_manager.get_epoch_height_from_prev_block(prev_block_hash)?;
        let prev_block_epoch_id = self.epoch_manager.get_epoch_id(prev_block_hash)?;
        let current_protocol_version = self.epoch_manager.get_epoch_protocol_version(&epoch_id)?;
        let prev_block_protocol_version =
            self.epoch_manager.get_epoch_protocol_version(&prev_block_epoch_id)?;
        let is_first_block_of_version = current_protocol_version != prev_block_protocol_version;

        let config = self.runtime_config_store.get_config(current_protocol_version);
```

**File:** chain/chain/src/runtime/mod.rs (L1249-1251)
```rust
        let epoch_id = self.epoch_manager.get_epoch_id_from_prev_block(&block.prev_block_hash)?;
        let protocol_version = self.epoch_manager.get_epoch_protocol_version(&epoch_id)?;
        let config = self.runtime_config_store.get_config(protocol_version);
```

**File:** chain/chain/src/chain_update.rs (L611-630)
```rust
        let apply_result = self.runtime_adapter.apply_chunk(
            RuntimeStorageConfig::new(*chunk_extra.state_root(), true),
            ApplyChunkReason::UpdateTrackedShard,
            ApplyChunkShardContext {
                shard_uid,
                last_validator_proposals: chunk_extra.validator_proposals(),
                gas_limit: chunk_extra.gas_limit(),
                is_new_chunk: false,
                on_post_state_ready: None,
                memtrie_pin,
            },
            ApplyChunkBlockContext::from_header(
                &block_header,
                prev_block_header.next_gas_price(),
                block.block_congestion_info(),
                block.block_bandwidth_requests(),
            ),
            &[],
            SignedValidPeriodTransactions::empty(),
        )?;
```

**File:** runtime/runtime/src/function_call.rs (L325-329)
```rust
    if !context.view_config.is_some() {
        let unused_gas = function_call.gas.saturating_sub(outcome.used_gas);
        let distributed = runtime_ext.receipt_manager.distribute_gas(unused_gas)?;
        outcome.used_gas = outcome.used_gas.checked_add_result(distributed)?;
    }
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L397-398)
```rust
        let max_gas_burnt_view = self.max_gas_burnt_view(view_state.current_protocol_version);
        let view_config = Some(ViewConfig { max_gas_burnt: max_gas_burnt_view });
```
