### Title
Congestion-buffer gas recomputed with current `RuntimeConfig` instead of cached value causes `buffered_receipts_gas` desync and node panic - (File: `runtime/runtime/src/congestion_control.rs`)

### Summary
When a receipt is buffered under congestion control, its "congestion gas" is computed once and added to `own_congestion_info.buffered_receipts_gas`. For legacy (non-`StateStoredReceipt`) receipts, however, this same gas value is **recomputed from the receipt's action list using the runtime config in effect at dequeue time**, rather than using the value that was originally added. If the relevant fee parameters change between buffering and forwarding (e.g. across a protocol upgrade), the value subtracted no longer matches the value that was added, corrupting the buffered-gas accounting.

### Finding Description
`forward_or_buffer_receipt` computes gas for a not-yet-forwarded receipt with the *current* `apply_state.config` and stores it in the buffer along with `own_congestion_info.add_buffered_receipt_gas(gas)`: [1](#0-0) 

Later, when the buffer is drained in `forward_from_buffer_to_shard`, the gas value used to decide forwarding and to call `remove_buffered_receipt_gas` is obtained via `receipt_congestion_gas`, which for legacy `Receipt` values **recomputes** `compute_receipt_congestion_gas` from scratch using `&apply_state.config` — i.e. the config active at the time of forwarding, not the config that was active when the receipt was buffered: [2](#0-1) [3](#0-2) 

`compute_receipt_congestion_gas` derives its result from `config.fees` (`total_prepaid_exec_fees`, `ActionCosts::new_action_receipt` exec fee, `total_prepaid_send_fees`, attached function-call gas), all of which are versioned runtime parameters that can change with a protocol upgrade, as documented: [4](#0-3) 

Only when `use_state_stored_receipt` is enabled is the gas value cached in `StateStoredReceiptMetadata` at buffer time and read back verbatim on removal, avoiding the mismatch: [5](#0-4) [6](#0-5) 

This flag is itself a protocol-version-gated runtime parameter (`use_state_stored_receipt` appears in `core/parameters/res/runtime_configs/72.yaml`), meaning any receipt buffered while running under a protocol version prior to this feature's activation — or any legacy `Receipt` still sitting in the buffer across the upgrade boundary — is subject to the stale-recompute bug described here, exactly mirroring the reported pattern of "recompute with current rate instead of using the cached value used at update time."

The mismatch surfaces at the end of `forward_from_buffer`, which asserts the buffered gas total is exactly zero once every buffer is drained: [7](#0-6) 

and `remove_buffered_receipt_gas` performs a `checked_sub` that errors out on underflow: [8](#0-7) 

### Impact Explanation
If gas parameters affecting `total_prepaid_exec_fees`/`total_prepaid_send_fees`/the `new_action_receipt` exec fee change via a protocol upgrade while receipts remain in a shard's outgoing buffer (which is expected under sustained congestion — the entire purpose of buffering is to hold receipts across multiple blocks/epochs), the gas value recomputed at dequeue time will differ from the value added at buffer time. This can:
- trigger the `checked_sub` underflow in `remove_buffered_receipt_gas`, returning `RuntimeError::UnexpectedIntegerOverflow` and aborting chunk application, or
- leave a residual nonzero `buffered_receipts_gas` after all buffers are emptied, tripping the `assert_eq!(... , 0)` panic in `forward_from_buffer`.

Because `CongestionInfo` (including `buffered_receipts_gas`) is a consensus-critical field carried in chunk headers and used deterministically by every node applying the same chunk, this bug is deterministic across all validators for the affected chunk — i.e. it causes a synchronized panic/chunk-application failure on all nodes, which is a chain-halting condition rather than a benign divergence. This matches the accepted "node panic / chain stall" impact category.

### Likelihood Explanation
Triggering requires (a) sustained shard congestion so that receipts remain buffered for an extended period, and (b) a protocol upgrade that changes any of the fee parameters feeding `compute_receipt_congestion_gas` occurring while such receipts are outstanding, and (c) the chain running under a protocol version where `use_state_stored_receipt` has not yet caged the receipt into the metadata-cached form. This is a narrower, upgrade-timing-dependent condition (Medium likelihood), but does not require any privileged/validator/malicious-node behavior — ordinary users can create congestion and receipts via normal transactions, and protocol upgrades are a routine, scheduled network event.

### Recommendation
Ensure the congestion-gas (and size) values used at buffer-time are always cached and reused unconditionally on removal, regardless of `use_state_stored_receipt`/protocol version — i.e., always store `StateStoredReceiptMetadata` for buffered/delayed receipts (or otherwise persist the originally computed gas/size alongside the receipt) so that `forward_from_buffer_to_shard` never re-derives congestion gas from a potentially different `RuntimeConfig` than the one active when the receipt was enqueued.

### Proof of Concept
1. Induce sustained outgoing congestion to a shard so that receipts accumulate in `ShardsOutgoingReceiptBuffer` while running on a protocol version where `use_state_stored_receipt` is disabled (legacy `Receipt` storage), per `runtime/runtime/src/congestion_control.rs:292-325` (buffer path) and `core/parameters/res/runtime_configs/72.yaml` (feature gating).
2. While those receipts remain buffered, advance the chain across a protocol upgrade that changes any parameter feeding `action_receipt_congestion_gas` (e.g. `send_sir`/`send_not_sir`/`execution` costs in `action_receipt_creation_config`, visible in `utils/mainnet-res/res/mainnet_genesis.json:36-40`).
3. Once congestion clears and `forward_from_buffer_to_shard` drains the buffer, `receipt_congestion_gas` recomputes gas with the new config (`runtime/runtime/src/congestion_control.rs:351`), producing a value different from what was added at buffer time, causing either the `checked_sub` underflow in `remove_buffered_receipt_gas` (`core/primitives/src/congestion_info.rs:309-321`) or the `assert_eq!` panic in `forward_from_buffer` (`runtime/runtime/src/congestion_control.rs:281-284`), both of which abort chunk application deterministically on every node processing that chunk.

### Citations

**File:** runtime/runtime/src/congestion_control.rs (L253-287)
```rust
        let mut all_buffers_empty = true;

        // First forward any receipts that may still be in the outgoing buffers
        // of the parent shards.
        for &shard_id in &self.info.parent_shard_ids {
            self.sink.forward_from_buffer_to_shard(
                shard_id,
                state_update,
                apply_state,
                &self.info.shard_layout,
            )?;
            let is_buffer_empty = self.sink.outgoing_buffers.to_shard(shard_id).len() == 0;
            all_buffers_empty &= is_buffer_empty;
        }

        // Then forward receipts from the outgoing buffers of the shard in the
        // current shard layout.
        for shard_id in self.info.shard_layout.shard_ids() {
            self.sink.forward_from_buffer_to_shard(
                shard_id,
                state_update,
                apply_state,
                &self.info.shard_layout,
            )?;
            let is_buffer_empty = self.sink.outgoing_buffers.to_shard(shard_id).len() == 0;
            all_buffers_empty &= is_buffer_empty;
        }

        // Assert that empty buffers match zero buffered gas.
        if all_buffers_empty {
            assert_eq!(self.sink.own_congestion_info.buffered_receipts_gas(), 0);
        }

        Ok(())
    }
```

**File:** runtime/runtime/src/congestion_control.rs (L292-325)
```rust
    pub(crate) fn forward_or_buffer_receipt(
        &mut self,
        receipt: Receipt,
        apply_state: &ApplyState,
        state_update: &mut TrieUpdate,
    ) -> Result<(), RuntimeError> {
        let shard = receipt.receiver_shard_id(&self.info.shard_layout)?;
        let size = compute_receipt_size(&receipt)?;
        let gas = compute_receipt_congestion_gas(&receipt, &apply_state.config)?;

        match ReceiptSinkV2::try_forward(
            receipt,
            gas,
            size,
            shard,
            &mut self.sink.outgoing_limit,
            &mut self.sink.outgoing_receipts,
            apply_state,
            &mut self.sink.stats,
        )? {
            ReceiptForwarding::Forwarded => (),
            ReceiptForwarding::NotForwarded(receipt) => {
                self.sink.buffer_receipt(
                    receipt,
                    size,
                    gas,
                    state_update,
                    shard,
                    apply_state.config.use_state_stored_receipt,
                )?;
            }
        }
        Ok(())
    }
```

**File:** runtime/runtime/src/congestion_control.rs (L338-395)
```rust
    fn forward_from_buffer_to_shard(
        &mut self,
        buffer_shard_id: ShardId,
        state_update: &mut TrieUpdate,
        apply_state: &ApplyState,
        shard_layout: &ShardLayout,
    ) -> Result<(), RuntimeError> {
        let mut num_forwarded = 0;
        let mut outgoing_metadatas_updates: Vec<(ByteSize, Gas)> = Vec::new();
        for receipt_result in
            self.outgoing_buffers.to_shard(buffer_shard_id).iter(&state_update.trie, true)
        {
            let receipt = receipt_result?;
            let gas = receipt_congestion_gas(&receipt, &apply_state.config)?;
            let size = receipt_size(&receipt)?;
            let should_update_outgoing_metadatas = receipt.should_update_outgoing_metadatas();
            let receipt = receipt.into_receipt();
            let target_shard_id = receipt.receiver_shard_id(&shard_layout)?;

            match Self::try_forward(
                receipt,
                gas,
                size,
                target_shard_id,
                &mut self.outgoing_limit,
                &mut self.outgoing_receipts,
                apply_state,
                &mut self.stats,
            )? {
                ReceiptForwarding::Forwarded => {
                    self.own_congestion_info.remove_receipt_bytes(size)?;
                    self.own_congestion_info.remove_buffered_receipt_gas(gas.as_gas().into())?;
                    if should_update_outgoing_metadatas {
                        // Can't update metadatas immediately because state_update is borrowed by iterator.
                        outgoing_metadatas_updates.push((ByteSize::b(size), gas));
                    }
                    // count how many to release later to avoid modifying
                    // `state_update` while iterating based on
                    // `state_update.trie`.
                    num_forwarded += 1;
                }
                ReceiptForwarding::NotForwarded(_) => {
                    break;
                }
            }
        }

        self.outgoing_buffers.to_shard(buffer_shard_id).pop_n(state_update, num_forwarded)?;
        for (size, gas) in outgoing_metadatas_updates {
            self.outgoing_metadatas.update_on_receipt_popped(
                buffer_shard_id,
                size,
                gas,
                state_update,
            )?;
        }
        Ok(())
    }
```

**File:** runtime/runtime/src/congestion_control.rs (L465-501)
```rust
    /// Put a receipt in the outgoing receipt buffer of a shard.
    fn buffer_receipt(
        &mut self,
        receipt: Receipt,
        size: u64,
        gas: Gas,
        state_update: &mut TrieUpdate,
        shard: ShardId,
        use_state_stored_receipt: bool,
    ) -> Result<(), RuntimeError> {
        let receipt = match use_state_stored_receipt {
            true => {
                let metadata =
                    StateStoredReceiptMetadata { congestion_gas: gas, congestion_size: size };
                let receipt = StateStoredReceipt::new_owned(receipt, metadata);
                let receipt = ReceiptOrStateStoredReceipt::StateStoredReceipt(receipt);
                receipt
            }
            false => ReceiptOrStateStoredReceipt::Receipt(std::borrow::Cow::Owned(receipt)),
        };

        self.own_congestion_info.add_receipt_bytes(size)?;
        self.own_congestion_info.add_buffered_receipt_gas(gas)?;

        if receipt.should_update_outgoing_metadatas() {
            self.outgoing_metadatas.update_on_receipt_pushed(
                shard,
                ByteSize::b(size),
                gas,
                state_update,
            )?;
        }

        self.outgoing_buffers.to_shard(shard).push_back(state_update, &receipt)?;
        self.stats.buffered_receipts.entry(shard).or_default().add_receipt(size, gas);
        Ok(())
    }
```

**File:** runtime/runtime/src/congestion_control.rs (L654-735)
```rust
/// Get the receipt gas from the receipt that was retrieved from the state.
/// If it is a [Receipt], the gas will be computed.
/// If it s the [StateStoredReceipt], the size will be read from the metadata.
pub(crate) fn receipt_congestion_gas(
    receipt: &ReceiptOrStateStoredReceipt,
    config: &RuntimeConfig,
) -> Result<Gas, IntegerOverflowError> {
    match receipt {
        ReceiptOrStateStoredReceipt::Receipt(receipt) => {
            compute_receipt_congestion_gas(receipt, config)
        }
        ReceiptOrStateStoredReceipt::StateStoredReceipt(receipt) => {
            Ok(receipt.metadata().congestion_gas)
        }
    }
}

/// Calculate the gas of a receipt before it is pushed into a state queue or
/// buffer. Please note that this method should only be used when storing
/// receipts into state. It should not be used for retrieving receipts from the
/// state.
///
/// The calculation is part of protocol and should only be modified with a
/// protocol upgrade.
pub(crate) fn compute_receipt_congestion_gas(
    receipt: &Receipt,
    config: &RuntimeConfig,
) -> Result<Gas, IntegerOverflowError> {
    match receipt.versioned_receipt() {
        VersionedReceiptEnum::Action(action_receipt) => {
            // account for gas guaranteed to be used for executing the receipts
            action_receipt_congestion_gas(receipt, config, action_receipt.into())
        }
        VersionedReceiptEnum::Data(_data_receipt) => {
            // Data receipts themselves don't cost gas to execute, their cost is
            // burnt at creation. What we should count, is the gas of the
            // postponed action receipt. But looking that up would require
            // reading the postponed receipt from the trie.
            // Thus, the congestion control MVP does not account for data
            // receipts or postponed receipts.
            Ok(Gas::ZERO)
        }
        VersionedReceiptEnum::PromiseYield(_) => {
            // The congestion control MVP does not account for yielding a
            // promise. Yielded promises are confined to a single account, hence
            // they never cross the shard boundaries. This makes it irrelevant
            // for the congestion MVP, which only counts gas in the outgoing
            // buffers and delayed receipts queue.
            Ok(Gas::ZERO)
        }
        VersionedReceiptEnum::PromiseResume(_) => {
            // The congestion control MVP does not account for resuming a promise.
            // Unlike `PromiseYield`, it is possible that a promise-resume ends
            // up in the delayed receipts queue.
            // But similar to a data receipt, it would be difficult to find the cost
            // of it without expensive state lookups.
            Ok(Gas::ZERO)
        }
        VersionedReceiptEnum::GlobalContractDistribution(_) => Ok(Gas::ZERO),
    }
}

fn action_receipt_congestion_gas(
    receipt: &Receipt,
    config: &RuntimeConfig,
    action_receipt: VersionedActionReceipt,
) -> Result<Gas, IntegerOverflowError> {
    let prepaid_exec_gas =
        total_prepaid_exec_fees(config, &action_receipt.actions(), receipt.receiver_id())?
            .gas
            .checked_add(config.fees.fee(ActionCosts::new_action_receipt).exec_fee().gas)
            .ok_or(IntegerOverflowError)?;
    // account for gas guaranteed to be used for creating new receipts
    let prepaid_send_cost = total_prepaid_send_fees(config, &action_receipt.actions())?;
    let prepaid_gas = prepaid_exec_gas.checked_add_result(prepaid_send_cost.gas)?;

    // account for gas potentially used for dynamic execution
    let gas_attached_to_fns = total_prepaid_gas(&action_receipt.actions())?;
    let gas = gas_attached_to_fns.checked_add_result(prepaid_gas)?;

    Ok(gas)
}
```

**File:** docs/architecture/gas/parameter_definition.md (L16-36)
```markdown
## Using Parameters in Code

As the introduction on this page already hints at it, parameter values are
versioned. In other words, they can change if the protocol version changes. A
nearcore binary has to support multiple versions and choose the correct
parameter value at runtime.

To make this easy, there is
[`RuntimeConfigStore`](https://github.com/near/nearcore/blob/a8964d200b3938a63d389263bc39c1bcd75b1de4/core/primitives/src/runtime/config_store.rs#L43).
It contains a sparse map from protocol versions to complete runtime
configurations (`BTreeMap<ProtocolVersion, Arc<RuntimeConfig>>`).
The runtime then uses `store.get_config(protocol_version)` to access a runtime
configuration for a specific version.

It is crucial to always use this runtime config store. Never hard-code parameter
values. Never look them up in a different way.

In practice, this usually translates to a `&RuntimeConfig` argument for any
function that depends on parameter values. This config object implicitly defines
the protocol version. It should therefore not be cached. It should be read from
the store once per chunk and then passed down to all functions that need it.
```

**File:** core/primitives/src/receipt.rs (L121-130)
```rust
/// The metadata associated with the receipt stored in state.
#[derive(BorshDeserialize, BorshSerialize, PartialEq, Eq, Debug, ProtocolSchema)]
pub struct StateStoredReceiptMetadata {
    /// The congestion gas of the receipt when it was stored in the state.
    /// Please see [compute_receipt_congestion_gas] for more details.
    pub congestion_gas: Gas,
    /// The congestion size of the receipt when it was stored in the state.
    /// Please see [compute_receipt_size] for more details.
    pub congestion_size: u64,
}
```

**File:** core/primitives/src/congestion_info.rs (L309-321)
```rust
    pub fn remove_buffered_receipt_gas(&mut self, gas: u128) -> Result<(), RuntimeError> {
        match self {
            CongestionInfo::V1(inner) => {
                inner.buffered_receipts_gas =
                    inner.buffered_receipts_gas.checked_sub(gas).ok_or_else(|| {
                        RuntimeError::UnexpectedIntegerOverflow(
                            "remove_buffered_receipt_gas".into(),
                        )
                    })?;
            }
        }
        Ok(())
    }
```
