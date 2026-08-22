## Analysis

The CCIP report's bug class is: **an unhandled exception during cross-chain message processing causes the receiving entity to panic/revert, blocking the message channel and stalling further processing until manual intervention.**

The closest reachable analog in nearcore is in the delayed-receipt draining path, not in a "manual retry" queue but in a structurally similar mechanism: `DelayedReceiptQueueWrapper::pop`'s `receipt_filter_fn`, used while draining receipts that were queued across a resharding boundary. [1](#0-0) 

```rust
fn receipt_filter_fn(&self, receipt: &ReceiptOrStateStoredReceipt) -> bool {
    let shard_layout = self.epoch_info_provider.shard_layout(&self.epoch_id).unwrap();
    let receipt_shard_id = receipt.get_receipt().receiver_shard_id(&shard_layout).unwrap();
    receipt_shard_id == self.shard_id
}
```

`receiver_shard_id` for a `GlobalContractDistribution` receipt attempts to resolve the receipt's `target_shard` (recorded when the receipt was created, potentially many resharding epochs ago) against the *current* shard layout, falling back to `resolve_to_current_shard` if the shard no longer exists directly: [2](#0-1) 

If `resolve_to_current_shard` cannot map the stale `target_shard` to any current shard (e.g., the shard's split history isn't fully tracked, as happens with non-V3/static shard layouts, or across specific multi-resharding sequences), it returns `Err(EpochError::ShardingError(...))`. That `Err` is immediately `.unwrap()`-ed inside `receipt_filter_fn`, which is called on every `pop()` of the delayed-receipt queue while draining it.

There is a dedicated regression test in the codebase explicitly describing exactly this failure mode — a stale `GlobalContractDistribution` receipt surviving two resharding generations while parked in the delayed queue, and asserting the chain does not stall when it is eventually drained: [3](#0-2) 

Notably the test itself states: *"The fix only works with V3 shard layouts (dynamic resharding). With static resharding, the shard layout doesn't maintain a full split history."* — meaning outside the narrow dynamic-resharding (V3) case that this test targets, the `.unwrap()` panic path in `receipt_filter_fn` remains a live, reachable hazard for any shard-layout transition that doesn't retain full split history for a delayed `GlobalContractDistribution` receipt's stale `target_shard`.

This is triggerable by an ordinary, unprivileged action: any account deploying a global contract creates a `GlobalContractDistributionReceipt` with a `target_shard`; if that receipt is delayed (e.g., due to congestion) across a resharding event where the split history for its `target_shard` is not preserved, draining the delayed-receipt queue on that shard calls `receipt_filter_fn` → `receiver_shard_id` → `Err` → `.unwrap()` panic, crashing every validator/chunk-producer for that shard and halting chunk production — a direct chain-stall DoS, analogous to the CCIP unhandled-exception blocking cross-chain messages.

### Title
Panic-on-unwrap in delayed-receipt shard filter for stale `GlobalContractDistribution` receipts can stall the chain - (File: runtime/runtime/src/congestion_control.rs)

### Summary
`DelayedReceiptQueueWrapper::receipt_filter_fn` calls `.unwrap()` on `Receipt::receiver_shard_id`, which can return `Err(EpochError::ShardingError)` for a `GlobalContractDistribution` receipt whose recorded `target_shard` cannot be resolved to any shard in the current layout. This is reachable whenever such a receipt is delayed across a resharding transition that doesn't preserve full split history for its stale target, causing every node applying that shard's delayed-receipt queue to panic.

### Finding Description
`GlobalContractDistributionReceipt::target_shard()` freezes a `ShardId` at receipt-creation time. While the receipt sits in the delayed-receipt queue (e.g., because the shard is compute/congestion limited), the shard layout can change via resharding. When the queue is later drained, `DelayedReceiptQueueWrapper::pop` calls `receipt_filter_fn` on every popped entry, which unconditionally unwraps both `epoch_info_provider.shard_layout(...)` and `receiver_shard_id(&shard_layout)`. `receiver_shard_id` attempts `shard_layout.resolve_to_current_shard(target_shard)` as a fallback and returns an `Err` if the stale shard cannot be mapped forward — which the codebase's own regression test acknowledges is possible outside full dynamic (V3) resharding with tracked split history. That `Err` propagates straight into a panic via `.unwrap()`, with no error handling, retry, or graceful degradation path.

### Impact Explanation
A panic inside chunk/receipt application aborts the node process (or is caught as a fatal apply error depending on the calling context), effectively halting block/chunk production for the shard. Because this occurs deterministically for all correct validators processing the same delayed queue and same shard layout, it produces a chain-wide stall rather than a single node’s failure — a direct denial-of-service on chain progress, analogous to the CCIP report's "blocked message channel until manual intervention," except here there is no manual-execution fallback: normal protocol operation cannot proceed until the invalid state is somehow bypassed (e.g., via a protocol upgrade/hotfix).

### Likelihood Explanation
Triggering requires: (1) an account deploying a global contract (unprivileged, ordinary transaction), (2) sufficient congestion/compute pressure to delay the resulting distribution receipt, and (3) a resharding event (or sequence) occurring while the receipt is delayed such that the recorded `target_shard` cannot be resolved via `resolve_to_current_shard`. The codebase's own test comments confirm this gap exists for shard layouts without full split-history tracking (non-V3/static resharding paths), making this a concrete, currently-unmitigated code path rather than a purely theoretical one, though it requires resharding to be actively occurring, which is an infrequent but real and now-more-common event with dynamic resharding.

### Recommendation
Replace the `.unwrap()` calls in `receipt_filter_fn` with proper error propagation (return a `Result` from the filter/`pop` path and surface a recoverable `RuntimeError`), and ensure `receiver_shard_id` failures for stale `GlobalContractDistribution` receipts are handled gracefully (e.g., treat as "not yet deliverable, keep delayed" or drop with a fee refund) rather than causing an unrecoverable panic. Additionally, ensure split-history tracking is guaranteed for any shard layout capable of hosting delayed cross-shard `GlobalContractDistribution` receipts, not just V3/dynamic resharding.

### Proof of Concept
1. Deploy a global contract from an account on shard S (creates a `GlobalContractDistributionReceipt` with `target_shard = S`).
2. Saturate compute on shard S every block so the distribution receipt is pushed into the delayed-receipt queue and remains there.
3. Trigger a resharding sequence that splits shard S (and potentially splits again) without full split-history retention for the old `target_shard` value (as described in the existing test at [4](#0-3) ).
4. Stop saturating and let the delayed queue drain; when `receipt_filter_fn` pops the stale receipt, `receiver_shard_id` returns `Err`, which is `.unwrap()`-ed, panicking chunk application and stalling the chain on that shard.

### Citations

**File:** runtime/runtime/src/congestion_control.rs (L868-909)
```rust
    // With ReshardingV3, it's possible for a chunk to have delayed receipts that technically
    // belong to the sibling shard before a resharding event.
    // Here, we filter all the receipts that don't belong to the current shard_id.
    //
    // The function follows the guidelines of standard iterator filter function
    // We return true if we should retain the receipt and false if we should filter it.
    fn receipt_filter_fn(&self, receipt: &ReceiptOrStateStoredReceipt) -> bool {
        let shard_layout = self.epoch_info_provider.shard_layout(&self.epoch_id).unwrap();
        let receipt_shard_id = receipt.get_receipt().receiver_shard_id(&shard_layout).unwrap();
        receipt_shard_id == self.shard_id
    }

    pub(crate) fn pop(
        &mut self,
        trie_update: &mut TrieUpdate,
        config: &RuntimeConfig,
    ) -> Result<Option<ReceiptOrStateStoredReceipt<'_>>, RuntimeError> {
        // While processing receipts, we need to keep track of the gas and bytes
        // even for receipts that may be filtered out due to a resharding event
        loop {
            // Check proof size limit before each receipt is popped.
            if trie_update.trie.check_proof_size_limit_exceed() {
                break;
            }
            let Some(receipt) = self.queue.pop_front(trie_update)? else {
                break;
            };
            let delayed_gas = receipt_congestion_gas(&receipt, &config)?;
            let delayed_bytes = receipt_size(&receipt)? as u64;
            self.removed_delayed_gas =
                self.removed_delayed_gas.checked_add(delayed_gas).ok_or(IntegerOverflowError)?;
            self.removed_delayed_bytes = self
                .removed_delayed_bytes
                .checked_add(delayed_bytes)
                .ok_or(IntegerOverflowError)?;

            // Track gas and bytes for receipt above and return only receipt that belong to the shard.
            if self.receipt_filter_fn(&receipt) {
                return Ok(Some(receipt));
            }
        }
        Ok(None)
```

**File:** core/primitives/src/receipt.rs (L437-466)
```rust
    pub fn receiver_shard_id(&self, shard_layout: &ShardLayout) -> Result<ShardId, EpochError> {
        let shard_id = match self.receipt() {
            ReceiptEnum::Action(_)
            | ReceiptEnum::ActionV2(_)
            | ReceiptEnum::Data(_)
            | ReceiptEnum::PromiseYield(_)
            | ReceiptEnum::PromiseYieldV2(_)
            | ReceiptEnum::PromiseResume(_) => {
                shard_layout.account_id_to_shard_id(self.receiver_id())
            }
            ReceiptEnum::GlobalContractDistribution(receipt) => {
                let target_shard = receipt.target_shard();
                if shard_layout.shard_ids().contains(&target_shard) {
                    target_shard
                } else {
                    // The target shard may be from an arbitrarily old layout (the receipt could
                    // have been delayed across multiple resharding events). resolve_to_current_shard
                    // will find a shard descendant in the current layout.
                    let Some(current_shard) = shard_layout.resolve_to_current_shard(target_shard)
                    else {
                        return Err(EpochError::ShardingError(format!(
                            "Shard {target_shard} does not exist in the shard layout or its split history",
                        )));
                    };
                    current_shard
                }
            }
        };
        Ok(shard_id)
    }
```

**File:** test-loop-tests/src/tests/global_contracts_distribution.rs (L30-65)
```rust
#[test]
#[cfg_attr(feature = "protocol_feature_spice", ignore)]
fn test_stale_global_contract_distribution_after_double_resharding() {
    init_test_logger();

    // The fix only works with V3 shard layouts (dynamic resharding).
    // With static resharding, the shard layout doesn't maintain a full split history.
    if !ProtocolFeature::DynamicResharding.enabled(PROTOCOL_VERSION) {
        return;
    }

    let epoch_length: BlockHeightDelta = 10;
    let base_boundary_accounts = create_account_ids(["user2", "user3"]).to_vec();
    let base_shard_layout = ShardLayout::multi_shard_custom(base_boundary_accounts, 3);
    let deploy_user: AccountId = create_account_id("user0");
    let users = create_account_ids(["user0", "user1", "user2", "user3", "user4", "user5"]).to_vec();
    let validators_spec = create_validators_spec(1, 0);
    let clients = validators_spec_clients(&validators_spec);
    let chunk_producer = clients[0].clone();
    let gas_limit = Gas::from_teragas(300);
    let base_pv = PROTOCOL_VERSION - 1;

    // Configure dynamic resharding to force-split two shards sequentially.
    // The first split targets the shard containing deploy_user (user0), so the
    // GlobalContractDistribution receipt becomes stale after two layout transitions.
    let first_split_shard = base_shard_layout.account_id_to_shard_id(&deploy_user);
    let second_split_shard = base_shard_layout.account_id_to_shard_id(&create_account_id("user4"));
    assert_ne!(first_split_shard, second_split_shard);

    let dynamic_config = DynamicReshardingConfig {
        memory_usage_threshold: u64::MAX,
        min_child_memory_usage: u64::MAX,
        max_number_of_shards: 100,
        min_epochs_between_resharding: 1.try_into().unwrap(),
        force_split_shards: vec![first_split_shard, second_split_shard],
        block_split_shards: vec![],
```

**File:** test-loop-tests/src/tests/global_contracts_distribution.rs (L165-186)
```rust
    // Step 4: Stop saturating. Let the delayed queue drain.
    // If the vulnerability exists, processing the stale GlobalContractDistribution
    // receipt will panic in receipt_filter_fn() when receiver_shard_id() fails
    // to remap the old target_shard after two resharding generations.
    let current_height = {
        let node = env.node_for_account(&chunk_producer);
        node.client().chain.chain_store().head().unwrap().height
    };
    let drain_end = current_height + epoch_length * 2;
    env.runner_for_account(&chunk_producer).run_until_head_height(drain_end);

    let head_height = {
        let node = env.node_for_account(&chunk_producer);
        node.client().chain.chain_store().head().unwrap().height
    };
    assert!(
        head_height >= drain_end,
        "chain stalled at height {}; expected >= {} (likely panicked processing stale receipt)",
        head_height,
        drain_end
    );
}
```
