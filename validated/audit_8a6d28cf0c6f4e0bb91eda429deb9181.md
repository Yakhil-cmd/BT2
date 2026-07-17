### Title
Receipt Size Invariant Bypass via Unvalidated `output_data_receivers` Append After `promise_return` — (`File: runtime/runtime/src/lib.rs`)

### Summary

In `apply_action_receipt`, new receipts produced by contract execution are validated against `max_receipt_size` using `ValidateReceiptMode::NewReceipt`. However, when a contract uses `promise_return` (returning a `ReturnData::ReceiptIndex`), the runtime subsequently mutates the already-validated receipt by appending `output_data_receivers` from the parent receipt. No re-validation of the receipt size occurs after this mutation. The resulting receipt can exceed `max_receipt_size` (4,194,304 bytes) and is forwarded cross-shard and executed without rejection. This is a confirmed, acknowledged production bug (nearcore issue #12606).

### Finding Description

The validation gate in `apply_action_receipt` runs at lines 856–865:

```rust
if let Err(e) = new_result.new_receipts.iter().try_for_each(|receipt| {
    validate_receipt(
        &apply_state.config.wasm_config.limit_config,
        receipt,
        apply_state.current_protocol_version,
        ValidateReceiptMode::NewReceipt,   // ← checks max_receipt_size
    )
}) {
    new_result.result = Err(ActionErrorKind::NewReceiptValidationError(e).into());
}
``` [1](#0-0) 

After this validation, the code handles the `promise_return` case at lines 1020–1037. When the contract returns a `ReceiptIndex`, the runtime mutates the receipt in-place by extending its `output_data_receivers` with those of the parent receipt:

```rust
if let Ok(ReturnData::ReceiptIndex(receipt_index)) = result.result {
    match result.new_receipts.get_mut(receipt_index as usize)...receipt_mut() {
        ReceiptEnum::ActionV2(new_action_receipt) | ... => new_action_receipt
            .output_data_receivers
            .extend_from_slice(&action_receipt.output_data_receivers()),
        ...
    }
}
``` [2](#0-1) 

There is no call to `validate_receipt` after this mutation. The receipt's serialized size now exceeds `max_receipt_size` but is forwarded to the receiving shard.

The receiving shard processes it with `ValidateReceiptMode::ExistingReceipt`, which explicitly skips the size check:

```rust
validate_receipt(
    &processing_state.apply_state.config.wasm_config.limit_config,
    receipt,
    protocol_version,
    ValidateReceiptMode::ExistingReceipt,   // ← no size check
)
``` [3](#0-2) 

The `ExistingReceipt` mode is documented to intentionally skip the size check precisely because of this bug:

```
2) There is a bug which allows to create receipts that are above the size limit. Runtime has
   to handle them gracefully until the receipt size limit bug is fixed.
   See https://github.com/near/nearcore/issues/12606 for details.
``` [4](#0-3) 

A second path exists via `value_return`: a contract returning a value of size ≈ `max_length_returned_data` causes a `DataReceipt` whose total borsh-serialized size exceeds `max_receipt_size`, because `validate_data_receipt` only checks the payload length, not the total receipt envelope size. [5](#0-4) 

The congestion-control layer also acknowledges the bypass and works around it by clamping the size used for outgoing-limit accounting:

```rust
// There is a bug which allows to create receipts that are above the size limit.
// See https://github.com/near/nearcore/issues/12606
if size > max_receipt_size {
    size = max_receipt_size;
}
``` [6](#0-5) 

### Impact Explanation

`max_receipt_size` is a **hard limit** in the pre-inclusion transaction validation layer. Its purpose is to bound `ChunkStateWitness` size (target ≤ 17 MiB) and prevent individual receipts from monopolising chunk capacity. The bypass allows any unprivileged user to produce receipts that exceed this limit and have them executed cross-shard. The exact corrupted value is the receipt's borsh-serialized size, which exceeds 4,194,304 bytes. Downstream effects include: state-witness size exceeding the combined limit, potential chunk-validator disagreement on witness validity, and liveness risk if the oversized witness cannot be distributed within the network's bandwidth constraints.

### Likelihood Explanation

Any account with enough NEAR to deploy a contract can trigger this. The pattern is: deploy a contract, call a method that creates a near-maximum-size receipt C and does `promise_return(C)` from a callback that itself has `output_data_receivers`. The runtime appends those receivers to C after validation. No special privilege is required. [7](#0-6) 

### Recommendation

After the `output_data_receivers` append at lines 1029–1035, re-run `validate_receipt` with `ValidateReceiptMode::NewReceipt` on the mutated receipt. If the size now exceeds `max_receipt_size`, set `result.result` to `Err(ActionErrorKind::NewReceiptValidationError(ReceiptValidationError::ReceiptSizeExceeded {...}))` and do not forward the receipt. Apply the same fix to the `value_return` → `DataReceipt` path by checking the total borsh size of the data receipt envelope, not just the payload length.

### Proof of Concept

The nearcore test suite already demonstrates the bug end-to-end:

```
test_max_receipt_size_promise_return  (test-loop-tests/src/tests/max_receipt_size.rs:130)
test_max_receipt_size_value_return    (test-loop-tests/src/tests/max_receipt_size.rs:216)
```

Both tests call `assert_oversized_receipt_occurred`, which walks the chain and confirms that a receipt with `borsh_size > max_receipt_size` was forwarded and included in a chunk — proving the size gate was bypassed. [8](#0-7)

### Citations

**File:** runtime/runtime/src/lib.rs (L856-865)
```rust
                if let Err(e) = new_result.new_receipts.iter().try_for_each(|receipt| {
                    validate_receipt(
                        &apply_state.config.wasm_config.limit_config,
                        receipt,
                        apply_state.current_protocol_version,
                        ValidateReceiptMode::NewReceipt,
                    )
                }) {
                    new_result.result = Err(ActionErrorKind::NewReceiptValidationError(e).into());
                }
```

**File:** runtime/runtime/src/lib.rs (L1020-1037)
```rust
            if let Ok(ReturnData::ReceiptIndex(receipt_index)) = result.result {
                // Modifying a new receipt instead of sending data
                match result
                    .new_receipts
                    .get_mut(receipt_index as usize)
                    .expect("the receipt for the given receipt index should exist")
                    .receipt_mut()
                {
                    ReceiptEnum::Action(new_action_receipt)
                    | ReceiptEnum::PromiseYield(new_action_receipt) => new_action_receipt
                        .output_data_receivers
                        .extend_from_slice(&action_receipt.output_data_receivers()),
                    ReceiptEnum::ActionV2(new_action_receipt)
                    | ReceiptEnum::PromiseYieldV2(new_action_receipt) => new_action_receipt
                        .output_data_receivers
                        .extend_from_slice(&action_receipt.output_data_receivers()),
                    _ => unreachable!("the receipt should be an action receipt"),
                }
```

**File:** runtime/runtime/src/lib.rs (L2512-2518)
```rust
            validate_receipt(
                &processing_state.apply_state.config.wasm_config.limit_config,
                receipt,
                protocol_version,
                ValidateReceiptMode::ExistingReceipt,
            )
            .map_err(RuntimeError::ReceiptValidationError)?;
```

**File:** runtime/runtime/src/verifier.rs (L580-585)
```rust
    /// be less strict because:
    /// 1) Older receipts might have been created before new validation rules.
    /// 2) There is a bug which allows to create receipts that are above the size limit. Runtime has
    ///    to handle them gracefully until the receipt size limit bug is fixed.
    ///    See https://github.com/near/nearcore/issues/12606 for details.
    ExistingReceipt,
```

**File:** runtime/runtime/src/verifier.rs (L619-630)
```rust
fn validate_data_receipt(
    limit_config: &LimitConfig,
    receipt: &DataReceipt,
) -> Result<(), ReceiptValidationError> {
    let data_len = receipt.data.as_ref().map(|data| data.len()).unwrap_or(0);
    if data_len as u64 > limit_config.max_length_returned_data {
        return Err(ReceiptValidationError::ReturnedValueLengthExceeded {
            length: data_len as u64,
            limit: limit_config.max_length_returned_data,
        });
    }
    Ok(())
```

**File:** runtime/runtime/src/congestion_control.rs (L413-427)
```rust
        // There is a bug which allows to create receipts that are above the size limit. Receipts
        // above the size limit might not fit under the maximum outgoing size limit. Let's pretend
        // that all receipts are at most `max_receipt_size` to avoid receipts getting stuck.
        // See https://github.com/near/nearcore/issues/12606
        let max_receipt_size = apply_state.config.wasm_config.limit_config.max_receipt_size;
        if size > max_receipt_size {
            tracing::debug!(
                target: "runtime",
                receipt_id=?receipt.receipt_id(),
                size,
                max_receipt_size,
                "try_forward observed a receipt with size exceeding the size limit",
            );
            size = max_receipt_size;
        }
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L124-128)
```rust
// A function call will generate a new receipt. Size of this receipt will be equal to
// `max_receipt_size`, it'll pass validation, but then `output_data_receivers` will be modified and
// the receipt's size will go above max_receipt_size. The receipt should be rejected, but currently
// isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
// Runtime shouldn't die when it encounters a receipt with size above `max_receipt_size`.
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L350-420)
```rust
/// Assert that there was an incoming receipt with size above max_receipt_size
fn assert_oversized_receipt_occurred(node: &TestLoopNode<'_>) {
    let client = node.client();
    let chain = &client.chain;
    let epoch_manager = &*client.epoch_manager;

    let tip = chain.head().unwrap();
    let epoch_id = epoch_manager.get_epoch_id(&tip.last_block_hash).unwrap();
    let protocol_version = epoch_manager.get_epoch_protocol_version(&epoch_id).unwrap();
    let runtime_config = client.runtime_adapter.get_runtime_config(protocol_version);
    let max_receipt_size = runtime_config.wasm_config.limit_config.max_receipt_size;

    let mut block = chain.get_block(&tip.last_block_hash).unwrap();

    // Go over all blocks down to genesis looking for a receipt above max_receipt_size.
    loop {
        if block.header().is_genesis() {
            panic!("Didn't find receipt with size above max_receipt_size!");
        }
        let prev_block = chain.get_block(block.header().prev_hash()).unwrap();

        let shard_layout = epoch_manager
            .get_shard_layout(&epoch_manager.get_epoch_id(block.hash()).unwrap())
            .unwrap();

        let oversized = if ProtocolFeature::Spice.enabled(protocol_version) {
            // With spice chunks are executed asynchronously and their produced receipts are
            // persisted as receipt proofs keyed by the block in which the chunk was applied,
            // rather than as incoming receipts on the following block.
            shard_layout.shard_ids().any(|shard_id| {
                chain
                    .chain_store()
                    .iter_receipt_proofs_for_shard(block.hash(), shard_id)
                    .iter()
                    .flat_map(|proof| proof.0.iter())
                    .any(|receipt| receipt_is_oversized(receipt, max_receipt_size))
            })
        } else {
            block.chunks().iter_new().any(|new_chunk| {
                let shard_id = new_chunk.shard_id();
                let prev_shard_index = epoch_manager
                    .get_prev_shard_id_from_prev_hash(block.header().prev_hash(), shard_id)
                    .unwrap()
                    .2;
                let prev_height_included =
                    prev_block.chunks().get(prev_shard_index).unwrap().height_included();
                let incoming_receipts_proofs = get_incoming_receipts_for_shard(
                    &chain.chain_store,
                    epoch_manager,
                    shard_id,
                    &shard_layout,
                    *block.hash(),
                    prev_height_included,
                    ReceiptFilter::TargetShard,
                )
                .unwrap();
                incoming_receipts_proofs
                    .iter()
                    .flat_map(|response| response.1.iter())
                    .flat_map(|proof| proof.0.iter())
                    .any(|receipt| receipt_is_oversized(receipt, max_receipt_size))
            })
        };

        if oversized {
            return;
        }

        block = prev_block;
    }
}
```
