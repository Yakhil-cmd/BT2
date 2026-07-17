### Title
Receipt `output_data_receivers` Extension After Size Validation Allows Oversized Receipts to Bypass `max_receipt_size` Limit — (`runtime/runtime/src/lib.rs`)

### Summary

The nearcore runtime validates a newly-created action receipt against `max_receipt_size` before the receipt is complete. When a contract uses `promise_return`, the runtime subsequently appends the parent receipt's `output_data_receivers` to the returned receipt **after** the size check has already passed. The combined receipt exceeds `max_receipt_size` and is forwarded without re-validation. This is an exact structural analog to M03: a size guard is applied to a partial object, and additional fields are appended later, silently violating the invariant.

### Finding Description

**Validation point** — `validate_receipt` with `ValidateReceiptMode::NewReceipt` checks the Borsh-serialized size of a receipt against `limit_config.max_receipt_size`: [1](#0-0) 

**Post-validation mutation** — After the function call completes and new receipts are assembled, `apply_action_receipt` in `lib.rs` detects a `ReturnData::ReceiptIndex` result and extends the returned receipt's `output_data_receivers` with those of the parent receipt: [2](#0-1) 

The `output_data_receivers` field is part of `ActionReceipt` / `ActionReceiptV2` and contributes to the Borsh-serialized size: [3](#0-2) 

**No re-validation** — After the extension the receipt is forwarded directly via `receipt_sink.forward_or_buffer_receipt` without a second size check. Incoming receipts on the receiving shard are validated only with `ValidateReceiptMode::ExistingReceipt`, which explicitly skips the size gate: [4](#0-3) 

**Codebase acknowledgement** — The bug is explicitly tracked as issue #12606 and the `ExistingReceipt` mode was added as a workaround so the runtime does not crash when it encounters these oversized receipts: [5](#0-4) 

The test `test_max_receipt_size_promise_return` reproduces the exact scenario and asserts that an oversized receipt does appear in the chain: [6](#0-5) 

A second variant, `test_max_receipt_size_value_return`, shows the same bypass via a large `value_return` that is wrapped in a data receipt whose size also exceeds the limit: [7](#0-6) 

### Impact Explanation

The `max_receipt_size` limit (4 MiB) is a hard protocol invariant. It exists to bound `ChunkStateWitness` size and to ensure the bandwidth scheduler can always grant enough bandwidth to forward any single receipt: [8](#0-7) [9](#0-8) 

An oversized receipt can:
1. Cause the bandwidth scheduler to be unable to grant sufficient bandwidth for the receipt group containing it, potentially stalling cross-shard delivery.
2. Push the uncompressed `ChunkStateWitness` beyond the 17 MiB design budget documented in `state_witness_size_limits.md`.
3. Permanently violate the protocol invariant for any receipt that enters the delayed queue, since delayed receipts are also validated only with `ExistingReceipt` mode.

### Likelihood Explanation

Any unprivileged user can trigger this with a single deployed contract. The attack requires:
1. Deploy a contract.
2. Call a method that creates a promise chain `[A -then-> B]`.
3. When A executes, create a receipt C whose Borsh size equals exactly `max_receipt_size` (crafted via large `args`), then call `promise_return(C)`.
4. The runtime extends C's `output_data_receivers` with B's data receiver, pushing C above the limit.

No validator, operator, or privileged role is required. The `max_receipt_size_promise_return_method1` test contract method demonstrates the exact construction.

### Recommendation

After the `output_data_receivers` extension at `lib.rs` lines 1029–1035, re-validate the modified receipt's Borsh size against `max_receipt_size` before forwarding it. If the size is exceeded, the function call should fail with `NewReceiptValidationError(ReceiptSizeExceeded)` rather than silently producing an oversized receipt. The same re-check should be applied to the `value_return` path where a data receipt wrapping the return value is constructed.

### Proof of Concept

```
1. Deploy a contract with method max_receipt_size_promise_return_method1.
2. Call the method with args_size = max_receipt_size - base_receipt_size.
   (base_receipt_size is the Borsh size of a minimal ActionReceiptV2 with one FunctionCall action.)
3. The contract creates [A -then-> B]; when A runs it creates receipt C of size
   exactly max_receipt_size and calls promise_return(C).
4. Runtime extends C.output_data_receivers with B's DataReceiver (~200 bytes).
5. C's Borsh size is now max_receipt_size + ~200 bytes > max_receipt_size.
6. C is forwarded as an outgoing receipt; the receiving shard accepts it under
   ExistingReceipt mode (no size check).
7. assert_oversized_receipt_occurred() confirms the oversized receipt is present
   in the chain's incoming receipt proofs.
``` [10](#0-9)

### Citations

**File:** runtime/runtime/src/verifier.rs (L533-541)
```rust
    if mode == ValidateReceiptMode::NewReceipt {
        let receipt_size: u64 =
            borsh::object_length(receipt).unwrap().try_into().expect("Can't convert usize to u64");
        if receipt_size > limit_config.max_receipt_size {
            return Err(ReceiptValidationError::ReceiptSizeExceeded {
                size: receipt_size,
                limit: limit_config.max_receipt_size,
            });
        }
```

**File:** runtime/runtime/src/verifier.rs (L573-586)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateReceiptMode {
    /// Used for validating new receipts that were just created.
    /// More strict than `OldReceipt` mode, which has to handle older receipts.
    NewReceipt,
    /// Used for validating older receipts that were saved in the state/received. Less strict than
    /// NewReceipt validation. Tolerates some receipts that wouldn't pass new validation. It has to
    /// be less strict because:
    /// 1) Older receipts might have been created before new validation rules.
    /// 2) There is a bug which allows to create receipts that are above the size limit. Runtime has
    ///    to handle them gracefully until the receipt size limit bug is fixed.
    ///    See https://github.com/near/nearcore/issues/12606 for details.
    ExistingReceipt,
}
```

**File:** runtime/runtime/src/lib.rs (L1019-1037)
```rust
        if !action_receipt.output_data_receivers().is_empty() {
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

**File:** core/primitives/src/receipt.rs (L597-598)
```rust
    /// If present, where to route the output data
    pub output_data_receivers: Vec<DataReceiver>,
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L124-128)
```rust
// A function call will generate a new receipt. Size of this receipt will be equal to
// `max_receipt_size`, it'll pass validation, but then `output_data_receivers` will be modified and
// the receipt's size will go above max_receipt_size. The receipt should be rejected, but currently
// isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
// Runtime shouldn't die when it encounters a receipt with size above `max_receipt_size`.
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L150-207)
```rust
    // User calls a contract method
    // Contract method creates a DAG with two promises: [A -then-> B]
    // When promise A is executed, it creates a third promise - `C` and does a `promise_return`.
    // The DAG changes to: [C ->then-> B]
    // The receipt for promise C is a maximum size receipt.
    // Adding the `output_data_receivers` to C's receipt makes it go over the size limit.
    let base_receipt_template = Receipt::V0(ReceiptV0 {
        predecessor_id: account.clone(),
        receiver_id: account.clone(),
        receipt_id: CryptoHash::default(),
        receipt: ReceiptEnum::Action(ActionReceipt {
            signer_id: account.clone(),
            signer_public_key: account_signer.public_key().into(),
            gas_price: Balance::ZERO,
            output_data_receivers: vec![],
            input_data_ids: vec![],
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "noop".into(),
                args: vec![],
                gas: Gas::ZERO,
                deposit: Balance::ZERO,
            }))],
        }),
    });
    let base_receipt_template = action_receipt_v1_to_latest(&base_receipt_template);
    let base_receipt_size = borsh::object_length(&base_receipt_template).unwrap();
    let max_receipt_size = 4_194_304;
    let args_size = max_receipt_size - base_receipt_size;

    // Call the contract
    let large_receipt_tx = SignedTransaction::call(
        102,
        account.clone(),
        account.clone(),
        &account_signer,
        Balance::ZERO,
        "max_receipt_size_promise_return_method1".into(),
        format!("{{\"args_size\": {}}}", args_size).into(),
        Gas::from_teragas(300),
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(large_receipt_tx, Duration::seconds(5));

    // Make sure that the last promise in the DAG was called
    let assert_test_completed = SignedTransaction::call(
        103,
        account.clone(),
        account,
        &account_signer,
        Balance::ZERO,
        "assert_test_completed".into(),
        "".into(),
        Gas::from_teragas(300),
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(assert_test_completed, Duration::seconds(5));

    assert_oversized_receipt_occurred(&env.validator());
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L210-213)
```rust
/// Return a value that is as large as max_receipt_size. The value will be wrapped in a data receipt
/// and the data receipt will be bigger than max_receipt_size. The receipt should be rejected, but
/// currently isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
/// Creates the following promise DAG:
```

**File:** core/store/src/trie/outgoing_metadata.rs (L96-104)
```rust
#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, ProtocolSchema)]
pub struct ReceiptGroupV0 {
    /// Total size of receipts in this group.
    /// Should be no larger than `max_receipt_size`, otherwise the bandwidth
    /// scheduler will not be able to grant the bandwidth needed to send
    /// the receipts in this group.
    pub size: u64,
    /// Total gas of receipts in this group.
    pub gas: u128,
```

**File:** core/primitives/src/bandwidth_scheduler.rs (L293-298)
```rust
    /// The maximum amount of bandwidth that can be granted on a single link.
    /// Should be at least as big as `max_receipt_size`.
    pub max_single_grant: Bandwidth,
    /// Maximum size of a single receipt.
    pub max_receipt_size: Bandwidth,
    /// Maximum bandwidth allowance that a link can accumulate.
```
