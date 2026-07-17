### Title
Receipt Size Limit Bypassed via `promise_return` Mutation After Validation — (`File: runtime/runtime/src/lib.rs`)

### Summary

An unprivileged user can craft a contract that produces a receipt exactly at `max_receipt_size` (4 MiB), which passes the `NewReceipt` size check. The runtime then **mutates** that already-validated receipt by appending `output_data_receivers` from the parent receipt (the `promise_return` path), pushing it above the limit. The mutated receipt is never re-validated and enters the chain as an oversized receipt, violating the hard `max_receipt_size` invariant. This is tracked as nearcore issue #12606 and is explicitly acknowledged in production code.

### Finding Description

The `validate_receipt` function enforces `max_receipt_size` only when called with `ValidateReceiptMode::NewReceipt`: [1](#0-0) 

After each action executes, new receipts are validated immediately: [2](#0-1) 

However, after that validation, the `promise_return` path in `apply_action_receipt` **mutates** the already-validated receipt by appending `output_data_receivers` from the parent receipt: [3](#0-2) 

This mutation happens **after** `validate_receipt` has already approved the receipt. No re-validation occurs. The receipt is then forwarded or buffered without any size check.

When the receipt later arrives as an incoming or delayed receipt, it is validated with `ValidateReceiptMode::ExistingReceipt`, which **explicitly skips** the size check: [4](#0-3) 

The production comment at line 583–584 reads: *"There is a bug which allows to create receipts that are above the size limit. Runtime has to handle them gracefully until the receipt size limit bug is fixed. See https://github.com/near/nearcore/issues/12606 for details."*

The test file confirms the exploit path and that oversized receipts reach the chain: [5](#0-4) 

### Impact Explanation

`max_receipt_size = 4,194,304` bytes is a **hard limit** designed to keep `ChunkStateWitness` under 17 MiB. Receipts above this limit violate the state witness size budget. Chunk validators enforce these limits independently; if a chunk producer includes an oversized receipt, validators may compute a different chunk application result and refuse to endorse the chunk, potentially causing a chain stall. The corrupted value is the receipt's serialized size exceeding `limit_config.max_receipt_size`. [6](#0-5) 

### Likelihood Explanation

Any unprivileged user who can deploy a contract can trigger this. The attack requires:
1. Deploy a contract that creates a receipt with `args` sized to exactly fill `max_receipt_size`.
2. Use `promise_return` so the runtime appends `output_data_receivers` post-validation.

The test `test_max_receipt_size_promise_return` demonstrates this is reachable with standard contract calls. [7](#0-6) 

### Recommendation

Re-validate the receipt **after** `output_data_receivers` are appended at lines 1029–1035 of `runtime/runtime/src/lib.rs`. Specifically, call `validate_receipt(..., ValidateReceiptMode::NewReceipt)` on the mutated receipt before it is added to `result.new_receipts` or forwarded. Alternatively, enforce the size check inside the `extend_from_slice` path itself, returning an `ActionErrorKind::NewReceiptValidationError` if the post-mutation size exceeds `max_receipt_size`.

### Proof of Concept

1. Deploy a contract with a method `max_receipt_size_promise_return_method1` that:
   - Creates promise DAG `[A -then-> B]`
   - When A executes, creates promise C with `args` sized so `borsh(C) == max_receipt_size`
   - Calls `promise_return(C)` — this causes the runtime to append B's `output_data_receivers` to C
2. Submit a transaction calling this method.
3. Observe that receipt C, now `> max_receipt_size`, is forwarded into the chain.

The existing test `test_max_receipt_size_promise_return` in `test-loop-tests/src/tests/max_receipt_size.rs` reproduces this exactly and asserts `assert_oversized_receipt_occurred`, confirming the oversized receipt is present in the chain. [8](#0-7)

### Citations

**File:** runtime/runtime/src/verifier.rs (L527-542)
```rust
pub(crate) fn validate_receipt(
    limit_config: &LimitConfig,
    receipt: &Receipt,
    current_protocol_version: ProtocolVersion,
    mode: ValidateReceiptMode,
) -> Result<(), ReceiptValidationError> {
    if mode == ValidateReceiptMode::NewReceipt {
        let receipt_size: u64 =
            borsh::object_length(receipt).unwrap().try_into().expect("Can't convert usize to u64");
        if receipt_size > limit_config.max_receipt_size {
            return Err(ReceiptValidationError::ReceiptSizeExceeded {
                size: receipt_size,
                limit: limit_config.max_receipt_size,
            });
        }
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

**File:** runtime/runtime/src/lib.rs (L855-866)
```rust
            if new_result.result.is_ok() {
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

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L124-128)
```rust
// A function call will generate a new receipt. Size of this receipt will be equal to
// `max_receipt_size`, it'll pass validation, but then `output_data_receivers` will be modified and
// the receipt's size will go above max_receipt_size. The receipt should be rejected, but currently
// isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
// Runtime shouldn't die when it encounters a receipt with size above `max_receipt_size`.
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L150-208)
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
}
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L422-429)
```rust
fn receipt_is_oversized(receipt: &Receipt, max_receipt_size: u64) -> bool {
    let receipt_size: u64 = borsh::object_length(receipt).unwrap().try_into().unwrap();
    if receipt_size > max_receipt_size {
        tracing::info!(%receipt_size, %max_receipt_size, "found receipt above max size");
        return true;
    }
    false
}
```

**File:** docs/misc/state_witness_size_limits.md (L1-18)
```markdown
## State witness size limits

Some limits were introduced to keep the size of `ChunkStateWitness` reasonable.
`ChunkStateWitness` contains all the incoming transactions and receipts that will be processed during chunk application and in theory a single receipt could be tens of megabytes in size. Distributing a `ChunkStateWitness` this large would be troublesome, so we limit the size and number of transactions, receipts, etc. The limits aim to keep the total uncompressed size of `ChunkStateWitness` under 17MiB.

There are two types of size limits:

* Hard limit - the size must be below this limit, anything else is considered invalid
* Soft limit - things are added until the limit is exceeded, after that things stop being added. The last added thing is allowed to slightly exceed the limit.

The limits are:

* `max_transaction_size = 1.5 MiB`
  * All transactions must be below 1.5 MiB, otherwise they'll be considered invalid and rejected.
  * Previously was 4MiB, now reduced to 1.5MiB
* `max_receipt_size - 4 MiB`:
  * All receipts must be below 4 MiB, otherwise they'll be considered invalid and rejected.
  * Previously there was no limit on receipt size. Set to 4MiB, might be reduced to 1.5MiB in the future to match the transaction limit.
```
