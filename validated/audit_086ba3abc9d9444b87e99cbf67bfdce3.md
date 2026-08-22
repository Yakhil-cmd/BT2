Root cause and exploit path confirmed by the codebase itself.

### Title
Undercounted congestion/bandwidth accounting for oversized receipts smuggles bytes past outgoing size limits - ([File: runtime/runtime/src/congestion_control.rs])

### Summary
An unprivileged account can create an oversized `Receipt` via the known `output_data_receivers`/`promise_return` growth bug (tracked as near/nearcore#12606), which bypasses `validate_receipt`'s size check because the check runs before `output_data_receivers` are appended. `ReceiptSinkV2::try_forward` then deliberately clamps the accounted size to `max_receipt_size` while forwarding the full, larger receipt, so the byte accounting against `outgoing_limit`/bandwidth grants understates the real bytes placed on the wire.

### Finding Description
`validate_receipt` in `runtime/runtime/src/verifier.rs` (lines 526-542) only checks `borsh::object_length(receipt) <= max_receipt_size` for `ValidateReceiptMode::NewReceipt`. In `runtime/runtime/src/lib.rs` (lines 1008-1057), after a `FunctionCall` returns `ReturnData::ReceiptIndex`, the code extends `new_action_receipt.output_data_receivers` with the caller's `action_receipt.output_data_receivers()` *after* the receipt was already created/sized, so the final serialized receipt can exceed `max_receipt_size` without failing validation. This exact bug is acknowledged in-code: `ValidateReceiptMode::ExistingReceipt` doc comment explicitly references issue #12606, and `test-loop-tests/src/tests/max_receipt_size.rs::test_max_receipt_size_promise_return` (and `test_max_receipt_size_value_return`) reproduce it and assert the oversized receipt does end up on-chain via `assert_oversized_receipt_occurred`.

Once such an oversized receipt reaches `ReceiptSinkV2::try_forward` (`runtime/runtime/src/congestion_control.rs` lines 403-427), the code detects `size > max_receipt_size` and explicitly clamps `size = max_receipt_size` before subtracting it from `forward_limit.size` and recording it in `stats.forwarded_receipts` (lines 451-456). The comment states this is intentional, to avoid receipts getting permanently stuck when they exceed the accounting limit, per issue #12606. However, the real receipt object (uncapped size) is what gets pushed into `outgoing_receipts` and eventually serialized onto the wire / into the outgoing receipt proofs, while the shard's `outgoing_limit.size` (derived from `bandwidth_scheduler_output.granted_bandwidth`, tied to `outgoing_receipts_usual_size_limit`/`outgoing_receipts_big_size_limit`) is only debited by the clamped `max_receipt_size` amount. This lets an attacker's oversized receipt consume less bandwidth "budget" than its real byte footprint, letting extra bytes (the delta between real size and `max_receipt_size`) pass unaccounted through the per-shard size gate.

### Impact Explanation
This is validator/node resource-exhaustion class: unaccounted bytes in outgoing receipt forwarding inflate the actual amount of data (state witnesses, receipt proofs, network payload) beyond what the bandwidth scheduler/congestion accounting believes it granted, undermining the "congestion/bandwidth accounting completeness" invariant. It does not itself cause fund loss but degrades the guarantees congestion control provides (state witness/proof size bounding, shard-to-shard bandwidth fairness), which can be leveraged by unprivileged attackers to push disproportionately large receipts through the network relative to the accounted budget.

### Likelihood Explanation
This requires only: (1) deploying a contract, (2) invoking a promise chain that hits the known `output_data_receivers` growth-after-validation bug (`promise_batch_then` with `promise_return`, as reproduced by `max_receipt_size_promise_return_method1/2` in `runtime/near-test-contracts/test-contract-rs/src/lib.rs`), all of which is achievable by any ordinary account through public RPC — no privileged access needed. The underlying oversized-receipt bug is already documented and reproducible by the existing test suite, making this fully repeatable.

### Recommendation
Fix the root cause: re-validate/re-check receipt size in `runtime/runtime/src/lib.rs` after `output_data_receivers` are appended to a returned receipt (not only prior to that mutation), so oversized receipts are rejected at creation time (issue #12606) instead of silently exceeding `max_receipt_size`. As defense in depth, `ReceiptSinkV2::try_forward` in `runtime/runtime/src/congestion_control.rs` should account against `outgoing_limit`/`stats.forwarded_receipts` using the *actual* computed `size`, not the clamped value, while separately handling the "avoid getting stuck" liveness concern (e.g., by allowing a one-time overflow-forward but still debiting the real size, or capping the limit floor at zero rather than under-charging).

### Proof of Concept
Extend `test-loop-tests/src/tests/max_receipt_size.rs::test_max_receipt_size_promise_return`: after `assert_oversized_receipt_occurred`, additionally capture the `ReceiptSinkStats`/`ChunkApplyStats` for the chunk that forwarded the oversized receipt (via `chunk_apply_stats` or `ReceiptSinkStats::forwarded_receipts`), compute the real `borsh::object_length` of the forwarded receipt, and assert that the recorded `ReceiptsStats` size entry equals the real size rather than the clamped `max_receipt_size`. The test should fail today (proving the discrepancy) since `try_forward` (`runtime/runtime/src/congestion_control.rs:403-427`) always records the clamped size in `stats.forwarded_receipts`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** runtime/runtime/src/congestion_control.rs (L403-427)
```rust
    fn try_forward(
        receipt: Receipt,
        gas: Gas,
        mut size: u64,
        shard: ShardId,
        outgoing_limit: &mut HashMap<ShardId, OutgoingLimit>,
        outgoing_receipts: &mut Vec<Receipt>,
        apply_state: &ApplyState,
        stats: &mut ReceiptSinkStats,
    ) -> Result<ReceiptForwarding, RuntimeError> {
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

**File:** runtime/runtime/src/congestion_control.rs (L451-456)
```rust
        if forward_limit.gas >= admission_gas && forward_limit.size >= size {
            tracing::trace!(target: "runtime", ?shard, receipt_id=?receipt.receipt_id(), "forwarding buffered receipt");
            outgoing_receipts.push(receipt);
            forward_limit.gas = forward_limit.gas.saturating_sub(gas);
            forward_limit.size -= size;
            stats.forwarded_receipts.entry(shard).or_default().add_receipt(size, gas);
```

**File:** runtime/runtime/src/verifier.rs (L526-542)
```rust
/// Validates a given receipt. Checks validity of the Action or Data receipt.
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

**File:** runtime/runtime/src/lib.rs (L1013-1038)
```rust
        // Generating outgoing data
        // A {
        // B().then(C())}  B--data receipt->C

        // A {
        // B(); 42}
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
            } else {
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L124-208)
```rust
// A function call will generate a new receipt. Size of this receipt will be equal to
// `max_receipt_size`, it'll pass validation, but then `output_data_receivers` will be modified and
// the receipt's size will go above max_receipt_size. The receipt should be rejected, but currently
// isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
// Runtime shouldn't die when it encounters a receipt with size above `max_receipt_size`.
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

**File:** runtime/near-test-contracts/test-contract-rs/src/lib.rs (L1871-1940)
```rust
/// Create promise DAG:
/// A[self.max_receipt_size_promise_return_method2()] -then-> B[self.mark_test_completed()]
#[no_mangle]
pub unsafe fn max_receipt_size_promise_return_method1() {
    input(0);
    let mut args = vec![0u8; register_len(0) as usize];
    read_register(0, args.as_mut_ptr());

    current_account_id(0);
    let current_account = vec![0u8; register_len(0) as usize];
    read_register(0, current_account.as_ptr() as _);

    let method2 = b"max_receipt_size_promise_return_method2";
    let promise_a = promise_create(
        current_account.len() as u64,
        current_account.as_ptr() as u64,
        method2.len() as u64,
        method2.as_ptr() as u64,
        args.len() as u64, // Forward the args
        args.as_ptr() as u64,
        0,
        200 * TGAS,
    );

    let empty_args: &[u8] = &[];
    let test_completed_method = b"mark_test_completed";
    let _promise_b = promise_then(
        promise_a,
        current_account.len() as u64,
        current_account.as_ptr() as u64,
        test_completed_method.len() as u64,
        test_completed_method.as_ptr() as u64,
        empty_args.len() as u64,
        empty_args.as_ptr() as u64,
        0,
        20 * TGAS,
    );
}

/// Do a promise_return with a large receipt.
/// The receipt has a single FunctionCall action with large args.
/// Creates DAG:
/// C[self.noop(large_args)] -then-> B[self.mark_test_completed()]
#[no_mangle]
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
}
```
