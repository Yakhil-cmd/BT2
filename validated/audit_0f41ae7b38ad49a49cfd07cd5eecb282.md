### Title
Receipt size limit is checked only at creation time and not re-checked after later modification, allowing receipts that exceed `max_receipt_size` to be produced and propagated - ([File: runtime/runtime/src/verifier.rs])

### Summary
The report describes a class of bug where a length/size limit is enforced when an object is *created* but not re-checked at the point it is actually *used/accepted*, letting a crafted or incidentally-modified object bypass the limit. Nearcore has a structurally identical gap in receipt-size validation: the `max_receipt_size` bound is enforced only when a receipt is first validated as "new", but the runtime subsequently mutates already-validated receipts (appending `output_data_receivers`) without re-validating size, and receipts received from other shards are validated in a mode that skips the size check entirely.

### Finding Description
`validate_receipt` only performs the size check when `mode == ValidateReceiptMode::NewReceipt`: [1](#0-0) 

The `ValidateReceiptMode::ExistingReceipt` variant is explicitly documented as *intentionally* skipping this check, with an inline acknowledgment that “there is a bug which allows to create receipts that are above the size limit”: [2](#0-1) 

Separately, after a function call's promises/receipts have already been created and (in the `NewReceipt` path) validated, the runtime appends `output_data_receivers` to one of the newly created receipts (the receipt that ultimately returns a value via `ReturnData::ReceiptIndex`) without re-running `validate_receipt`: [3](#0-2) 

This mirrors the report's pattern exactly: the check (`num_commitments > MAX_COMMITMENTS` / here, `receipt_size > limit_config.max_receipt_size`) is applied at a specific creation checkpoint, but a subsequent mutation step that grows the object is not re-validated, and a second, more permissive code path (`ExistingReceipt`/verifier for already-verified proofs) accepts the object without checking the limit at all. Downstream code is aware this can happen and has added defensive clamps rather than fixing the root cause, e.g. in the congestion-control forwarding and bandwidth-request logic, both of which explicitly reference the same tracked bug: [4](#0-3) [5](#0-4) 

This is confirmed to be reachable from ordinary, unprivileged contract calls in the test suite, which reproduces exactly the "creation-time check passes, then a subsequent modification exceeds the limit, but is not rejected" scenario: [6](#0-5) 

### Impact Explanation
An oversized receipt can be produced by any account through a normal cross-contract call chain (no validator or node privilege required) and then propagate through the system as an "existing" receipt whose size is never re-validated. This is unbounded/underprivileged resource use: it can bypass the `max_receipt_size` admission control that other parts of the system (state witness size limits, bandwidth scheduler, outgoing receipt buffers) assume holds, potentially causing outsized state witnesses, receipts stuck in buffers, or inconsistent behavior between nodes handling the oversized receipt differently. The team's own mitigations (clamping sizes in `try_forward` and `generate_bandwidth_request`) are workarounds, not fixes, and only address two specific consumers of receipt size — other consumers of `Receipt` size assumptions are not necessarily protected.

### Likelihood Explanation
High likelihood of triggering: it requires only a single unprivileged transaction with a contract that creates a promise chain sized close to `max_receipt_size` and returns a receipt index (so `output_data_receivers` get appended post-validation) — exactly as exercised by `test_max_receipt_size_promise_return` and `test_max_receipt_size_value_return` in the existing test suite, both of which are explicitly labeled as demonstrating the still-open bug (nearcore issue #12606).

### Recommendation
Re-validate receipt size (and other `NewReceipt`-only limits) after any post-creation mutation of a receipt (e.g., after `output_data_receivers` are appended in `runtime/runtime/src/lib.rs`), rather than validating only once at creation. Additionally, `ValidateReceiptMode::ExistingReceipt` should not be used as a permanent bypass for the size check; the underlying bug (#12606) should be fixed at the source (rejecting the mutation, or accounting for the added bytes before the size check is performed) rather than mitigated downstream in `congestion_control.rs`.

### Proof of Concept
This is directly reproduced by the codebase's own regression test, which documents the still-present bug: [6](#0-5) 
1. Deploy `near_test_contracts::rs_contract()`.
2. Call `max_receipt_size_promise_return_method1` with an `args_size` chosen so the initial receipt for promise `A` is exactly `max_receipt_size` bytes (passes the `NewReceipt` size check).
3. When promise `A` executes and calls `promise_return`, the runtime appends `output_data_receivers` to the already-validated receipt for the next promise `C`, pushing its size above `max_receipt_size` — without any re-validation.
4. `assert_oversized_receipt_occurred` confirms an incoming receipt with `size > max_receipt_size` is present on-chain, proving the size limit was bypassed.

**Note on confidence:** I was unable to fully trace, due to tool-call limits in this final iteration, the exact call site in `runtime/runtime/src/lib.rs` where `validate_receipt` with `NewReceipt` mode is first invoked on the freshly created receipt (before the later `output_data_receivers` mutation shown at lines 1019-1037). The existence and mechanics of the gap are nonetheless strongly corroborated by the explicit code comments in `verifier.rs` and `congestion_control.rs` referencing the tracked bug, and by the dedicated regression tests in `test-loop-tests/src/tests/max_receipt_size.rs` that reproduce it end-to-end.

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

**File:** runtime/runtime/src/congestion_control.rs (L556-562)
```rust
        // There's a bug which allows to create receipts above `max_receipt_size` (https://github.com/near/nearcore/issues/12606).
        // This could cause problems with bandwidth scheduler which would generate requests for size above max size, and these
        // requests would never be fulfilled. For bandwidth requests let's pretend that all sizes are below `max_receipt_size`.
        // The same pretending logic is also present in `try_forward` which compares receipt size with outgoing limit.
        // This logic should also make it possible to do protocol upgrades that lower `max_receipt_size` without too much trouble.
        let sizes_iter = receipt_sizes_iter
            .map_ok(|group_size| std::cmp::min(group_size, params.max_receipt_size));
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
