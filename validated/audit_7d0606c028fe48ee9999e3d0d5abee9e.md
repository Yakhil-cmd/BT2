## Title
Receipts can exceed `max_receipt_size` after post-validation mutation (output_data_receivers / promise_return), bypassing the size limit enforced at creation — ([File: runtime/runtime/src/verifier.rs])

### Summary
This is a legitimate analog of the reported bug class: a hard limit (`max_receipt_size` in `LimitConfig`) is enforced at one point in the pipeline but can be violated later through a different code path that mutates the already-validated object, exactly mirroring the FantiumMinterV1/FantiumNFTV1 pattern where `maxInvocation` is assumed bounded by one contract but not enforced by the other's setters.

### Finding Description
`validate_receipt` in `runtime/runtime/src/verifier.rs` enforces `receipt_size <= limit_config.max_receipt_size` only when `mode == ValidateReceiptMode::NewReceipt` [1](#0-0) . However, the codebase's own `ValidateReceiptMode::ExistingReceipt` variant documents that this check can be bypassed after the fact: "There is a bug which allows to create receipts that are above the size limit. Runtime has to handle them gracefully until the receipt size limit bug is fixed." with an explicit reference to near/nearcore#12606 [2](#0-1) .

The concrete mechanism, confirmed by the in-repo regression tests in `test-loop-tests/src/tests/max_receipt_size.rs`, is: a receipt is created and validated against `max_receipt_size` when it is first constructed (e.g., via `promise_batch_action_function_call`/`create_action_receipt` in the VM logic host functions), but it is later mutated by a *separate* code path — appending `output_data_receivers` when a promise is chained via `promise_return`, or attaching a large returned value that becomes a `DataReceipt` — without re-validating the size limit at that point [3](#0-2) . The test explicitly states: "the receipt has a single FunctionCall action with large args... Adding the `output_data_receivers` to C's receipt makes it go over the size limit" and that the receipt "should be rejected, but currently isn't because of a bug" [4](#0-3) . The same pattern recurs for large return values turned into oversized `DataReceipt`s [5](#0-4) .

This is structurally identical to the reported bug class: one code path (`FantiumMinterV1` / here, receipt creation-time validation in `validate_receipt`) assumes a hard cap, while another code path (`FantiumNFTV1` setters / here, the output-data-receiver attachment and value-return logic in the receipt manager and action execution) can push the value above that cap without re-checking it.

### Impact Explanation
Receipts above `max_receipt_size` are a resource-accounting invariant violation: `max_receipt_size` bounds storage, serialization cost, and cross-shard networking size assumptions throughout the protocol (state witnesses, receipt proofs, congestion control size accounting referenced in `congestion_control.rs`). Allowing receipts to silently exceed this bound risks unbounded resource use in receipt/state-witness handling and out-of-band divergence between nodes that assume the bound holds (the `ExistingReceipt` mode exists specifically to tolerate this divergence when replaying/validating historical state). The nearcore team's own comment frames this as requiring "handle them gracefully" rather than "this can't happen," which is itself evidence that oversized receipts are reachable in production and must be defended against at every consumer of receipt size assumptions, not just at creation time — the same "must check limit everywhere, not just in one place" defect pattern as the external report.

### Likelihood Explanation
High, in the sense that this is not a hypothetical: the repository already contains a tracked issue (near/nearcore#12606) and dedicated regression tests (`test_max_receipt_size_promise_return`, `test_max_receipt_size_value_return`) that reproduce oversized receipts via ordinary contract calls (`promise_return`, `promise_create`, large return values) reachable from any account submitting a transaction — no privileged or validator-only access is required. The bug is triggered purely through normal, unprivileged smart-contract execution.

### Recommendation
Re-validate `receipt_size <= max_receipt_size` at every point where a receipt's serialized content can grow after its initial creation-time check — specifically after `output_data_receivers` are appended (in `receipt_manager.rs` / wherever `promise_then`/`promise_return` attaches data receivers) and after large return values are wrapped into `DataReceipt`s — rather than relying solely on the single check in `validate_receipt` under `ValidateReceiptMode::NewReceipt`. This mirrors the external report's recommendation: every function that can push a bounded quantity (there, `maxInvocation`; here, receipt size) above its limit must itself enforce that limit, not just the function that first sets/creates the value.

### Proof of Concept
The existing repository test `test_max_receipt_size_promise_return` in `test-loop-tests/src/tests/max_receipt_size.rs` is a working PoC: it deploys a contract, calls `max_receipt_size_promise_return_method1` with `args_size` sized so the intermediate receipt is at exactly `max_receipt_size`, then triggers `promise_return` from within a chained promise so that `output_data_receivers` are appended post-validation, pushing the receipt above the limit; `assert_oversized_receipt_occurred` then confirms an oversized receipt was actually included in a block despite the limit [6](#0-5) . The analogous `test_max_receipt_size_value_return` reproduces the same outcome via a large returned value turned into an oversized `DataReceipt` [7](#0-6) .

Note on completeness: I was not able to fully trace, within the available indexed context, the exact line(s) in `receipt_manager.rs`/`actions.rs` where `output_data_receivers` are appended without a follow-up size check (grep confirmed the relevant matches exist in those files, but full function bodies were not retrieved before the iteration limit). A Devin session with full repository access would be needed to pinpoint the exact append site(s) for a complete patch.

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

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L210-267)
```rust
/// Return a value that is as large as max_receipt_size. The value will be wrapped in a data receipt
/// and the data receipt will be bigger than max_receipt_size. The receipt should be rejected, but
/// currently isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
/// Creates the following promise DAG:
/// A[self.return_large_value()] -then-> B[self.mark_test_completed()]
#[test]
fn test_max_receipt_size_value_return() {
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

    let max_receipt_size = 4_194_304;

    // Call the contract
    let large_receipt_tx = SignedTransaction::call(
        102,
        account.clone(),
        account.clone(),
        &account_signer,
        Balance::ZERO,
        "max_receipt_size_value_return_method".into(),
        format!("{{\"value_size\": {}}}", max_receipt_size).into(),
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
