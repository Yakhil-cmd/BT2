### Title
Receipt Size Limit Bypassed via Post-Validation `output_data_receivers` Mutation — (`File: runtime/runtime/src/lib.rs`)

### Summary
The `max_receipt_size` invariant is enforced on newly-created receipts before `output_data_receivers` are appended to them. When a contract uses `promise_return`, the runtime mutates the already-validated receipt by extending its `output_data_receivers` field, causing the final receipt stored in state to exceed `max_receipt_size` with no re-validation. This is a confirmed production bug (nearcore issue #12606) reachable by any unprivileged user.

### Finding Description

The `validate_receipt` function in `runtime/runtime/src/verifier.rs` enforces `max_receipt_size` only when called with `ValidateReceiptMode::NewReceipt`: [1](#0-0) 

After this validation passes, the runtime processes the `promise_return` path in `apply_action_receipt` inside `runtime/runtime/src/lib.rs`. When the parent receipt has non-empty `output_data_receivers` and the child returns a `ReturnData::ReceiptIndex`, the runtime directly mutates the already-validated child receipt by appending the parent's `output_data_receivers` to it: [2](#0-1) 

No re-validation of the receipt size occurs after this mutation. The receipt is then forwarded or buffered into state via `receipt_sink.forward_or_buffer_receipt` at line 1094 with its now-oversized serialized form. [3](#0-2) 

The `ValidateReceiptMode::ExistingReceipt` mode, used when reading receipts back from state, explicitly tolerates oversized receipts to handle this exact scenario: [4](#0-3) 

The nearcore team acknowledges this in the test file: [5](#0-4) 

### Impact Explanation

The broken invariant is: **every receipt stored in state must satisfy `size ≤ max_receipt_size`**. When violated:

1. **State witness size**: The `per_receipt_storage_proof_size_limit` and `main_storage_proof_size_soft_limit` calculations assume receipts are bounded by `max_receipt_size`. An oversized receipt inflates the state witness beyond protocol expectations.
2. **Congestion control**: `compute_receipt_size` is used to track congestion memory consumption. An oversized receipt causes `congestion_size` metadata to be incorrect, corrupting the congestion accounting for the shard.
3. **Protocol invariant**: The `max_receipt_size` limit is a consensus-level parameter. Receipts exceeding it are stored and executed, meaning the limit provides no actual enforcement guarantee. [6](#0-5) 

### Likelihood Explanation

Any unprivileged user can trigger this by:
1. Deploying a contract that creates a receipt with `args` sized to exactly `max_receipt_size - base_receipt_overhead`.
2. Calling that contract via a promise chain (`A.then(B)`) so that when `A` executes and calls `promise_return(C)`, the runtime appends `B`'s data receiver to `C`, pushing `C` over the limit.

The test `test_max_receipt_size_promise_return` demonstrates this is reachable with a standard function call transaction. [7](#0-6) 

### Recommendation

After the `output_data_receivers` extension at lines 1028–1035, re-validate the mutated receipt's size against `limit_config.max_receipt_size`. If the size is exceeded, return an `ActionError` with `NewReceiptValidationError(ReceiptSizeExceeded { … })` rather than forwarding the oversized receipt into state. This mirrors the existing guard in `validate_receipt` and closes the gap between validation time and mutation time.

### Proof of Concept

```
1. Deploy contract with method `max_receipt_size_promise_return_method1`
2. Submit tx: A calls method1(args_size = max_receipt_size - base_overhead)
   - method1 creates promise C (size = max_receipt_size) and does promise_return(C)
   - method1 is called via A.then(B), so B's data_receiver is appended to C
   - C's size = max_receipt_size + sizeof(DataReceiver) > max_receipt_size
3. C passes NewReceipt validation (before mutation), then is mutated and stored
4. assert_oversized_receipt_occurred() confirms the oversized receipt is in state
``` [8](#0-7)

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

**File:** runtime/runtime/src/lib.rs (L1089-1101)
```rust
                if new_receipt.is_instant_receipt() {
                    // Instant receipts are not sent as outgoing receipts, they will be processed immediately.
                    instant_receipts.push_back(new_receipt);
                } else {
                    // Send out the receipt as an outgoing receipt.
                    if let Err(e) = receipt_sink.forward_or_buffer_receipt(
                        new_receipt,
                        apply_state,
                        state_update,
                    ) {
                        return Some(Err(e));
                    }
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

**File:** runtime/runtime/src/congestion_control.rs (L957-967)
```rust
/// Calculate the size of a receipt before it is pushed into a state queue or
/// buffer. Please note that this method should only be used when storing
/// receipts into state. It should not be used for retrieving receipts from the
/// state.
///
/// The calculation is part of protocol and should only be modified with a
/// protocol upgrade.
pub(crate) fn compute_receipt_size(receipt: &Receipt) -> Result<u64, IntegerOverflowError> {
    let size = borsh::object_length(&receipt).unwrap();
    size.try_into().map_err(|_| IntegerOverflowError)
}
```
