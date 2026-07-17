### Title
Receipt `max_receipt_size` Limit Bypassed via Post-Validation `output_data_receivers` Mutation in `promise_return` Path — (`runtime/runtime/src/lib.rs`)

### Summary
The `max_receipt_size` hard limit (4 MiB) is enforced when a receipt is first created, but the runtime subsequently appends `output_data_receivers` entries to that same receipt when `promise_return` is used. This post-validation mutation causes the final receipt to exceed `max_receipt_size` without triggering any re-validation, allowing oversized receipts to enter the network and violate the `ChunkStateWitness` size invariant.

### Finding Description
The `validate_receipt` function in `runtime/runtime/src/verifier.rs` enforces `max_receipt_size` only when called with `ValidateReceiptMode::NewReceipt`:

```rust
if mode == ValidateReceiptMode::NewReceipt {
    let receipt_size: u64 = borsh::object_length(receipt)...;
    if receipt_size > limit_config.max_receipt_size {
        return Err(ReceiptValidationError::ReceiptSizeExceeded { ... });
    }
}
``` [1](#0-0) 

This check runs at receipt creation time. However, in `apply_action_receipt` in `runtime/runtime/src/lib.rs`, when the executing receipt has non-empty `output_data_receivers` and the contract calls `promise_return(receipt_C)`, the runtime **mutates receipt C after validation** by extending its `output_data_receivers` with the parent receipt's receivers:

```rust
if let Ok(ReturnData::ReceiptIndex(receipt_index)) = result.result {
    match result.new_receipts.get_mut(receipt_index as usize)...receipt_mut() {
        ReceiptEnum::Action(new_action_receipt) | ... => new_action_receipt
            .output_data_receivers
            .extend_from_slice(&action_receipt.output_data_receivers()),
        ...
    }
}
``` [2](#0-1) 

The exact attack path:
1. An unprivileged user deploys a contract.
2. The contract creates receipt C via `promise_create` with args sized to exactly fill `max_receipt_size` (4,194,304 bytes). Receipt C passes `validate_receipt` with `NewReceipt` mode.
3. The contract creates a callback B via `promise_then`, giving the parent receipt a non-empty `output_data_receivers`.
4. The contract calls `promise_return(C)`.
5. At runtime, the parent's `output_data_receivers` (each entry is ~70+ bytes) are appended to receipt C's `output_data_receivers`. Receipt C now exceeds `max_receipt_size` with no re-validation.
6. The oversized receipt is forwarded to the network.

The codebase explicitly acknowledges this bug. `ValidateReceiptMode::ExistingReceipt` was introduced specifically to skip the size check for receipts already in the network:

> "There is a bug which allows to create receipts that are above the size limit. Runtime has to handle them gracefully until the receipt size limit bug is fixed. See https://github.com/near/nearcore/issues/12606 for details." [3](#0-2) 

The congestion control layer also has a workaround that clamps the reported size of oversized receipts to `max_receipt_size` for accounting purposes, but the actual receipt bytes are larger: [4](#0-3) 

### Impact Explanation
The `max_receipt_size` limit exists to keep `ChunkStateWitness` under 17 MiB. An oversized receipt violates this invariant:
- The `ChunkStateWitness` can exceed its intended 17 MiB bound.
- Congestion control accounting is corrupted: the receipt's size is clamped to `max_receipt_size` for gas/size tracking, but the actual bytes transmitted are larger, causing the outgoing size budget to be under-counted.
- The broken invariant is permanent for any receipt that enters the network via this path, as `ExistingReceipt` mode never re-checks the size.

### Likelihood Explanation
Any unprivileged user can trigger this with a single contract deployment and one function call. The contract logic required is minimal: `promise_create` with large args + `promise_then` + `promise_return`. The test `test_max_receipt_size_promise_return` in the repository confirms this is reproducible and that oversized receipts do reach the network. [5](#0-4) 

### Recommendation
After the `output_data_receivers` extension at `lib.rs:1029–1035`, re-measure the receipt size and reject the execution (returning an `ActionError::NewReceiptValidationError(ReceiptSizeExceeded)`) if the post-mutation size exceeds `max_receipt_size`. This mirrors how the yield path already enforces the limit at creation time before the receipt is finalized.

### Proof of Concept
The existing test `test_max_receipt_size_promise_return` in `test-loop-tests/src/tests/max_receipt_size.rs` is a complete proof of concept. It:
1. Deploys a contract.
2. Calls `max_receipt_size_promise_return_method1` which creates a near-max-size receipt C and does `promise_return(C)` inside a `promise_then` DAG.
3. Asserts via `assert_oversized_receipt_occurred` that a receipt with `size > max_receipt_size` was observed in the network. [5](#0-4) 

The root cause in `ReceiptManager::create_action_receipt` shows that `output_data_receivers` is initialized empty at receipt creation time (passing the size check), and only populated later during `apply_action_receipt`: [6](#0-5)

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

**File:** runtime/runtime/src/verifier.rs (L579-585)
```rust
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

**File:** runtime/runtime/src/receipt_manager.rs (L111-137)
```rust
    pub(super) fn create_action_receipt(
        &mut self,
        input_data_ids: Vec<CryptoHash>,
        receipt_indices: Vec<ReceiptIndex>,
        receiver_id: AccountId,
    ) -> Result<ReceiptIndex, VMLogicError> {
        assert_eq!(input_data_ids.len(), receipt_indices.len());
        for (data_id, receipt_index) in input_data_ids.iter().zip(receipt_indices.into_iter()) {
            self.action_receipts
                .get_mut(receipt_index as usize)
                .ok_or(HostError::InvalidReceiptIndex { receipt_index })?
                .output_data_receivers
                .push(DataReceiver { data_id: *data_id, receiver_id: receiver_id.clone() });
        }

        let new_receipt = ActionReceiptMetadata {
            receiver_id,
            refund_to: None,
            output_data_receivers: vec![],
            input_data_ids,
            actions: vec![],
            is_promise_yield: false,
        };
        let new_receipt_index = self.action_receipts.len() as ReceiptIndex;
        self.action_receipts.push(new_receipt);
        Ok(new_receipt_index)
    }
```
