### Title
Receipt size validation is bypassed when `output_data_receivers` are appended after the size check, allowing oversized receipts into the chain - ([File: runtime/runtime/src/lib.rs])

### Summary
nearcore enforces a hard `max_receipt_size` limit on newly created receipts via `validate_receipt` in `ValidateReceiptMode::NewReceipt` mode. However, the append of `output_data_receivers` to an already-produced (and already size-validated) child receipt happens *after* that validation point, allowing a receipt that was exactly at the size limit to grow past it without being re-checked. This is the direct nearcore analog of the tBTC report: a construct that is legitimate/valid at the moment of admission can later cross a hard resource boundary through a step the validator doesn't account for, producing state that downstream consumers (chunk producers, forwarding logic, other validators) must special-case or risk failing/diverging on.

### Finding Description
`validate_receipt` checks the borsh-encoded size of a receipt against `limit_config.max_receipt_size` only when `mode == ValidateReceiptMode::NewReceipt`: [1](#0-0) 

The `ValidateReceiptMode::ExistingReceipt` variant is explicitly documented as a workaround for this exact defect, referencing an open upstream issue: [2](#0-1) 

In `runtime/runtime/src/lib.rs`, after a `FunctionCall` action executes and its resulting new receipts have presumably passed size validation, the runtime performs an additional mutation: if the executing `action_receipt` has non-empty `output_data_receivers`, they are appended (`extend_from_slice`) onto a receipt that was already created as part of `result.new_receipts` (the "promise_return" case), or new `Data` receipts are synthesized: [3](#0-2) 

This growth happens strictly after the receipt's size was measured and validated, so a receipt that was constructed at (or near) exactly `max_receipt_size` can be pushed above the limit by this later mutation — the size check is never re-run on the final, larger byte representation. The `test-loop-tests` in this repo explicitly document and reproduce this: [4](#0-3) [5](#0-4) 

The runtime team's own mitigation acknowledges the receipt can end up oversized on the wire/in state, and instead of preventing it, patches downstream consumers to clamp the observed size defensively when forwarding cross-shard receipts: [6](#0-5) 

This is precisely analogous to the tBTC bug class: a resource limit (Ethereum block gas limit / here, `max_receipt_size`) is checked at one point in the pipeline (submission of the BTC transaction / receipt creation) but a subsequent, allowed step (accumulating merkle proof overhead / appending `output_data_receivers`) pushes the artifact over the limit, and the system has no reliable way to reject it retroactively — it can only apply best-effort clamps after the fact.

### Impact Explanation
An oversized receipt (larger than `max_receipt_size`) escaping validation can:
- Persist in state/receipt queues as a receipt exceeding the size the rest of the protocol assumes as a hard bound, undermining the accounting used to bound `ChunkStateWitness` size (documented to target ~17 MiB total across all these hard/soft limits).
- Require ad-hoc clamping logic (as seen in `try_forward`) to avoid the receipt getting permanently stuck when being forwarded to other shards, which is itself an admission that the size invariant the rest of the system relies on does not actually hold.
- Create a risk of state/validation divergence between validators if any component (e.g. an older or differently-patched validator) doesn't apply the same defensive clamp, or if a future component assumes `receipt_size <= max_receipt_size` as a true invariant rather than a best-effort limit.

This does not directly cause token theft/inflation, but it is a concrete instance of "resource accounting / hard limit enforced too early, bypassed by allowed post-validation mutation" that the nearcore team itself tracks as a bug (referenced issue #12606) and works around rather than fixes at the root.

### Likelihood Explanation
High likelihood of triggering under normal (non-malicious) usage: any unprivileged account can deploy a contract that creates a promise near `max_receipt_size` and returns it via `promise_return`, or returns a large value that becomes a `Data` receipt payload — both are reachable purely through standard `FunctionCall` actions and `promise_create`/`promise_then`/`promise_return`/`value_return` host functions, with no special permissions required. The repository's own test suite reproduces this deterministically.

### Recommendation
- Re-validate receipt size (`ValidateReceiptMode::NewReceipt`) after `output_data_receivers` are appended to `result.new_receipts`, rather than only validating before this mutation.
- Alternatively, reserve size budget for `output_data_receivers` before/at receipt-size validation time so no post-validation append can push a receipt over `max_receipt_size`.
- Treat the current `try_forward` clamp as strictly temporary and track/fix the root cause (nearcore issue #12606) rather than relying on downstream defensive clamping, since other code paths that consume receipts may not apply the same protection.

### Proof of Concept
Using the repository's own reproduction (already present in the codebase), which exercises this exact defect: [7](#0-6) [8](#0-7) 

Both tests deploy a contract, invoke a method that produces a receipt sized at (or a value sized at) exactly `max_receipt_size`, trigger the `output_data_receivers`/data-receipt append path, and then call `assert_oversized_receipt_occurred` to confirm a receipt larger than `max_receipt_size` was actually observed in the chain — confirming the size-limit bypass is currently reachable via ordinary contract execution.

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

**File:** runtime/runtime/src/lib.rs (L1013-1058)
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
                let data = match result.result {
                    Ok(ReturnData::Value(ref data)) => Some(data.clone()),
                    Ok(_) => Some(vec![]),
                    Err(_) => None,
                };
                result.new_receipts.extend(action_receipt.output_data_receivers().iter().map(
                    |data_receiver| {
                        Receipt::V0(ReceiptV0 {
                            predecessor_id: account_id.clone(),
                            receiver_id: data_receiver.receiver_id.clone(),
                            receipt_id: CryptoHash::default(),
                            receipt: ReceiptEnum::Data(DataReceipt {
                                data_id: data_receiver.data_id,
                                data: data.clone(),
                            }),
                        })
                    },
                ));
            };
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

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L210-213)
```rust
/// Return a value that is as large as max_receipt_size. The value will be wrapped in a data receipt
/// and the data receipt will be bigger than max_receipt_size. The receipt should be rejected, but
/// currently isn't because of a bug (See https://github.com/near/nearcore/issues/12606)
/// Creates the following promise DAG:
```

**File:** test-loop-tests/src/tests/max_receipt_size.rs (L215-267)
```rust
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
