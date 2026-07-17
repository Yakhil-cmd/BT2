### Title
Duplicate `input_data_ids` in ActionReceipt Inflates `PendingDataCount`, Permanently Freezing Postponed Receipts — (`runtime/runtime/src/lib.rs`)

### Summary

A malicious contract can call the `promise_and` host function with duplicate promise indices, producing an `ActionReceipt` whose `input_data_ids` list contains the same `CryptoHash` more than once. Neither `promise_and` nor `validate_action_receipt` deduplicates this list. When `process_action_receipt` processes the receipt, it increments `pending_data_count` once per list entry (including duplicates) but writes only a single `TrieKey::PostponedReceiptId` entry per unique `data_id`. When the single corresponding `DataReceipt` arrives, it decrements the counter by one and removes the `PostponedReceiptId` entry, leaving `PendingDataCount > 0` with no remaining index entry to ever decrement it further. The postponed receipt is permanently frozen in state and will never execute.

### Finding Description

**Root cause — `promise_and` does not deduplicate receipt dependencies**

`promise_and` in `runtime/near-vm-runner/src/logic/logic.rs` collects receipt dependencies into a plain `Vec` without deduplication:

```rust
let mut receipt_dependencies = vec![];
for promise_idx in promise_indices {
    let promise = self.promises.get(promise_idx as usize)...;
    match &promise {
        Promise::Receipt(receipt_idx) => {
            receipt_dependencies.push(*receipt_idx);   // pushed once per occurrence
        }
        Promise::NotReceipt(receipt_indices) => {
            receipt_dependencies.extend(receipt_indices.clone());
        }
    }
    ...
}
self.checked_push_promise(Promise::NotReceipt(receipt_dependencies))
```

If a contract passes `[p, p]` (the same promise index twice), `receipt_dependencies` becomes `[idx, idx]`. This vector becomes the `input_data_ids` of the new `ActionReceipt`. [1](#0-0) 

**Missing guard — `validate_action_receipt` only checks length, not uniqueness**

`validate_action_receipt` rejects receipts that exceed `max_number_input_data_dependencies` but performs no duplicate check:

```rust
if receipt.input_data_ids().len() as u64 > limit_config.max_number_input_data_dependencies {
    return Err(...)
}
// No deduplication check follows
``` [2](#0-1) 

**Corrupted invariant — `pending_data_count` diverges from the number of unique pending `data_id`s**

`process_action_receipt` iterates over `input_data_ids()` and increments `pending_data_count` for every entry that is not yet in storage, then writes `TrieKey::PostponedReceiptId { data_id }` for each:

```rust
let mut pending_data_count: u32 = 0;
for data_id in action_receipt.input_data_ids() {
    if !has_received_data(state_update, account_id, *data_id)? {
        pending_data_count += 1;
        set(
            state_update,
            TrieKey::PostponedReceiptId { receiver_id: account_id.clone(), data_id: *data_id },
            receipt.receipt_id(),
        )
    }
}
```

For `input_data_ids = [X, X]`:
- First iteration: `has_received_data(X)` → `false`; `pending_data_count = 1`; writes `PostponedReceiptId[X]`.
- Second iteration: `has_received_data(X)` → still `false` (same trie snapshot); `pending_data_count = 2`; overwrites `PostponedReceiptId[X]` with the same value (idempotent write).

Result: `PendingDataCount = 2`, but only **one** `PostponedReceiptId` entry for `X`. [3](#0-2) 

**Permanent freeze — DataReceipt arrival cannot reduce count to zero**

When the `DataReceipt` for `X` arrives, `process_receipt` removes `PostponedReceiptId[X]` and decrements `PendingDataCount` from 2 to 1:

```rust
state_update.remove(TrieKey::PostponedReceiptId { receiver_id: account_id.clone(), data_id: data_receipt.data_id });
// pending_data_count == 2, so branch taken:
set(..., &(pending_data_count.checked_sub(1)...));  // writes 1
```

`PendingDataCount` is now 1, but `PostponedReceiptId[X]` no longer exists. No future `DataReceipt` for `X` will arrive (it was already delivered and stored). The counter can never reach 0. The postponed receipt is permanently stuck in state. [4](#0-3) 

### Impact Explanation

Any NEAR tokens deposited into the stuck receipt's execution (e.g., a cross-contract callback that was supposed to release or refund funds) are permanently frozen. The `PostponedReceipt` and its `PendingDataCount` entry remain in the trie indefinitely, consuming storage and preventing the callback from ever running. If the callback was a refund or settlement handler, the locked funds are irrecoverable. This is a High-severity receipt-causality invariant violation.

### Likelihood Explanation

Any unprivileged user can deploy a WASM contract that calls `promise_and` with a repeated promise index. The `promise_and` host function is part of the standard NEAR contract API, requires no special permissions, and is callable on any protocol version that supports cross-contract calls. The attack requires only a single transaction to deploy the malicious contract and one more to trigger the call.

### Recommendation

1. **In `promise_and`**: deduplicate `receipt_dependencies` before constructing the `Promise::NotReceipt` variant, or reject duplicate promise indices with a `HostError`.
2. **In `validate_action_receipt`**: add a uniqueness check on `input_data_ids` and return `ReceiptValidationError` if any `data_id` appears more than once.
3. **In `process_action_receipt`**: as a defense-in-depth measure, use a `HashSet` when counting `pending_data_count` so that duplicate `data_id` entries are counted only once.

### Proof of Concept

A malicious contract written in Rust pseudocode:

```rust
#[near_bindgen]
impl MaliciousContract {
    pub fn attack(&mut self, victim_account: AccountId) {
        // Create one cross-contract promise
        let p = env::promise_create(victim_account, "some_method", b"{}", 0, GAS);
        // Pass the same promise index TWICE to promise_and
        let combined = env::promise_and(&[p, p]);
        // Attach a callback that depends on `combined`
        env::promise_then(combined, env::current_account_id(), "callback", b"{}", 0, GAS);
    }

    pub fn callback(&mut self) {
        // This callback will NEVER execute because pending_data_count = 2
        // but only one DataReceipt will ever arrive.
    }
}
```

Step-by-step state trace:

1. `attack()` executes → new `ActionReceipt` R created with `input_data_ids = [D, D]`.
2. `process_action_receipt(R)`: `pending_data_count = 2`; `PostponedReceiptId[D] = R`; `PendingDataCount[R] = 2`.
3. `DataReceipt(D)` arrives: removes `PostponedReceiptId[D]`; decrements `PendingDataCount[R]` to 1.
4. No further `DataReceipt(D)` will arrive. `PendingDataCount[R] = 1` forever. `callback` never runs.

### Citations

**File:** runtime/near-vm-runner/src/logic/logic.rs (L2247-2272)
```rust
        let mut receipt_dependencies = vec![];
        for promise_idx in promise_indices {
            let promise = self
                .promises
                .get(promise_idx as usize)
                .ok_or(HostError::InvalidPromiseIndex { promise_idx })?;
            match &promise {
                Promise::Receipt(receipt_idx) => {
                    receipt_dependencies.push(*receipt_idx);
                }
                Promise::NotReceipt(receipt_indices) => {
                    receipt_dependencies.extend(receipt_indices.clone());
                }
            }
            // Checking this in the loop to prevent abuse of too many joined vectors.
            if receipt_dependencies.len() as u64
                > self.config.limit_config.max_number_input_data_dependencies
            {
                return Err(HostError::NumberInputDataDependenciesExceeded {
                    number_of_input_data_dependencies: receipt_dependencies.len() as u64,
                    limit: self.config.limit_config.max_number_input_data_dependencies,
                }
                .into());
            }
        }
        self.checked_push_promise(Promise::NotReceipt(receipt_dependencies))
```

**File:** runtime/runtime/src/verifier.rs (L595-600)
```rust
    if receipt.input_data_ids().len() as u64 > limit_config.max_number_input_data_dependencies {
        return Err(ReceiptValidationError::NumberInputDataDependenciesExceeded {
            number_of_input_data_dependencies: receipt.input_data_ids().len() as u64,
            limit: limit_config.max_number_input_data_dependencies,
        });
    }
```

**File:** runtime/runtime/src/lib.rs (L1319-1393)
```rust
                if let Some(receipt_id) = get(
                    state_update,
                    &TrieKey::PostponedReceiptId {
                        receiver_id: account_id.clone(),
                        data_id: data_receipt.data_id,
                    },
                )? {
                    // There is already a receipt that is awaiting for the just received data.
                    // Removing this pending data_id for the receipt from the state.
                    state_update.remove(TrieKey::PostponedReceiptId {
                        receiver_id: account_id.clone(),
                        data_id: data_receipt.data_id,
                    });
                    // Checking how many input data items is pending for the receipt.
                    let pending_data_count: u32 = get(
                        state_update,
                        &TrieKey::PendingDataCount { receiver_id: account_id.clone(), receipt_id },
                    )?
                    .ok_or_else(|| {
                        StorageError::StorageInconsistentState(
                            "pending data count should be in the state".to_string(),
                        )
                    })?;
                    if pending_data_count == 1 {
                        // It was the last input data pending for this receipt. We'll cleanup
                        // some receipt related fields from the state and execute the receipt.

                        // Removing pending data count from the state.
                        state_update.remove(TrieKey::PendingDataCount {
                            receiver_id: account_id.clone(),
                            receipt_id,
                        });
                        // Fetching the receipt itself.
                        let ready_receipt =
                            get_postponed_receipt(state_update, account_id, receipt_id)?
                                .ok_or_else(|| {
                                    StorageError::StorageInconsistentState(
                                        "pending receipt should be in the state".to_string(),
                                    )
                                })?;
                        // Removing the receipt from the state.
                        remove_postponed_receipt(state_update, account_id, receipt_id);
                        // Executing the receipt. It will read all the input data and clean it up
                        // from the state.
                        return self
                            .apply_action_receipt(
                                state_update,
                                apply_state,
                                pipeline_manager,
                                &ready_receipt,
                                receipt_sink,
                                instant_receipts,
                                validator_proposals,
                                stats,
                                epoch_info_provider,
                                receipt_to_tx,
                            )
                            .map(Some);
                    } else {
                        // There is still some pending data for the receipt, so we update the
                        // pending data count in the state.
                        set(
                            state_update,
                            TrieKey::PendingDataCount {
                                receiver_id: account_id.clone(),
                                receipt_id,
                            },
                            &(pending_data_count.checked_sub(1).ok_or_else(|| {
                                StorageError::StorageInconsistentState(
                                    "pending data count is 0, but there is a new DataReceipt"
                                        .to_string(),
                                )
                            })?),
                        );
                    }
```

**File:** runtime/runtime/src/lib.rs (L1529-1544)
```rust
        let mut pending_data_count: u32 = 0;
        for data_id in action_receipt.input_data_ids() {
            if !has_received_data(state_update, account_id, *data_id)? {
                pending_data_count += 1;
                // The data for a given data_id is not available, so we save a link to this
                // receipt_id for the pending data_id into the state.
                set(
                    state_update,
                    TrieKey::PostponedReceiptId {
                        receiver_id: account_id.clone(),
                        data_id: *data_id,
                    },
                    receipt.receipt_id(),
                )
            }
        }
```
