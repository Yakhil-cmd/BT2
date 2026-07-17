## Analysis

I need to trace the exact dedup logic in `submit_promise_resume_data` and determine whether a second call with the same `data_id` in the same execution can bypass it.

### Step 1: The Guard in `submit_promise_resume_data` [1](#0-0) 

The guard condition is:
```
if has_yield_receipt_in_state || has_yield_status_in_state { ... }
```

### Step 2: What `has_promise_yield_status` actually checks [2](#0-1) 

It calls `trie.contains_key(...)` — it checks **key existence only**, not the value. It returns `true` for **any** `PromiseYieldStatus` variant, including `ResumeInitiated`.

### Step 3: What the first call writes [3](#0-2) 

After the first successful call, `set_promise_yield_status` writes `PromiseYieldStatus::ResumeInitiated` to `trie_update` — the key still exists.

### Step 4: What the second call sees

`trie_update` reflects in-memory writes immediately (as explicitly noted in the comment at `create_promise_yield_receipt_with_id`): [4](#0-3) 

So on the second call with the same `data_id`:
- `has_promise_yield_receipt` → still `true` (the PromiseYield receipt is not removed from trie by `submit_promise_resume_data`)
- `has_promise_yield_status` → still `true` (key exists with value `ResumeInitiated`)

The condition passes again, and `create_promise_resume_receipt` is called a second time: [5](#0-4) 

This unconditionally pushes a second `DataReceiptMetadata { data_id, is_promise_resume: true }` into `data_receipts` with no dedup check of its own.

### Step 5: Is the `data_id` attacker-controlled?

The `data_id` is returned to the contract from `promise_yield_create` (via `create_promise_yield_receipt`): [6](#0-5) 

The contract receives `input_data_id` and can pass it to `promise_yield_resume` as many times as it wishes within the same function call.

---

### Conclusion

The dedup mechanism is broken. `has_promise_yield_status` checks only for key existence, not for `status == Yielded`. After the first `submit_promise_resume_data` call sets the status to `ResumeInitiated`, the key still exists, so the second call passes the guard and emits a second `PromiseResume` receipt for the same `data_id`. The `create_promise_resume_receipt` function has no dedup of its own.

---

### Title
Double PromiseResume Receipt Emission via Broken Dedup in `submit_promise_resume_data` — (`runtime/runtime/src/ext.rs`)

### Summary
A contract can call `promise_yield_resume` twice with the same `data_id` in a single function call, causing two `PromiseResume` (Data) receipts with `is_promise_resume=true` to be emitted for the same `data_id` in the same chunk, violating the one-resume-per-yield invariant.

### Finding Description
`submit_promise_resume_data` guards against duplicate resumes using:

```rust
let has_yield_status_in_state =
    has_promise_yield_status(self.trie_update, &self.account_id, data_id)?;

if has_yield_receipt_in_state || has_yield_status_in_state {
    self.receipt_manager.create_promise_resume_receipt(data_id, data);
    set_promise_yield_status(..., PromiseYieldStatus::ResumeInitiated);
    return Ok(true);
}
```

`has_promise_yield_status` checks only for **key existence** in `trie_update`, not for the value being `Yielded`. After the first call writes `ResumeInitiated` to `trie_update`, the second call finds the key still present and passes the guard again. `create_promise_resume_receipt` has no dedup of its own and unconditionally appends to `data_receipts`. The PromiseYield receipt is also not removed from `trie_update` by `submit_promise_resume_data`, so `has_promise_yield_receipt` also remains `true` for yields from prior executions.

### Impact Explanation
Two `PromiseResume` receipts with the same `data_id` are emitted in the same chunk. When the runtime processes them:
- The first resolves the PromiseYield receipt and removes it from state.
- The second arrives for a `data_id` whose yield is already resolved, potentially storing orphaned `ReceivedData` in trie (state leak) or triggering undefined behavior in the receipt dependency resolution logic.

The yield causality invariant — each PromiseYield receipt is resolved exactly once — is broken by an unprivileged contract.

### Likelihood Explanation
Any deployed contract that calls `promise_yield_resume` twice with the same `data_id` in one function call triggers this. No special privileges are required; only the ability to deploy and call a contract.

### Recommendation
Change the guard to check the actual status value, not just key existence:

```rust
let status = get_promise_yield_status(self.trie_update, &self.account_id, data_id)?;
if has_yield_receipt_in_state || status == Some(PromiseYieldStatus::Yielded) {
    self.receipt_manager.create_promise_resume_receipt(data_id, data);
    set_promise_yield_status(..., PromiseYieldStatus::ResumeInitiated);
    return Ok(true);
}
```

### Proof of Concept
Write a runtime `apply` test where a contract:
1. Calls `promise_yield_create` → receives `data_id`
2. Calls `promise_yield_resume(data_id, b"first")` → returns `true`
3. Calls `promise_yield_resume(data_id, b"second")` → also returns `true` (should return `false`)

Assert that `apply` output contains exactly one Data receipt with `is_promise_resume=true` for that `data_id`. With the current code, two such receipts are present.

### Citations

**File:** runtime/runtime/src/ext.rs (L346-362)
```rust
    fn create_promise_yield_receipt(
        &mut self,
        receiver_id: AccountId,
    ) -> Result<(ReceiptIndex, CryptoHash), VMLogicError> {
        let input_data_id = self.generate_data_id();
        let receipt_index =
            self.receipt_manager.create_promise_yield_receipt(input_data_id, receiver_id.clone());

        set_promise_yield_status(
            &mut self.trie_update,
            &receiver_id,
            input_data_id,
            PromiseYieldStatus::Yielded,
        );

        Ok((receipt_index, input_data_id))
    }
```

**File:** runtime/runtime/src/ext.rs (L369-375)
```rust
        // Check for duplicate yield_id in trie. TrieUpdate also reflects writes from earlier
        // calls within the same function call, so this also catches in-transaction duplicates.
        if has_yield_id_mapping(self.trie_update, &receiver_id, user_yield_id)
            .map_err(wrap_storage_error)?
        {
            return Ok(None);
        }
```

**File:** runtime/runtime/src/ext.rs (L395-419)
```rust
    fn submit_promise_resume_data(
        &mut self,
        data_id: CryptoHash,
        data: Vec<u8>,
    ) -> Result<bool, VMLogicError> {
        let has_yield_receipt_in_state =
            has_promise_yield_receipt(self.trie_update, self.account_id.clone(), data_id)
                .map_err(wrap_storage_error)?;
        let has_yield_status_in_state =
            has_promise_yield_status(self.trie_update, &self.account_id, data_id)
                .map_err(wrap_storage_error)?;

        if has_yield_receipt_in_state || has_yield_status_in_state {
            self.receipt_manager.create_promise_resume_receipt(data_id, data);
            set_promise_yield_status(
                &mut self.trie_update,
                &self.account_id,
                data_id,
                PromiseYieldStatus::ResumeInitiated,
            );
            return Ok(true);
        }

        Ok(false)
    }
```

**File:** core/store/src/utils/mod.rs (L231-240)
```rust
pub fn has_promise_yield_status(
    trie: &dyn TrieAccess,
    receiver_id: &AccountId,
    data_id: CryptoHash,
) -> Result<bool, StorageError> {
    trie.contains_key(
        &TrieKey::PromiseYieldStatus { receiver_id: receiver_id.clone(), data_id },
        AccessOptions::DEFAULT,
    )
}
```

**File:** runtime/runtime/src/receipt_manager.rs (L175-181)
```rust
    pub(super) fn create_promise_resume_receipt(&mut self, data_id: CryptoHash, data: Vec<u8>) {
        self.data_receipts.push(DataReceiptMetadata {
            data_id,
            data: Some(data),
            is_promise_resume: true,
        });
    }
```
