The code path is fully traceable. Here is the analysis:

## Step 1: `submit_promise_resume_data` guard logic [1](#0-0) 

The guard condition is:
```rust
if has_yield_receipt_in_state || has_yield_status_in_state {
    self.receipt_manager.create_promise_resume_receipt(data_id, data);
    set_promise_yield_status(..., PromiseYieldStatus::ResumeInitiated);
    return Ok(true);
}
```

## Step 2: `has_promise_yield_status` checks key existence, not value [2](#0-1) 

`has_promise_yield_status` calls `trie.contains_key(...)` — it returns `true` if the `PromiseYieldStatus` key exists **regardless of whether the value is `Yielded` or `ResumeInitiated`**.

## Step 3: `TrieUpdate::contains_key` reads the prospective map first [3](#0-2) 

After the first `submit_promise_resume_data` call writes `ResumeInitiated` into the prospective map via `set_promise_yield_status`, the second call's `has_promise_yield_status` hits the prospective map first and returns `true` — because the key still exists with a non-`None` value (`ResumeInitiated`).

## Step 4: `set_promise_yield_status` writes to prospective map [4](#0-3) 

The write goes into `TrieUpdate::prospective` (a `BTreeMap`), which is exactly what `contains_key` reads on the second call.

## Conclusion

The bug is real. The guard was intended to prevent double-resume, but it only checks **key presence**, not **key value**. After the first call writes `ResumeInitiated`, the second call reads the prospective map, finds the key still present, and proceeds to call `create_promise_resume_receipt` a second time with the same `data_id`.

---

### Title
Double-resume of a single yield data_id within one function call execution produces two PromiseResume receipts — (`runtime/runtime/src/ext.rs`)

### Summary
`RuntimeExt::submit_promise_resume_data` uses `has_promise_yield_status` to guard against duplicate resumes. That function only checks whether the `PromiseYieldStatus` trie key **exists**, not whether its value is `Yielded` vs `ResumeInitiated`. Because `TrieUpdate::contains_key` reads the prospective map first, a second call within the same execution sees the `ResumeInitiated` value written by the first call and incorrectly passes the guard, enqueuing a second `PromiseResume` receipt for the same `data_id`.

### Finding Description
In `submit_promise_resume_data`: [5](#0-4) 

The guard `has_yield_status_in_state` is computed by `has_promise_yield_status`, which calls `trie.contains_key(TrieKey::PromiseYieldStatus { ... })`: [2](#0-1) 

This returns `true` for **any** stored status — both `Yielded` and `ResumeInitiated`. After the first resume call writes `ResumeInitiated` into the `TrieUpdate` prospective map: [6](#0-5) 

The second call's `contains_key` hits the prospective map first: [3](#0-2) 

It finds the key present (value is `Some(ResumeInitiated)`), returns `true`, and the guard passes again. `create_promise_resume_receipt` is called a second time with the same `data_id`, producing two `DataReceiptMetadata` entries in `ReceiptManager::data_receipts`.

### Impact Explanation
The yield callback executes twice for a single yield. If the callback transfers funds (e.g., via `promise_batch_action_transfer`), the deposit is paid out twice — a direct double-spend of the attached deposit. Even without a transfer, any state mutation in the callback is applied twice, corrupting the "each yield is resumed exactly once" causality invariant.

### Likelihood Explanation
Any unprivileged user who deploys a contract can trigger this by calling `promise_yield_resume` twice with the same `data_id` in a single function call. No validator or operator privilege is required. The attacker controls the contract code and the transaction input.

### Recommendation
Replace the existence check with a value check. The guard should only pass when the status is specifically `Yielded`, not when it is `ResumeInitiated`. Use `get_promise_yield_status` and match on `Some(PromiseYieldStatus::Yielded)`:

```rust
let yield_status = get_promise_yield_status(self.trie_update, &self.account_id, data_id)
    .map_err(wrap_storage_error)?;
let has_active_yield_status = matches!(yield_status, Some(PromiseYieldStatus::Yielded));

if has_yield_receipt_in_state || has_active_yield_status {
    ...
}
```

### Proof of Concept
Write a runtime integration test that:
1. Applies a receipt whose contract calls `promise_yield_create` to obtain a `data_id`.
2. In the same function call, calls `promise_yield_resume(data_id, payload)` twice.
3. After execution, asserts that `ReceiptManager::data_receipts` contains exactly **one** entry for that `data_id` (currently it will contain two, demonstrating the bug).

### Citations

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

**File:** core/store/src/utils/mod.rs (L242-253)
```rust
pub fn set_promise_yield_status(
    state_update: &mut TrieUpdate,
    receiver_id: &AccountId,
    data_id: CryptoHash,
    status: PromiseYieldStatus,
) {
    set(
        state_update,
        TrieKey::PromiseYieldStatus { receiver_id: receiver_id.clone(), data_id },
        &status,
    );
}
```

**File:** core/store/src/trie/update.rs (L147-158)
```rust
    pub fn contains_key(&self, key: &TrieKey, opts: AccessOptions) -> Result<bool, StorageError> {
        let mut key_buf = SmallKeyVec::new_const();
        key.append_into(&mut key_buf);
        if let Some(data) = self.prospective.get(&*key_buf) {
            return Ok(data.value.is_some());
        } else if let Some(changes_with_trie_key) = self.committed.get(&*key_buf) {
            if let Some(RawStateChange { data, .. }) = changes_with_trie_key.changes.last() {
                return Ok(data.is_some());
            }
        }
        self.trie.contains_key(&*key_buf, opts)
    }
```

**File:** core/store/src/trie/update.rs (L160-167)
```rust
    pub fn set(&mut self, trie_key: TrieKey, value: Vec<u8>) {
        // NOTE: Converting `TrieKey` to a `Vec<u8>` is useful here for 2 reasons:
        // - Using `Vec<u8>` for sorting `BTreeMap` in the same order as a `Trie` and
        //   avoid recomputing `Vec<u8>` every time. It helps for merging iterators.
        // - Using `TrieKey` later for `RawStateChangesWithTrieKey` for State changes RPCs.
        self.prospective
            .insert(trie_key.to_vec(), TrieKeyValueUpdate { trie_key, value: Some(value) });
    }
```
