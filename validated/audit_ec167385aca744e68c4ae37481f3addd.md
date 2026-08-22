### Title
`DeterministicStateInitAction` bypasses `max_length_storage_key` when constructing `TrieKey::ContractData` - ([File: runtime/runtime/src/deterministic_account_id.rs])

### Summary
The `max_length_storage_key` limit is enforced only inside `storage_write` in `runtime/near-vm-runner/src/logic/logic.rs` before `TrieKey::ContractData` is built via `ext.storage_set`. The alternate path `deploy_deterministic_account` in `core/primitives/src/deterministic_account_id.rs` (actually `runtime/runtime/src/deterministic_account_id.rs`) builds `TrieKey::ContractData { account_id, key }` directly from attacker-controlled `state_init.data()` key/value pairs without going through that check.

### Finding Description
`deploy_deterministic_account` iterates `state_init.data()` and, for each `(key, value)` pair, constructs `TrieKey::ContractData { account_id: account_id.clone(), key: key.to_vec() }` and calls `state_update.set(trie_key, value.clone())`: [1](#0-0) 

Unlike the `storage_write` host function path (`runtime/near-vm-runner/src/logic/logic.rs`), which validates `key.len() <= max_length_storage_key` before calling into `ext.storage_set`, this function performs no such length check on `key`. It only accounts for storage usage/rent via `checked_add` on `key_bytes + value_bytes + extra_per_record_bytes`, which prevents integer overflow and ensures the account pays storage rent for the bytes, but does not cap the key length at the protocol-configured `max_length_storage_key` (2048 bytes).

Because `DeterministicStateInitAction` is a user-submittable action (part of NEP-616 deterministic account state init) reachable from an ordinary account holder via a transaction/receipt, an attacker can supply a `state_init.data()` entry with a key far larger than `max_length_storage_key`, as long as they pay the resulting storage rent for that key length. This directly matches the audit's "Scoped impact" description: a code path constructing `TrieKey::ContractData` that bypasses the `max_length_storage_key` check used by the canonical `storage_write` path, since the length-capping invariant is a protocol design bound above and beyond storage-rent accounting (used to bound trie key/node size for CPU/memory during chunk application, and to keep gas-cost approximations for storage operations meaningful).

### Impact Explanation
This falls into the "gas or storage metering bypass" / "unbounded resource use" NEAR bounty impact class: an attacker-controlled arbitrarily long trie key (unbounded by protocol's declared 2048-byte `max_length_storage_key` bound) can be inserted into the trie. Although storage rent is charged proportional to key length (so this is not "free" execution), the protocol-wide invariant that `TrieKey::ContractData` keys are bounded by `max_length_storage_key` is broken for this action type, which can inflate per-node trie processing costs (key comparisons, node splitting, RocksDB key sizes) beyond what other subsystems (e.g. `max_length_storage_key`-based gas cost models, prefetcher, split.rs, RPC-facing display/query code) assume.

### Likelihood Explanation
Requires only that `DeterministicStateInitAction` is reachable by an ordinary account holder (no special privilege) and that the attacker funds enough deposit to cover storage staking for the oversized key/value. This is fully within the "unprivileged attacker" threat model described in the prompt. Feasibility depends on whether `DeterministicStateInitAction`/`DeterministicAccountStateInit` validation (in `action_validation.rs`/protocol feature gating, not inspected in this session) independently enforces a key-length bound before or after this code executes — I was not able to confirm or rule that out within the available tool budget, so this should be verified further.

### Recommendation
Add an explicit length check `key.len() <= apply_state.config.wasm_config.limit_config.max_length_storage_key` (and equivalent value-length check) in `deploy_deterministic_account` before constructing `TrieKey::ContractData`, returning an `ActionErrorKind` (e.g. a new "state init key too long" error) instead of proceeding, mirroring the check already performed in `runtime/near-vm-runner/src/logic/logic.rs::storage_write`.

### Proof of Concept
Integration test in `runtime/runtime/src/deterministic_account_id.rs` tests (or `runtime/runtime` integration test suite):
1. Construct a `DeterministicStateInitAction` receipt targeting a fresh/uninitialized account, with `state_init.data()` containing one `(key, value)` pair where `key.len() == max_length_storage_key + 1` (2049 bytes), and `deposit` sufficient to cover storage staking for that record.
2. Apply the receipt via the runtime's `apply` entry point.
3. Assert: (a) the action succeeds (no `ActionError` is returned) and (b) `TrieUpdate`/final state contains a `TrieKey::ContractData` entry whose serialized key exceeds `col::CONTRACT_DATA.len() + account_id.len() + ACCOUNT_DATA_SEPARATOR.len() + max_length_storage_key`.
4. Contrast with an equivalent `storage_write` call for the same key length through a contract, which is expected to fail with `HostError::KeyLengthExceeded` — showing the metering/limit invariant is inconsistent between the two `TrieKey::ContractData`-constructing paths.

### Citations

**File:** runtime/runtime/src/deterministic_account_id.rs (L131-147)
```rust
    // Step 2: insert provided key-value pairs
    let mut required_storage_usage = account.storage_usage();
    for (key, value) in state_init.data() {
        let trie_key = TrieKey::ContractData { account_id: account_id.clone(), key: key.to_vec() };

        let value_bytes = value.len() as u64;
        let key_bytes = key.len() as u64;
        let extra_per_record_bytes = storage_usage_config.num_extra_bytes_record;

        let new_bytes = value_bytes
            .checked_add(key_bytes)
            .and_then(|acc| acc.checked_add(extra_per_record_bytes))
            .ok_or(IntegerOverflowError {})?;
        state_update.set(trie_key, value.clone());
        required_storage_usage =
            required_storage_usage.checked_add(new_bytes).ok_or(IntegerOverflowError {})?;
    }
```
