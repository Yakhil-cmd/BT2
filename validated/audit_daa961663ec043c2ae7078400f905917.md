Let me check the action validation for gas keys and the `num_extra_bytes_record` value to complete the analysis.

### Title
Storage Usage Undercount for `GasKeyNonce` Trie Entries in `gas_key_storage_cost` — (`runtime/runtime/src/access_keys.rs`)

### Summary

`gas_key_storage_cost` computes `per_nonce_key_size` as only `public_key.trie_id_len() + size_of::<NonceIndex>()`, omitting the 1-byte column prefix, `account_id.len()` bytes, and 1-byte separator that are unconditionally written into every `TrieKey::GasKeyNonce` trie key. The result is that `account.storage_usage()` is undercounted by exactly `(2 + account_id.len()) * num_nonces` bytes whenever a gas key is added, allowing an account to pass `check_storage_stake` while occupying more trie storage than its locked balance covers.

### Finding Description

**`per_nonce_key_size` computation** in `gas_key_storage_cost`:

```rust
// runtime/runtime/src/access_keys.rs  lines 38-39
let per_nonce_key_size = public_key.trie_id_len() as u64 + size_of::<NonceIndex>() as u64;
``` [1](#0-0) 

**Actual bytes written** for every `TrieKey::GasKeyNonce` entry (`append_into`):

```rust
// core/primitives/src/trie_key.rs  lines 550-556
TrieKey::GasKeyNonce { account_id, key_handle, index: nonce_index } => {
    buf.push(col::ACCESS_KEY);              // 1 byte  ← missing from per_nonce_key_size
    buf.extend(account_id.as_bytes());      // account_id.len() bytes  ← missing
    buf.push(ACCESS_KEY_SEPARATOR);         // 1 byte  ← missing
    append_key_handle_trie_id(buf, key_handle);  // trie_id_len() bytes  ✓
    buf.extend(&nonce_index.to_le_bytes()); // size_of::<NonceIndex>() bytes  ✓
}
``` [2](#0-1) 

The canonical helper `gas_key_nonce_key_len` (used elsewhere, e.g. in `delete_gas_key` for compute accounting) correctly includes all components:

```rust
// core/primitives/src/trie_key.rs  lines 324-326
pub fn gas_key_nonce_key_len(account_id: &AccountId, key_handle: &PublicKeyHandle) -> usize {
    access_key_key_len(account_id.len(), key_handle.trie_id_len()) + size_of::<NonceIndex>()
}
``` [3](#0-2) 

where `access_key_key_len` is:

```rust
// core/primitives-core/src/trie_key.rs  lines 13-14
pub fn access_key_key_len(account_id_len: usize, public_key_len: usize) -> usize {
    COLUMN_PREFIX_LEN + account_id_len + ACCESS_KEY_SEPARATOR_LEN + public_key_len
}
``` [4](#0-3) 

So `gas_key_nonce_key_len` = `1 + account_id.len() + 1 + trie_id_len + size_of::<NonceIndex>()`, while `per_nonce_key_size` = `trie_id_len + size_of::<NonceIndex>()`. The gap is `2 + account_id.len()` bytes per nonce.

`add_gas_key` applies this undercount directly to `account.storage_usage()`:

```rust
// runtime/runtime/src/access_keys.rs  lines 216-226
account.set_storage_usage(
    account
        .storage_usage()
        .checked_add(gas_key_storage_cost(fee_config, public_key, &access_key, num_nonces))
        ...
);
``` [5](#0-4) 

### Impact Explanation

`check_storage_stake` uses `account.storage_usage()` to determine the minimum locked balance. Because `account.storage_usage()` is undercounted by `(2 + account_id.len()) * num_nonces` bytes, the account can hold all `num_nonces` nonce trie entries while locking less NEAR than the actual trie storage requires. For a 64-byte account ID the undercount is 66 bytes per nonce. With `MAX_NONCES_FOR_GAS_KEY` nonces the total undercount is `66 * MAX_NONCES_FOR_GAS_KEY` bytes — real trie storage that is not covered by the storage stake.

Note: `access_key_storage_usage` (used for the base access-key entry) has the same structural omission, but that is a pre-existing single-entry issue. The gas-key path multiplies the error by `num_nonces`, making it the amplified, new surface.

### Likelihood Explanation

Any unprivileged account can submit an `AddKeyAction` with a gas-key permission. Validation only checks `num_nonces ∈ [1, MAX_NONCES_FOR_GAS_KEY]` and that `balance == 0`; it does not verify that the account's locked balance covers the actual trie key bytes. [6](#0-5) 

The attacker needs only a sufficiently long account ID (up to 64 bytes) and enough balance to pass the undercounted storage check.

### Recommendation

Replace the hand-rolled `per_nonce_key_size` with the existing canonical helper:

```rust
// In gas_key_storage_cost, replace:
let per_nonce_key_size = public_key.trie_id_len() as u64 + size_of::<NonceIndex>() as u64;

// With:
let per_nonce_key_size = gas_key_nonce_key_len(account_id, &public_key.into()) as u64;
```

This requires threading `account_id` into `gas_key_storage_cost` (already available at all call sites). The same fix should be applied symmetrically to `access_key_storage_usage` for the base access-key entry.

### Proof of Concept

1. Create an account with a 64-byte account ID.
2. Submit `AddKeyAction` with `AccessKey::gas_key_full_access(MAX_NONCES_FOR_GAS_KEY)`.
3. After the action, iterate the trie over the `ACCESS_KEY` prefix for the account and sum the byte lengths of all `GasKeyNonce` raw keys.
4. Assert `account.storage_usage() >= sum_of_actual_key_lengths + sum_of_value_lengths`.
5. The assertion fails: `account.storage_usage()` is short by `66 * MAX_NONCES_FOR_GAS_KEY` bytes, confirming the account holds trie storage not covered by its locked balance.

### Citations

**File:** runtime/runtime/src/access_keys.rs (L38-39)
```rust
    let per_nonce_value_size = borsh::object_length(&(0 as Nonce)).unwrap() as u64;
    let per_nonce_key_size = public_key.trie_id_len() as u64 + size_of::<NonceIndex>() as u64;
```

**File:** runtime/runtime/src/access_keys.rs (L216-226)
```rust
    account.set_storage_usage(
        account
            .storage_usage()
            .checked_add(gas_key_storage_cost(fee_config, public_key, &access_key, num_nonces))
            .ok_or_else(|| {
                StorageError::StorageInconsistentState(format!(
                    "Storage usage integer overflow for account {}",
                    account_id
                ))
            })?,
    );
```

**File:** core/primitives/src/trie_key.rs (L324-326)
```rust
pub fn gas_key_nonce_key_len(account_id: &AccountId, key_handle: &PublicKeyHandle) -> usize {
    access_key_key_len(account_id.len(), key_handle.trie_id_len()) + size_of::<NonceIndex>()
}
```

**File:** core/primitives/src/trie_key.rs (L550-556)
```rust
            TrieKey::GasKeyNonce { account_id, key_handle, index: nonce_index } => {
                buf.push(col::ACCESS_KEY);
                buf.extend(account_id.as_bytes());
                buf.push(ACCESS_KEY_SEPARATOR);
                append_key_handle_trie_id(buf, key_handle);
                buf.extend(&nonce_index.to_le_bytes());
            }
```

**File:** core/primitives-core/src/trie_key.rs (L13-14)
```rust
pub fn access_key_key_len(account_id_len: usize, public_key_len: usize) -> usize {
    COLUMN_PREFIX_LEN + account_id_len + ACCESS_KEY_SEPARATOR_LEN + public_key_len
```

**File:** runtime/runtime/src/action_validation.rs (L312-319)
```rust
        if gas_key_info.num_nonces == 0
            || gas_key_info.num_nonces > AccessKeyPermission::MAX_NONCES_FOR_GAS_KEY
        {
            return Err(ActionsValidationError::GasKeyInvalidNumNonces {
                requested_nonces: gas_key_info.num_nonces,
                limit: AccessKeyPermission::MAX_NONCES_FOR_GAS_KEY,
            });
        }
```
