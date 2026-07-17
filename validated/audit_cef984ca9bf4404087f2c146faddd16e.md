### Title
`action_delete_account` Omits Global Contract Identifier Storage from Deletion-Size Check, Incorrectly Blocking Account Deletion - (File: `runtime/runtime/src/actions.rs`)

### Summary

In `action_delete_account`, the legacy code path (protocol versions < 85) computes the account's non-contract storage usage by subtracting only the **local contract code length** from `account.storage_usage()`. For accounts using a global contract (`AccountContract::Global` or `AccountContract::GlobalByAccount`), `local_contract_hash()` returns `None`, so `code_len` is 0 and nothing is subtracted. The global contract identifier bytes (32 bytes for a code-hash reference, or `account_id.len()` bytes for an account-ID reference) that were added to `storage_usage` by `use_global_contract` are never removed. The resulting `account_storage_usage` is overstated by exactly `identifier_storage_usage()` bytes, causing the guard `account_storage_usage > MAX_ACCOUNT_DELETION_STORAGE_USAGE` to fire incorrectly and block deletion of accounts whose actual non-contract state is within the limit.

### Finding Description

`use_global_contract` adds the identifier length to `account.storage_usage()`: [1](#0-0) 

`action_delete_account` must subtract that same overhead before comparing against the deletion limit. The fixed path does so via `get_contract_storage_usage`, which handles all contract variants: [2](#0-1) 

The legacy path, however, only calls `get_code_len_or_default` with `local_contract_hash().unwrap_or_default()`. For a global-contract account, `local_contract_hash()` returns `None`, so `unwrap_or_default()` yields `CryptoHash::default()`, and `get_code_len_or_default` returns 0: [3](#0-2) 

The comment in the code itself confirms the omission: *"Legacy behavior: only subtracts local contract code, misses the global contract identifier overhead."*

The corrupted value is `account_storage_usage` on line 331: it equals `account.storage_usage()` instead of `account.storage_usage() - identifier_len`. This overstated value is then compared against `MAX_ACCOUNT_DELETION_STORAGE_USAGE` (10,000 bytes): [4](#0-3) 

### Impact Explanation

Any account that has called `UseGlobalContractAction` and whose `storage_usage` falls in the range `(MAX_ACCOUNT_DELETION_STORAGE_USAGE, MAX_ACCOUNT_DELETION_STORAGE_USAGE + identifier_size]` is incorrectly rejected with `DeleteAccountWithLargeState`. The account cannot be deleted, so its balance cannot be swept to a beneficiary via `DeleteAccount`. The user's funds remain locked in an account they cannot close. The window is 32 bytes wide for `AccountContract::Global(CryptoHash)` and up to ~64 bytes wide for `AccountContract::GlobalByAccount(account_id)`.

The protocol-version guard confirms this is a live production invariant break, not a theoretical one: [5](#0-4) [6](#0-5) 

The feature is assigned to protocol version 85: [7](#0-6) 

Nodes running protocol versions < 85 still execute the buggy branch.

### Likelihood Explanation

Medium. The account must (a) have adopted a global contract via `UseGlobalContractAction` and (b) have accumulated storage usage in the narrow window just above `MAX_ACCOUNT_DELETION_STORAGE_USAGE`. Both conditions are user-controllable: a user can deliberately craft their storage to land in this range, or a third party can push contract-data writes into the account to place it there. Global contracts are a new but production-enabled feature (protocol version 77+), so affected accounts will exist on mainnet.

### Recommendation

Replace the legacy subtraction with `get_contract_storage_usage`, which correctly handles `AccountContract::None`, `Local`, `Global`, and `GlobalByAccount`. This is exactly what `ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage` does. Ensure the fix is activated at the earliest possible protocol version upgrade for any network still running < 85.

### Proof of Concept

The existing test `test_delete_account_global_contract_protocol_transition` in `runtime/runtime/src/actions.rs` directly demonstrates the bug: [8](#0-7) 

With `storage = MAX + 32` and `AccountContract::Global(CryptoHash::default())` (identifier = 32 bytes), the pre-fix protocol version returns `DeleteAccountWithLargeState` even though the account's non-contract state is exactly at the limit. The post-fix version correctly allows deletion. An unprivileged user can reproduce this on any node running protocol version < 85 by deploying a global contract to their account and writing enough contract-data keys to push `storage_usage` into the `(MAX, MAX + 32]` range, then submitting a `DeleteAccount` action.

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L97-104)
```rust
    account.set_storage_usage(
        account.storage_usage().checked_add(contract_identifier.len() as u64).ok_or_else(|| {
            StorageError::StorageInconsistentState(format!(
                "Storage usage integer overflow for account {}",
                account_id
            ))
        })?,
    );
```

**File:** runtime/runtime/src/actions.rs (L311-315)
```rust
    let account_storage_usage = if ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage
        .enabled(current_protocol_version)
    {
        let contract_storage = get_contract_storage_usage(state_update, account_id, account_ref)?;
        account_ref.storage_usage().saturating_sub(contract_storage)
```

**File:** runtime/runtime/src/actions.rs (L316-332)
```rust
    } else {
        // Legacy behavior: only subtracts local contract code, misses the
        // global contract identifier overhead.
        let account_storage_usage = account_ref.storage_usage();
        let code_len = get_code_len_or_default(
            state_update,
            account_id.clone(),
            account_ref.local_contract_hash().unwrap_or_default(),
        )?;
        debug_assert!(
            code_len == 0 || account_storage_usage > code_len,
            "account storage usage should be larger than code size. storage usage: {}, code size: {}",
            account_storage_usage,
            code_len
        );
        account_storage_usage.saturating_sub(code_len)
    };
```

**File:** runtime/runtime/src/actions.rs (L333-338)
```rust
    if account_storage_usage > Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE {
        result.result =
            Err(ActionErrorKind::DeleteAccountWithLargeState { account_id: account_id.clone() }
                .into());
        return Ok(());
    }
```

**File:** runtime/runtime/src/actions.rs (L395-409)
```rust
fn get_contract_storage_usage(
    state_update: &TrieUpdate,
    account_id: &AccountId,
    account: &Account,
) -> Result<StorageUsage, StorageError> {
    Ok(match account.contract().as_ref() {
        AccountContract::None => 0,
        AccountContract::Local(code_hash) => {
            get_code_len_or_default(state_update, account_id.clone(), *code_hash)?
        }
        AccountContract::Global(_) | AccountContract::GlobalByAccount(_) => {
            account.contract().identifier_storage_usage()
        }
    })
}
```

**File:** runtime/runtime/src/actions.rs (L1091-1115)
```rust
    fn test_delete_account_global_contract_protocol_transition() {
        let account_id: AccountId = "alice".parse().unwrap();
        let storage = Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE + 32;
        let enabled =
            ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage.protocol_version();

        // Before the fix: the identifier is not subtracted, so `MAX + 32 > MAX`.
        let before = test_delete_account_in_empty_trie(
            &account_id,
            AccountContract::Global(CryptoHash::default()),
            storage,
            enabled - 1,
        );
        expect_delete_account_too_large(&before);

        // From the fix onwards: the 32-byte identifier is subtracted, so
        // `MAX + 32 - 32 == MAX`, which is not `> MAX`.
        let after = test_delete_account_in_empty_trie(
            &account_id,
            AccountContract::Global(CryptoHash::default()),
            storage,
            enabled,
        );
        assert!(after.result.is_ok());
    }
```

**File:** core/primitives-core/src/version.rs (L355-359)
```rust
    /// Fix `action_delete_account` not subtracting the global contract
    /// identifier storage usage. Previously only local contract code was
    /// subtracted, overstating storage usage for accounts with global
    /// contracts and making them marginally harder to delete.
    FixDeleteAccountGlobalContractStorageUsage,
```

**File:** core/primitives-core/src/version.rs (L555-557)
```rust
            ProtocolFeature::FixDelegateActionDepositWithFunctionCallError
            | ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage
            | ProtocolFeature::FixDelegatedDeterministicStateInit
```
