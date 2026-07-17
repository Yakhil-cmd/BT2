## Analysis

I have traced the full code path. Let me summarize the findings.

### Code Path Trace

**Step 1: `use_global_contract` adds identifier length to `storage_usage`**

When `UseGlobalContractAction` with a `GlobalByAccount(id)` identifier is applied, `use_global_contract` adds `contract_identifier.len()` (up to 64 bytes for a max-length `AccountId`) to the account's `storage_usage`: [1](#0-0) 

**Step 2: Legacy `action_delete_account` path (before `FixDeleteAccountGlobalContractStorageUsage`)**

In the legacy branch, `get_code_len_or_default` is called with `account_ref.local_contract_hash().unwrap_or_default()`. For a `GlobalByAccount` account, `local_contract_hash()` returns `None`, so `unwrap_or_default()` yields `CryptoHash::default()`, and `get_code_len_or_default` returns `0`: [2](#0-1) 

So `account_storage_usage = account_ref.storage_usage().saturating_sub(0) = storage_usage` — the full value including the identifier overhead is used in the check.

**Step 3: The check** [3](#0-2) 

**Step 4: `get_code_len_or_default` returns 0 for global contracts** [4](#0-3) 

**Step 5: The fixed path correctly uses `identifier_storage_usage()`** [5](#0-4) 

For `GlobalByAccount(id)`, `identifier_storage_usage()` returns `id.len() as u64`: [6](#0-5) 

### Confirmed by Existing Tests

The test `test_delete_account_global_contract_protocol_transition` explicitly demonstrates the bug: [7](#0-6) 

The code comment in the legacy branch also acknowledges it: [8](#0-7) 

And the protocol feature description confirms the intent of the fix: [9](#0-8) 

---

### Verdict

### Title
Legacy `action_delete_account` Fails to Subtract Global Contract Identifier Overhead, Incorrectly Blocking Account Deletion — (`runtime/runtime/src/actions.rs`)

### Summary
Before `FixDeleteAccountGlobalContractStorageUsage` is enabled, `action_delete_account` uses `get_code_len_or_default` which returns `0` for accounts with global contracts (both `Global` and `GlobalByAccount`). The identifier overhead (32 bytes for `Global`, up to 64 bytes for `GlobalByAccount`) that was added to `storage_usage` by `use_global_contract` is never subtracted, causing the `MAX_ACCOUNT_DELETION_STORAGE_USAGE` check to use an inflated value.

### Finding Description
When an unprivileged user calls `UseGlobalContractAction` with a `GlobalByAccount` identifier of length `L`, `use_global_contract` adds `L` to `account.storage_usage()`. Later, when `DeleteAccountAction` is processed at a protocol version before `FixDeleteAccountGlobalContractStorageUsage`:

- `local_contract_hash()` returns `None` for a `GlobalByAccount` account
- `unwrap_or_default()` yields `CryptoHash::default()`
- `get_code_len_or_default(..., CryptoHash::default())` returns `0`
- `account_storage_usage = storage_usage - 0 = storage_usage` (identifier overhead not removed)
- Check: `storage_usage > MAX_ACCOUNT_DELETION_STORAGE_USAGE` uses the inflated value

An account whose actual non-contract storage is `S ≤ MAX` but whose recorded `storage_usage = S + L > MAX` (because `L` bytes of identifier overhead were added) will be incorrectly rejected with `DeleteAccountWithLargeState`.

### Impact Explanation
Any account that has used `UseGlobalContractAction` with a `GlobalByAccount` identifier and whose `storage_usage` falls in the range `(MAX_ACCOUNT_DELETION_STORAGE_USAGE, MAX_ACCOUNT_DELETION_STORAGE_USAGE + identifier_len]` cannot be deleted. `MAX_ACCOUNT_DELETION_STORAGE_USAGE = 10_000` and `identifier_len` can be up to 64 bytes. The account's balance cannot be recovered to the beneficiary, and the account is permanently undeletable until the protocol version advances past the fix.

### Likelihood Explanation
Requires: (1) protocol version before `FixDeleteAccountGlobalContractStorageUsage`, (2) account uses `UseGlobalContractAction` with `GlobalByAccount`, (3) `storage_usage` lands in the narrow window `(MAX, MAX + identifier_len]`. The window is small (up to 64 bytes) but the scenario is reachable by any unprivileged user on a pre-fix network.

### Recommendation
The fix is already present: `FixDeleteAccountGlobalContractStorageUsage` switches to `get_contract_storage_usage` which correctly handles all `AccountContract` variants. Ensure all production nodes upgrade past this protocol version.

### Proof of Concept
The existing test `test_delete_account_global_contract_protocol_transition` in `runtime/runtime/src/actions.rs` is a direct proof of concept — it sets `storage = MAX + 32`, uses `AccountContract::Global(CryptoHash::default())`, runs at `enabled - 1`, and asserts `DeleteAccountWithLargeState`. The same applies to `GlobalByAccount` with up to 64-byte identifiers.

### Citations

**File:** runtime/runtime/src/global_contracts.rs (L97-105)
```rust
    account.set_storage_usage(
        account.storage_usage().checked_add(contract_identifier.len() as u64).ok_or_else(|| {
            StorageError::StorageInconsistentState(format!(
                "Storage usage integer overflow for account {}",
                account_id
            ))
        })?,
    );
    account.set_contract(contract);
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

**File:** runtime/runtime/src/actions.rs (L381-393)
```rust
fn get_code_len_or_default(
    state_update: &TrieUpdate,
    account_id: AccountId,
    code_hash: CryptoHash,
) -> Result<StorageUsage, StorageError> {
    let code_len = state_update.get_code_len(account_id, code_hash)?;
    debug_assert!(
        code_len.is_some() || code_hash == CryptoHash::default(),
        "Non-default code hash for account with no contract deployed: {:?}",
        code_hash
    );
    Ok(code_len.unwrap_or_default().try_into().unwrap())
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

**File:** core/primitives-core/src/account.rs (L126-132)
```rust
    pub fn identifier_storage_usage(&self) -> u64 {
        match self {
            AccountContract::None | AccountContract::Local(_) => 0u64,
            AccountContract::Global(_) => 32u64,
            AccountContract::GlobalByAccount(id) => id.len() as u64,
        }
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
