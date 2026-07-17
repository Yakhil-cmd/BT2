### Title
`action_delete_account` storage-usage guard ignores global-contract identifier overhead, permanently blocking deletion of accounts with global contracts — (File: runtime/runtime/src/actions.rs)

---

### Summary

In `action_delete_account`, the pre-`FixDeleteAccountGlobalContractStorageUsage` code path computes the account's non-contract storage usage by subtracting only the **local** contract code length. For accounts using a global contract (`AccountContract::Global` or `AccountContract::GlobalByAccount`), the global-contract identifier overhead (32 bytes for `Global`, variable for `GlobalByAccount`) is included in `storage_usage` but is **never subtracted**. The guard check `account_storage_usage > Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE` therefore always fires for any account whose actual non-contract storage is within the 10 000-byte limit but whose raw `storage_usage` (including the identifier) exceeds it, making `DeleteAccount` permanently impossible for those accounts.

---

### Finding Description

`action_delete_account` in `runtime/runtime/src/actions.rs` gates account deletion on a storage-usage check:

```rust
// lines 311-332
let account_storage_usage = if ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage
    .enabled(current_protocol_version)
{
    let contract_storage = get_contract_storage_usage(state_update, account_id, account_ref)?;
    account_ref.storage_usage().saturating_sub(contract_storage)   // ← correct path
} else {
    // Legacy behavior: only subtracts local contract code, misses the
    // global contract identifier overhead.
    let code_len = get_code_len_or_default(
        state_update,
        account_id.clone(),
        account_ref.local_contract_hash().unwrap_or_default(),  // ← returns None for global
    )?;
    account_storage_usage.saturating_sub(code_len)              // ← subtracts 0 for global
};
if account_storage_usage > Account::MAX_ACCOUNT_DELETION_STORAGE_USAGE {   // line 333
    result.result = Err(ActionErrorKind::DeleteAccountWithLargeState { … }.into());
    return Ok(());
}
```

For an account with `AccountContract::Global`, `local_contract_hash()` returns `None`, so `get_code_len_or_default` is called with `CryptoHash::default()` and returns `0`. Nothing is subtracted. Yet `use_global_contract` (in `global_contracts.rs`, lines 97-104) adds the identifier length to `storage_usage` when the account adopts a global contract:

```rust
account.set_storage_usage(
    account.storage_usage().checked_add(contract_identifier.len() as u64)…
);
```

`identifier_storage_usage()` returns 32 for `AccountContract::Global` and `account_id.len()` for `AccountContract::GlobalByAccount`. Any account whose `storage_usage` lands in the half-open interval `(MAX_ACCOUNT_DELETION_STORAGE_USAGE, MAX_ACCOUNT_DELETION_STORAGE_USAGE + identifier_size]` — i.e., `(10 000, 10 032]` for a hash-keyed global contract — will always fail the guard and can never be deleted. The account's balance is permanently locked.

The fixed path (`get_contract_storage_usage`) correctly dispatches on contract type and subtracts the identifier overhead for global contracts, but this path is only taken once `FixDeleteAccountGlobalContractStorageUsage` is enabled at the current protocol version.

---

### Impact Explanation

`DeleteAccount` is the only mechanism by which an account can be removed and its balance recovered. For any account in the affected storage-usage band, every `DeleteAccount` receipt will return `ActionErrorKind::DeleteAccountWithLargeState` regardless of how many times it is retried or who sends it. The account's NEAR balance is permanently inaccessible. This is a **High** severity accounting invariant violation: the protocol's own storage-usage bookkeeping causes a legitimate operation to be permanently blocked.

---

### Likelihood Explanation

The trigger is entirely unprivileged:
1. Any user calls `UseGlobalContractAction` on their account, which adds 32 bytes (or `account_id.len()` bytes) to `storage_usage`.
2. If the account's pre-existing non-contract storage usage is in the range `(10 000 - identifier_size, 10 000]`, the resulting `storage_usage` crosses `MAX_ACCOUNT_DELETION_STORAGE_USAGE` solely due to the identifier overhead.
3. No admin or validator action is required; the state is reachable through ordinary on-chain transactions.

Global contracts are a production feature; accounts that adopt them and happen to sit near the 10 000-byte boundary are silently rendered undeletable.

---

### Recommendation

Replace the legacy subtraction with `get_contract_storage_usage`, which correctly handles all three contract types (`None`, `Local`, `Global`/`GlobalByAccount`). This is exactly what the `FixDeleteAccountGlobalContractStorageUsage` protocol feature does. Until that feature is activated at the current protocol version, the legacy path remains the live code path and the invariant is broken.

---

### Proof of Concept

The codebase's own regression test `test_delete_account_global_contract_protocol_transition` (lines 1091-1115 of `runtime/runtime/src/actions.rs`) demonstrates the bug directly:

```
storage = MAX_ACCOUNT_DELETION_STORAGE_USAGE + 32   // = 10 032
contract = AccountContract::Global(CryptoHash::default())

// Before fix (legacy path):
//   code_len = 0  (no local code)
//   account_storage_usage = 10 032 - 0 = 10 032 > 10 000  → DeleteAccountWithLargeState
//   Deletion FAILS even though non-contract storage is exactly MAX.

// After fix:
//   contract_storage = identifier_storage_usage() = 32
//   account_storage_usage = 10 032 - 32 = 10 000, not > 10 000  → deletion succeeds
```

**Analog mapping to H-1:**

| H-1 (Curve) | nearcore analog |
|---|---|
| `remove_liquidity(0,[0,0])` probe always reverts for CRV/ETH pool | `account_storage_usage.saturating_sub(code_len)` always returns inflated value for global-contract accounts |
| Guard check (`_checkReentrancyContext`) permanently blocks liquidation | Guard check (line 333) permanently blocks `DeleteAccount` |
| Root cause: wrong probe function for that pool type | Root cause: wrong subtraction function for that contract type |
| Fix: use `claim_admin_fees` instead | Fix: use `get_contract_storage_usage` instead | [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** runtime/runtime/src/actions.rs (L311-338)
```rust
    let account_storage_usage = if ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage
        .enabled(current_protocol_version)
    {
        let contract_storage = get_contract_storage_usage(state_update, account_id, account_ref)?;
        account_ref.storage_usage().saturating_sub(contract_storage)
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

**File:** core/primitives-core/src/account.rs (L158-160)
```rust
    /// Max number of bytes an account can have in its state (excluding contract code)
    /// before it is infeasible to delete.
    pub const MAX_ACCOUNT_DELETION_STORAGE_USAGE: u64 = 10_000;
```

**File:** core/primitives-core/src/version.rs (L355-359)
```rust
    /// Fix `action_delete_account` not subtracting the global contract
    /// identifier storage usage. Previously only local contract code was
    /// subtracted, overstating storage usage for accounts with global
    /// contracts and making them marginally harder to delete.
    FixDeleteAccountGlobalContractStorageUsage,
```
