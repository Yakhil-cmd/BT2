### Title
`GlobalContractIdentifier::len()` Understates Storage Usage for `AccountId` Variant, Allowing Storage-Stake Bypass — (`runtime/runtime/src/global_contracts.rs`)

---

### Summary

`GlobalContractIdentifier::len()` for the `AccountId` variant returns only the raw string byte count (`account_id.len()`), omitting the 4-byte Borsh `u32` length prefix that is part of the actual serialized `AccountContract::GlobalByAccount(AccountId)` payload stored in the `AccountV2` trie entry. `use_global_contract` uses this value to increment `account.storage_usage`, causing it to be understated by **4 bytes** per `GlobalByAccount` reference. The storage-stake check then passes with less balance than the trie actually requires.

---

### Finding Description

**`GlobalContractIdentifier::len()` — understated for `AccountId`** [1](#0-0) 

For `AccountId`, this returns `account_id.len()` — the raw UTF-8 byte count only.

**Actual Borsh layout of `AccountContract::GlobalByAccount(AccountId)` inside `AccountV2`:**

```
[1 byte discriminant][4 bytes u32 string length][N bytes string content]
```

`AccountContract::None` (the baseline) serializes to exactly 1 byte (discriminant only). Switching to `GlobalByAccount(account_id)` grows the account struct by `4 + N` bytes (the u32 length prefix + string content). Only `N` bytes are credited to `storage_usage`. [2](#0-1) 

**`use_global_contract` applies the understated value:** [3](#0-2) 

`contract_identifier.len()` = `account_id.len()` = N. The 4-byte u32 length prefix is never added.

**`AccountContract::identifier_storage_usage()` has the same defect:** [4](#0-3) 

Both the add path (`use_global_contract`) and the subtract path (`clear_account_contract_storage_usage`) use the same understated value, so the error is **not self-correcting** — it persists permanently in `storage_usage` for any account holding a `GlobalByAccount` reference.

**Contrast with `Global(CryptoHash)`:** that variant returns `32`, which exactly matches the hash payload size (the discriminant byte is shared baseline for all variants, so the net increase from `None` → `Global` is correctly 32 bytes). [5](#0-4) 

---

### Impact Explanation

`storage_usage` is the sole input to the storage-stake check. An account whose `storage_usage` is understated by 4 bytes can satisfy the check while holding ~4 × `storage_amount_per_byte` less NEAR than the trie actually requires. At the current mainnet parameter of `10^19` yoctoNEAR/byte, this is **~0.04 NEAR** of free storage per account using `GlobalByAccount`. The ledger invariant — `storage_usage` equals actual trie bytes consumed — is violated for every such account.

---

### Likelihood Explanation

Any unprivileged user can trigger this by submitting a `UseGlobalContractAction` with `GlobalContractIdentifier::AccountId(...)`. No special privileges are required. The existing integration test at line 144–147 of `test-loop-tests/src/tests/global_contracts.rs` asserts `storage_usage == baseline + identifier.len()`, which **encodes the bug as the expected value** rather than catching it. [6](#0-5) 

---

### Recommendation

Fix `GlobalContractIdentifier::len()` for the `AccountId` variant to include the 4-byte Borsh u32 length prefix:

```rust
GlobalContractIdentifier::AccountId(account_id) => account_id.len() + 4,
```

Apply the same correction to `AccountContract::identifier_storage_usage()` for `GlobalByAccount`. Update the integration test assertion to use `borsh::object_length` of the actual `AccountContract::GlobalByAccount(id)` minus `borsh::object_length` of `AccountContract::None` as the expected delta.

---

### Proof of Concept

```rust
use borsh::BorshSerialize;
use near_primitives_core::account::AccountContract;
use near_account_id::AccountId;

let id: AccountId = "alice.near".parse().unwrap();
let none_size = borsh::object_length(&AccountContract::None).unwrap();
let gba_size  = borsh::object_length(&AccountContract::GlobalByAccount(id.clone())).unwrap();
let expected_delta = (gba_size - none_size) as u64;  // = id.len() + 4 = 14

let reported_delta = id.len() as u64;                // = 10

assert_eq!(expected_delta, reported_delta);          // FAILS: 14 ≠ 10
```

The 4-byte gap is the Borsh `u32` string-length prefix that `GlobalContractIdentifier::len()` silently drops.

### Citations

**File:** core/primitives-core/src/global_contract.rs (L32-39)
```rust
impl GlobalContractIdentifier {
    pub fn len(&self) -> usize {
        match self {
            GlobalContractIdentifier::CodeHash(_) => 32,
            GlobalContractIdentifier::AccountId(account_id) => account_id.len(),
        }
    }
}
```

**File:** core/primitives-core/src/account.rs (L89-94)
```rust
pub enum AccountContract {
    None,
    Local(CryptoHash),
    Global(CryptoHash),
    GlobalByAccount(AccountId),
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

**File:** test-loop-tests/src/tests/global_contracts.rs (L144-147)
```rust
        assert_eq!(
            account_state.storage_usage,
            baseline_storage_usage + identifier.len() as StorageUsage
        );
```
