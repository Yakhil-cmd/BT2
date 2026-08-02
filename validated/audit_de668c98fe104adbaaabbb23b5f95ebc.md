[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** types/src/error.rs (L154-168)
```rust
/// Construct a canonical error code from a category and a reason.
pub fn canonical(category: u64, reason: u64) -> u64 {
    (category << 16) + reason
}

/// Functions to construct a canonical error code of the given category.
pub fn invalid_argument(r: u64) -> u64 {
    canonical(INVALID_ARGUMENT, r)
}
pub fn out_of_range(r: u64) -> u64 {
    canonical(OUT_OF_RANGE, r)
}
pub fn invalid_state(r: u64) -> u64 {
    canonical(INVALID_STATE, r)
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L61-75)
```text
    /// Prologue errors. These are separated out from the other errors in this
    /// module since they are mapped separately to major VM statuses, and are
    /// important to the semantics of the system.
    const PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY: u64 = 1001;
    const PROLOGUE_ESEQUENCE_NUMBER_TOO_OLD: u64 = 1002;
    const PROLOGUE_ESEQUENCE_NUMBER_TOO_NEW: u64 = 1003;
    const PROLOGUE_EACCOUNT_DOES_NOT_EXIST: u64 = 1004;
    const PROLOGUE_ECANT_PAY_GAS_DEPOSIT: u64 = 1005;
    const PROLOGUE_ETRANSACTION_EXPIRED: u64 = 1006;
    const PROLOGUE_EBAD_CHAIN_ID: u64 = 1007;
    const PROLOGUE_ESEQUENCE_NUMBER_TOO_BIG: u64 = 1008;
    const PROLOGUE_ESECONDARY_KEYS_ADDRESSES_COUNT_MISMATCH: u64 = 1009;
    const PROLOGUE_EFEE_PAYER_NOT_ENABLED: u64 = 1010;
    const PROLOGUE_ENONCE_ALREADY_USED: u64 = 1012;
    const PROLOGUE_ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE: u64 = 1013;
```

**File:** aptos-move/aptos-vm/src/errors.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```
