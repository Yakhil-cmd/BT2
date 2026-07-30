[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** external-crates/move/crates/move-core-types/src/runtime_value.rs (L1-24)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    VARIANT_TAG_MAX_VALUE,
    account_address::AccountAddress,
    annotated_value as A, fmt_list,
    runtime_visitor::{Error as VError, ValueDriver, Visitor, visit_struct, visit_value},
    u256,
};
use anyhow::{Result as AResult, anyhow};
use move_proc_macros::test_variant_order;
use serde::{
    Deserialize, Serialize,
    de::Error as DeError,
    ser::{SerializeSeq, SerializeTuple},
};
use std::{
    fmt::{self, Debug},
    io::Cursor,
};

pub use crate::compressed::runtime as compressed_layouts;
```

**File:** external-crates/move/crates/move-core-types/src/runtime_value.rs (L38-59)
```rust
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MoveVariant {
    pub tag: u16,
    pub fields: Vec<MoveValue>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MoveValue {
    U8(u8),
    U64(u64),
    U128(u128),
    Bool(bool),
    Address(AccountAddress),
    Vector(Vec<MoveValue>),
    Struct(MoveStruct),
    Signer(AccountAddress),
    // NOTE: Added in bytecode version v6, do not reorder!
    U16(u16),
    U32(u32),
    U256(u256::U256),
    Variant(MoveVariant),
}
```
