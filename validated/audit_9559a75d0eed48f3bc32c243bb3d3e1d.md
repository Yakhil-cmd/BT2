[1](#0-0)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/execution/values/values_impl.rs (L1-26)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cache::arena::{ArenaBuilder, ArenaVec},
    jit::execution::ast::Type,
    shared::{
        safe_ops::{SafeArithmetic as _, SafeIndex as _},
        views::{ValueView, ValueVisitor},
    },
};
use move_binary_format::{
    checked_as,
    errors::*,
    file_format::{Constant, SignatureToken, VariantTag},
    partial_vm_error,
};
use move_core_types::{
    VARIANT_TAG_MAX_VALUE,
    account_address::AccountAddress,
    runtime_value::{MoveEnumLayout, MoveStructLayout, MoveTypeLayout},
    u256,
    vm_status::sub_status::NFE_VECTOR_ERROR_BASE,
};
use std::fmt::{self, Debug, Display, Formatter};
```
