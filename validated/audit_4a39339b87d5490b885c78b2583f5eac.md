[1](#0-0) [2](#0-1)

### Citations

**File:** external-crates/move/crates/move-binary-format/src/lib.rs (L237-249)
```rust
macro_rules! checked_as {
    ($value:expr, $target_type:ty) => {{
        let v = $value;
        <$target_type>::try_from(v).map_err(|e| {
            $crate::partial_vm_error!(
                UNKNOWN_INVARIANT_VIOLATION_ERROR,
                "Value {} cannot be safely cast to {}: {:?}",
                v,
                stringify!($target_type),
                e
            )
        })
    }};
```

**File:** external-crates/move/crates/move-binary-format/src/deserializer.rs (L1-20)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    binary_config::{BinaryConfig, TableConfig},
    check_bounds::BoundsChecker,
    errors::*,
    file_format::*,
    file_format_common::*,
};
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, metadata::Metadata,
    vm_status::StatusCode,
};
use std::{
    collections::HashSet,
    convert::TryInto,
    io::{Cursor, Read},
};
```
