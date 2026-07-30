[1](#0-0)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/execution/values/values_impl.rs (L5-18)
```rust
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
```
