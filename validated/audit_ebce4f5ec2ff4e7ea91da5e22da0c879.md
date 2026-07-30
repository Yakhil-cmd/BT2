[1](#0-0) [2](#0-1)

### Citations

**File:** external-crates/move/crates/move-binary-format/src/file_format_common.rs (L185-186)
```rust
pub const VARIANT_INSTANTIATION_HANDLE_INDEX_MAX: u64 = 1024;
pub const VARIANT_HANDLE_INDEX_MAX: u64 = 1024;
```

**File:** external-crates/move/crates/move-binary-format/src/check_bounds.rs (L1-21)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    IndexKind,
    errors::{
        PartialVMError, PartialVMResult, bounds_error,
        offset_out_of_bounds as offset_out_of_bounds_error, verification_error,
    },
    file_format::{
        AbilitySet, Bytecode, CodeOffset, CodeUnit, CompiledModule, Constant, DatatypeHandle,
        EnumDefInstantiation, EnumDefinition, FieldHandle, FieldInstantiation, FunctionDefinition,
        FunctionDefinitionIndex, FunctionHandle, FunctionInstantiation, JumpTableInner, LocalIndex,
        ModuleHandle, Signature, SignatureToken, StructDefInstantiation, StructDefinition,
        StructFieldInformation, TableIndex, VariantDefinition, VariantHandle,
        VariantInstantiationHandle, VariantJumpTable,
    },
    internals::ModuleIndex,
    safe_assert,
};
```
