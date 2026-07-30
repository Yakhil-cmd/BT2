[1](#0-0)

### Citations

**File:** external-crates/move/crates/move-binary-format/src/normalized.rs (L1-21)
```rust
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::file_format::{
    self, AbilitySet, Bytecode as FBytecode, CodeOffset, CompiledModule, DatatypeHandleIndex,
    DatatypeTyParameter, EnumDefinition, EnumDefinitionIndex, FieldDefinition, FieldHandleIndex,
    FieldInstantiationIndex, FunctionDefinition, FunctionHandleIndex, FunctionInstantiationIndex,
    JumpTableInner, LocalIndex, SignatureIndex, SignatureToken, StructDefInstantiationIndex,
    StructDefinition, StructDefinitionIndex, StructFieldInformation, TypeParameterIndex,
    VariantDefinition, VariantHandleIndex, VariantInstantiationHandleIndex, VariantTag, Visibility,
};
use indexmap::IndexMap;
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{StructTag, TypeTag},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow, collections::HashSet, fmt::Debug, hash::Hash, ops::Deref, rc::Rc, sync::Arc,
};
```
