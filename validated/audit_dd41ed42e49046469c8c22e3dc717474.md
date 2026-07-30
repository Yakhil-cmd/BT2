[1](#0-0) [2](#0-1)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/jit/execution/translate.rs (L1-41)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cache::{
        arena::{ArenaBox, ArenaBuilder, ArenaVec},
        identifier_interner::{IdentifierInterner, IdentifierKey},
    },
    dbg_println,
    execution::{
        dispatch_tables::{DefinitionMap, IntraPackageKey, PackageVirtualTable, VirtualTableKey},
        values::Value,
    },
    jit::{execution::ast::*, optimization::ast as input},
    natives::functions::NativeFunctions,
    shared::{
        TypeSize,
        safe_ops::{SafeArithmetic as _, SafeIndex as _},
        types::{DefiningTypeId, OriginalId, VersionId},
        unique_map,
        vm_pointer::VMPointer,
    },
};
use move_binary_format::{
    checked_as,
    errors::{PartialVMError, PartialVMResult},
    file_format::{
        self as FF, CompiledModule, FunctionDefinition, FunctionDefinitionIndex,
        FunctionHandleIndex, SignatureIndex, SignatureToken, StructFieldInformation, TableIndex,
    },
    partial_vm_error,
};
use move_core_types::{
    identifier::Identifier, language_storage::ModuleId, resolver::IntraPackageName,
};

use indexmap::IndexMap;
use tracing::instrument;

use std::collections::{BTreeMap, BTreeSet, HashMap};
```

**File:** external-crates/move/crates/move-vm-runtime/src/jit/execution/translate.rs (L47-86)
```rust
struct PackageContext<'borrows> {
    pub natives: &'borrows NativeFunctions,
    pub interner: &'borrows IdentifierInterner,

    pub type_origin_table: HashMap<IntraPackageKey, DefiningTypeId>,

    pub version_id: VersionId,
    pub original_id: OriginalId,
    // NB: this is under the package's context so we don't need to further resolve by
    // address in this table.
    pub loaded_modules: IndexMap<IdentifierKey, Module>,

    // NB: All things except for types are allocated into this arena.
    pub package_arena: ArenaBuilder,

    pub vtable_funs: DefinitionMap<VMPointer<Function>>,
    pub vtable_types: DefinitionMap<VMPointer<DatatypeDescriptor>>,
}

struct FunctionContext<'pkg_ctxt, 'natives> {
    package_context: &'pkg_ctxt PackageContext<'natives>,
    module: &'pkg_ctxt CompiledModule,
    definitions: Definitions,
}

struct Definitions {
    structs: Vec<VMPointer<StructDef>>,
    struct_instantiations: Vec<VMPointer<StructInstantiation>>,
    #[allow(unused)]
    enums: Vec<VMPointer<EnumDef>>,
    #[allow(unused)]
    enum_instantiations: Vec<VMPointer<EnumInstantiation>>,
    variants: Vec<VMPointer<VariantDef>>,
    variant_instantiations: Vec<VMPointer<VariantInstantiation>>,
    field_handles: Vec<VMPointer<FieldHandle>>,
    field_instantiations: Vec<VMPointer<FieldInstantiation>>,
    function_instantiations: Vec<VMPointer<FunctionInstantiation>>,
    signatures: Vec<VMPointer<ArenaVec<ArenaType>>>,
    constants: Vec<VMPointer<Constant>>,
}
```
