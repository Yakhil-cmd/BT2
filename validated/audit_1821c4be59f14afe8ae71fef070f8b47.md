[1](#0-0)

### Citations

**File:** api/types/src/move_types.rs (L1-22)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{Address, Bytecode, IdentifierWrapper, VerifyInput, VerifyInputWithRecursion};
use anyhow::{bail, format_err};
use aptos_resource_viewer::{AnnotatedMoveClosure, AnnotatedMoveStruct, AnnotatedMoveValue};
use aptos_types::{account_config::CORE_CODE_ADDRESS, event::EventKey, transaction::Module};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{CompiledModule, CompiledScript, StructTypeParameter, Visibility},
};
use move_core_types::{
    ability::{Ability, AbilitySet},
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{
        FunctionParamOrReturnTag, FunctionTag, ModuleId, StructTag, TypeTag, LEGACY_OPTION_VEC,
    },
    parser::{parse_struct_tag, parse_type_tag},
    transaction_argument::TransactionArgument,
};
use poem_openapi::{types::Type, Enum, Object, Union};
```
