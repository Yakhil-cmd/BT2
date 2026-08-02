[1](#0-0) [2](#0-1)

### Citations

**File:** api/types/src/wrappers.rs (L1-19)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! The purpose of this file is to define wrappers that we can use in the
//! endpoint handlers, specifically for accepting these types as parameters.
//! In Poem, it is not enough to impl FromStr for the types we want to use
//! as path parameters, as that does not describe anything about the input.
//! These wrappers say "I don't care" and use the impl_poem_type and
//! impl_poem_parameter macros to make it that we declare these inputs as
//! just strings, using the FromStr impl to parse the path param. They can
//! then be unpacked to the real type beneath.

use crate::{Address, VerifyInput, U64};
use anyhow::{bail, Context};
use aptos_types::{event::EventKey, state_store::state_key::StateKey};
use move_core_types::identifier::{IdentStr, Identifier};
use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use std::{convert::From, fmt, ops::Deref, str::FromStr};
```

**File:** api/types/src/move_types.rs (L1-31)
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
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    convert::{From, Into, TryFrom, TryInto},
    fmt,
    fmt::Display,
    result::Result,
    str::FromStr,
};
```
