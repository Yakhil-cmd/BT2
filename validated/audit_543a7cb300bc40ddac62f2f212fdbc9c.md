[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** external-crates/move/crates/move-bytecode-verifier-meter/src/lib.rs (L48-65)
```rust
    /// Adds the number of items with growth factor
    #[deprecated(note = "this function is extremely slow and should be avoided")]
    fn add_items_with_growth(
        &mut self,
        scope: Scope,
        mut units_per_item: u128,
        items: usize,
        growth_factor: f32,
    ) -> PartialVMResult<()> {
        if items == 0 {
            return Ok(());
        }
        for _ in 0..items {
            self.add(scope, units_per_item)?;
            units_per_item = growth_factor.mul(units_per_item as f32) as u128;
        }
        Ok(())
    }
```

**File:** external-crates/move/crates/move-bytecode-verifier-meter/src/bound.rs (L22-37)
```rust
impl Meter for BoundMeter {
    fn enter_scope(&mut self, name: &str, scope: Scope) {
        let bounds = self.get_bounds_mut(scope);
        bounds.name = name.into();
        bounds.units = 0;
    }

    fn transfer(&mut self, from: Scope, to: Scope, factor: f32) -> PartialVMResult<()> {
        let units = (self.get_bounds_mut(from).units as f32 * factor) as u128;
        self.add(to, units)
    }

    fn add(&mut self, scope: Scope, units: u128) -> PartialVMResult<()> {
        self.get_bounds_mut(scope).add(units)
    }
}
```

**File:** external-crates/move/move-execution/v2/crates/move-bytecode-verifier/src/reference_safety/abstract_state.rs (L1-20)
```rust
// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines the abstract state for the type and memory safety analysis.
use crate::absint::{AbstractDomain, FunctionContext, JoinResult};
use move_binary_format::{
    errors::{PartialVMError, PartialVMResult},
    file_format::{
        CodeOffset, FieldHandleIndex, FunctionDefinitionIndex, LocalIndex, Signature,
        SignatureToken, StructDefinitionIndex,
    },
    safe_unwrap,
};
use move_borrow_graph::references::RefID;
use move_bytecode_verifier_meter::{Meter, Scope};
use move_core_types::vm_status::StatusCode;
use std::collections::{BTreeMap, BTreeSet};

type BorrowGraph = move_borrow_graph::graph::BorrowGraph<(), Label>;
```
