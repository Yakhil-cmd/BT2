[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/execution/dispatch_tables.rs (L25-30)
```rust
use move_binary_format::{
    checked_as,
    errors::{Location, PartialVMResult, VMResult},
    file_format::{AbilitySet, TypeParameterIndex},
    partial_vm_error,
};
```

**File:** external-crates/move/crates/move-vm-runtime/src/execution/dispatch_tables.rs (L131-139)
```rust
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct DepthFormula {
    /// The terms for each type parameter, if present.
    /// Ti + Ci
    pub terms: Vec<(TypeParameterIndex, u64)>,
    /// The minimal depth of the value of this type regardless of type parameters.
    /// CBase
    pub constant: u64,
}
```
