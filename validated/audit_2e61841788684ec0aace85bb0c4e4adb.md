[1](#0-0) [2](#0-1)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/execution/values/values_impl.rs (L1-1)
```rust
// Copyright (c) The Diem Core Contributors
```

**File:** external-crates/move/crates/move-vm-runtime/src/execution/interpreter/locals.rs (L1-45)
```rust
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(unsafe_code)]

use crate::{
    execution::values::{MemBox, values_impl::Value},
    shared::safe_ops::SafeArithmetic as _,
};

use move_binary_format::{errors::PartialVMResult, partial_vm_error, safe_assert};

use std::collections::HashMap;

// -------------------------------------------------------------------------------------------------
// Heap
// -------------------------------------------------------------------------------------------------

/// The Move VM's base heap. This is PTBs and arguments to invocation functions are stored, so that
/// we can handle references to/from them.
#[derive(Debug)]
pub struct BaseHeap {
    next_id: usize,
    values: HashMap<BaseHeapId, MemBox<Value>>,
}

/// An ID for an entry in a Base Heap.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct BaseHeapId(usize);

/// The runtime machine "heap" for execution. This allows us to grab and return frame slots and the
/// like. Note that this isn't a _true_ heap (crrently), it only allows for allocating and freeing
/// stackframes.
#[derive(Debug)]
pub struct MachineHeap {
    /// Tracks the current stack frame slots on the heap
    cur_size: usize,
}

/// A stack frame is an allocated frame. It was allocated starting at `start` in the heap. When it
/// is freed, we need to check that we are freeing the one on the end of the heap.
#[derive(Debug)]
pub struct StackFrame {
    slice: Vec<MemBox<Value>>,
}
```
