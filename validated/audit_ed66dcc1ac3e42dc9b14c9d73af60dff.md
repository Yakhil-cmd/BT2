[1](#0-0)

### Citations

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L4-26)
```rust
use crate::{
    abstract_write_op::{
        AbstractResourceWriteOp, GroupWrite, InPlaceDelayedFieldChangeOp,
        ResourceGroupInPlaceDelayedFieldChangeOp, WriteWithDelayedFieldsOp,
    },
    module_and_script_storage::module_storage::AptosModuleStorage,
    module_write_set::{ModuleWrite, ModuleWriteSet},
    resolver::ExecutorView,
};
use aptos_aggregator::delayed_change::DelayedChange;
use aptos_types::{
    contract_event::ContractEvent,
    error::{code_invariant_error, PanicError},
    state_store::{
        state_key::{inner::StateKeyInner, StateKey},
        state_value::StateValueMetadata,
    },
    transaction::ChangeSet as StorageChangeSet,
    write_set::{TransactionWrite, WriteOp, WriteOpSize, WriteSetMut},
};
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_core_types::{value::MoveTypeLayout, vm_status::StatusCode};
use move_vm_types::delayed_values::delayed_field_id::DelayedFieldID;
```
