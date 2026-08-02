[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** third_party/move/move-core/types/src/vm_status.rs (L132-142)
```rust
/// A status type is one of 5 different variants, along with a fallback variant in the case that we
/// don't recognize the status code.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum StatusType {
    Validation,
    Verification,
    InvariantViolation,
    Deserialization,
    Execution,
    Unknown,
}
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L204-232)
```rust
    pub fn keep_or_discard(
        self,
        function_values_enabled: bool,
        memory_limit_exceeded_as_miscellaneous_error: bool,
        abort_messages_enabled: bool,
    ) -> Result<KeptVMStatus, DiscardedVMStatus> {
        match self {
            VMStatus::Executed => Ok(KeptVMStatus::Executed),
            VMStatus::MoveAbort {
                location,
                code,
                message,
            } => Ok(KeptVMStatus::MoveAbort {
                location,
                code,
                message: if abort_messages_enabled {
                    message
                } else {
                    None
                },
            }),
            VMStatus::ExecutionFailure {
                status_code: StatusCode::OUT_OF_GAS,
                ..
            }
            | VMStatus::Error {
                status_code: StatusCode::OUT_OF_GAS,
                ..
            } => Ok(KeptVMStatus::OutOfGas),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3254-3272)
```rust
                if let StatusType::InvariantViolation = vm_status.status_type() {
                    match vm_status.status_code() {
                        // Type resolution failure can be triggered by user input when providing a bad type argument, skip this case.
                        StatusCode::TYPE_RESOLUTION_FAILURE
                        if vm_status.sub_status()
                            == Some(move_core_types::vm_status::sub_status::type_resolution_failure::EUSER_TYPE_LOADING_FAILURE) => {},
                        // The known Move function failure and type resolution failure could be a result of speculative execution. Use speculative logger.
                        StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION
                        | StatusCode::TYPE_RESOLUTION_FAILURE => {
                            speculative_error!(
                                log_context,
                                format!(
                                    "[aptos_vm] Transaction breaking invariant violation: {:?}\ntxn: {:?}",
                                    vm_status,
                                    bcs::to_bytes::<SignedTransaction>(txn),
                                ),
                            );
                        },
                        // Paranoid mode failure. We need to be alerted about this ASAP.
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/aptosvm_authenticators.rs (L462-474)
```rust
    match tdbg!(status) {
        ExecutionStatus::Success => (),
        ExecutionStatus::MiscellaneousError(e) => {
            if let Some(e) = e {
                if e.status_type() == StatusType::InvariantViolation
                    && *e != StatusCode::TYPE_RESOLUTION_FAILURE
                    && *e != StatusCode::STORAGE_ERROR
                {
                    panic!("invariant violation {:?}", e);
                }
            }
            return Err(Corpus::Keep);
        },
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/aptosvm_publish_and_run.rs (L280-293)
```rust
    match tdbg!(status) {
        ExecutionStatus::Success => (),
        ExecutionStatus::MiscellaneousError(e) => {
            if let Some(e) = e {
                if (e.status_type() == StatusType::InvariantViolation
                    || e.status_type() == StatusType::Unknown)
                    && *e != StatusCode::TYPE_RESOLUTION_FAILURE
                    && *e != StatusCode::STORAGE_ERROR
                {
                    panic!("invariant violation {:?}, {:?}", e, res.auxiliary_data());
                }
            }
            return Err(Corpus::Keep);
        },
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/aptosvm_publish_and_run_transactional.rs (L350-364)
```rust
            match tdbg!(status) {
                ExecutionStatus::Success | ExecutionStatus::OutOfGas => {
                    vm.apply_write_set(res.write_set())
                },
                ExecutionStatus::MiscellaneousError(e) => {
                    if let Some(e) = e {
                        if e.status_type() == StatusType::InvariantViolation
                            && *e != StatusCode::TYPE_RESOLUTION_FAILURE
                            && *e != StatusCode::STORAGE_ERROR
                        {
                            panic!("invariant violation {:?}, {:?}", e, res.auxiliary_data());
                        }
                    }
                    return Err(Corpus::Keep);
                },
```
