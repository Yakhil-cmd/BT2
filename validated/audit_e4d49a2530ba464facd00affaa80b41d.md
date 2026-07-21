Looking at the `replace_class` implementation in the deprecated syscall handler and comparing it to other syscalls that properly guard against validate-mode execution:

**`replace_class` in `DeprecatedSyscallHintProcessor` (lines 795–807):**

```rust
fn replace_class(
    request: ReplaceClassRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut Self,
) -> DeprecatedSyscallResult<ReplaceClassResponse> {
    syscall_handler.state.get_compiled_class(request.class_hash)?;
    syscall_handler
        .state
        .set_class_hash_at(syscall_handler.storage_address, request.class_hash)?;
    Ok(ReplaceClassResponse {})
}
```

There is **no** call to `verify_not_in_validate_mode` and no `ExecutionMode::Validate` check. [1](#0-0) 

The helper `verify_not_in_validate_mode` exists and is available to the handler: [2](#0-1) 

Other state-mutating syscalls in the same handler do guard against validate mode. For example, `call_contract` explicitly checks `is_validate_mode()`: [3](#0-2) 

And `deploy` checks `should_reject_deploy(...)` which gates on `ExecutionMode::Validate`: [4](#0-3) 

The Cairo1 path in `syscall_base.rs` similarly guards `get_class_hash_at` against validate mode: [5](#0-4) 

---

### Title
Missing `ExecutionMode::Validate` guard in `DeprecatedSyscallHintProcessor::replace_class` allows Cairo0 `__validate__` to mutate contract class hash — (`crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs`)

### Summary
The deprecated (Cairo0) syscall handler's `replace_class` implementation performs a direct `set_class_hash_at` state write with no check for `ExecutionMode::Validate`. A Cairo0 account contract whose `__validate__` entry point calls `replace_class` with any declared class hash will successfully overwrite its own class hash in state during the validation phase, violating the invariant that `__validate__` must not mutate state.

### Finding Description
`DeprecatedSyscallHintProcessor::replace_class` (lines 795–807) calls `syscall_handler.state.set_class_hash_at(syscall_handler.storage_address, request.class_hash)` unconditionally. The handler exposes `verify_not_in_validate_mode` and `is_validate_mode()` helpers, and every other state-mutating deprecated syscall (`call_contract`, `deploy`, `emit_event` indirectly via context limits) either checks the execution mode or is gated by a versioned-constants flag. `replace_class` has no such guard. Because `__validate__` runs under `ExecutionMode::Validate` and its state changes are committed on success (only reverted on failure/revert), a successful `replace_class` call inside `__validate__` permanently changes the contract's class hash before `__execute__` runs.

### Impact Explanation
**Critical — Wrong state / class hash from blockifier/syscall execution logic.**

After `__validate__` completes successfully, the blockifier does not roll back its state writes. The contract's class hash at `storage_address` is now the attacker-chosen hash. Subsequent execution (`__execute__`) and all future transactions to that account will dispatch to the replaced class. This corrupts the on-chain class-hash mapping for the account address, producing a wrong class hash in committed state.

### Likelihood Explanation
Any unprivileged user can deploy a Cairo0 account contract (via `deploy_account`) whose `__validate__` body calls the `replace_class` syscall with a previously declared class hash. No operator or privileged access is required. The only prerequisite is that the replacement class hash is declared on-chain, which is itself an unprivileged operation.

### Recommendation
Add a validate-mode guard at the top of `replace_class`, mirroring the pattern used by `call_contract` and `deploy`:

```rust
fn replace_class(
    request: ReplaceClassRequest,
    _vm: &mut VirtualMachine,
    syscall_handler: &mut Self,
) -> DeprecatedSyscallResult<ReplaceClassResponse> {
    syscall_handler.verify_not_in_validate_mode("replace_class")?;
    syscall_handler.state.get_compiled_class(request.class_hash)?;
    syscall_handler
        .state
        .set_class_hash_at(syscall_handler.storage_address, request.class_hash)?;
    Ok(ReplaceClassResponse {})
}
```

Also verify the Cairo1 path (`syscall_base.rs` `replace_class`) carries an equivalent guard.

### Proof of Concept
1. Declare two Cairo0 classes: `ClassA` (the account, whose `__validate__` calls `replace_class(class_hash_of_B)`) and `ClassB` (any valid Cairo0 class).
2. Declare `ClassB` on-chain so `get_compiled_class` succeeds.
3. Submit a `deploy_account` transaction deploying `ClassA`.
4. Submit any invoke transaction from the deployed account. During `__validate__`, `replace_class` executes without error, writing `ClassB`'s hash to the account's address in state.
5. Assert: `state.get_class_hash_at(account_address) == class_hash_of_B` after the transaction is applied — the class hash has been corrupted during validation. [1](#0-0) [6](#0-5)

### Citations

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L281-295)
```rust
    pub fn is_validate_mode(&self) -> bool {
        self.execution_mode() == ExecutionMode::Validate
    }

    /// Returns an error if the syscall is run in validate mode.
    pub fn verify_not_in_validate_mode(&self, syscall_name: &str) -> DeprecatedSyscallResult<()> {
        if self.is_validate_mode() {
            return Err(DeprecatedSyscallExecutionError::InvalidSyscallInExecutionMode {
                syscall_name: syscall_name.to_string(),
                execution_mode: self.execution_mode(),
            });
        }

        Ok(())
    }
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L543-550)
```rust
        // Check that the call is legal if in Validate execution mode.
        if syscall_handler.is_validate_mode() && syscall_handler.storage_address != storage_address
        {
            return Err(DeprecatedSyscallExecutionError::InvalidSyscallInExecutionMode {
                syscall_name: "call_contract".to_string(),
                execution_mode: syscall_handler.execution_mode(),
            });
        }
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L598-608)
```rust
        let versioned_constants =
            &syscall_handler.context.tx_context.block_context.versioned_constants;
        if should_reject_deploy(
            versioned_constants.disable_deploy_in_validation_mode,
            syscall_handler.execution_mode(),
        ) {
            return Err(DeprecatedSyscallExecutionError::InvalidSyscallInExecutionMode {
                syscall_name: "deploy".to_string(),
                execution_mode: syscall_handler.execution_mode(),
            });
        }
```

**File:** crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs (L795-807)
```rust
    fn replace_class(
        request: ReplaceClassRequest,
        _vm: &mut VirtualMachine,
        syscall_handler: &mut Self,
    ) -> DeprecatedSyscallResult<ReplaceClassResponse> {
        // Ensure the class is declared (by reading it).
        syscall_handler.state.get_compiled_class(request.class_hash)?;
        syscall_handler
            .state
            .set_class_hash_at(syscall_handler.storage_address, request.class_hash)?;

        Ok(ReplaceClassResponse {})
    }
```

**File:** crates/blockifier/src/execution/syscalls/syscall_base.rs (L225-227)
```rust
        if self.context.execution_mode == ExecutionMode::Validate {
            self.reject_syscall_in_validate_mode("get_class_hash_at")?;
        }
```
