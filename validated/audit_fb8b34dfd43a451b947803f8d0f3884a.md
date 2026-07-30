[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** external-crates/move/crates/move-bytecode-verifier/src/stack_usage_verifier.rs (L78-116)
```rust
            // Check that the stack height is sufficient to accommodate the number
            // of pops this instruction does
            if stack_size_increment < num_pops {
                return Err(
                    PartialVMError::new(StatusCode::NEGATIVE_STACK_SIZE_WITHIN_BLOCK)
                        .at_code_offset(self.current_function(), block_start),
                );
            }
            if let Some(new_incr) = u64::checked_sub(stack_size_increment, num_pops) {
                stack_size_increment = new_incr
            } else {
                return Err(
                    PartialVMError::new(StatusCode::NEGATIVE_STACK_SIZE_WITHIN_BLOCK)
                        .at_code_offset(self.current_function(), block_start),
                );
            };
            if let Some(new_incr) = u64::checked_add(stack_size_increment, num_pushes) {
                stack_size_increment = new_incr
            } else {
                return Err(
                    PartialVMError::new(StatusCode::POSITIVE_STACK_SIZE_AT_BLOCK_END)
                        .at_code_offset(self.current_function(), block_start),
                );
            };

            if stack_size_increment > config.max_value_stack_size as u64 {
                return Err(PartialVMError::new(StatusCode::VALUE_STACK_OVERFLOW)
                    .at_code_offset(self.current_function(), block_start));
            }
        }

        if stack_size_increment == 0 {
            Ok(())
        } else {
            Err(
                PartialVMError::new(StatusCode::POSITIVE_STACK_SIZE_AT_BLOCK_END)
                    .at_code_offset(self.current_function(), block_start),
            )
        }
```

**File:** external-crates/move/crates/move-bytecode-verifier/src/stack_usage_verifier.rs (L254-262)
```rust
            Bytecode::Unpack(idx) => {
                let struct_definition = self.module.struct_def_at(*idx);
                let field_count = match &struct_definition.field_information {
                    // 'Native' here is an error that will be caught by the bytecode verifier later
                    StructFieldInformation::Native => 0,
                    StructFieldInformation::Declared(fields) => fields.len(),
                };
                (1, field_count as u64)
            }
```

**File:** external-crates/move/crates/move-bytecode-verifier/src/type_safety.rs (L1-1)
```rust
// Copyright (c) The Diem Core Contributors
```
