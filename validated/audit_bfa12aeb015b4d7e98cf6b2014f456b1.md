[1](#0-0)

### Citations

**File:** program-runtime/src/cpi.rs (L825-836)
```rust
            let update_caller = update_callee_account(
                memory_mapping,
                check_aligned,
                &translated_account.caller_account,
                callee_account,
                syscall_parameter_address_restrictions,
                virtual_address_space_adjustments,
                account_data_direct_mapping,
            )?;
            translated_account.update_caller_account_region =
                translated_account.update_caller_account_info || update_caller;
        }
```
