[1](#0-0) [2](#0-1)

### Citations

**File:** external-crates/move/crates/move-bytecode-verifier/src/limits.rs (L326-332)
```rust
                let weight = *size_table.entry(sig_idx).or_insert_with(|| {
                    self.module
                        .signature_at(sig_idx)
                        .0
                        .iter()
                        .fold(0usize, |acc, ty| acc.saturating_add(weighted_type_size(ty)))
                });
```

**File:** external-crates/move/crates/move-bytecode-verifier/src/limits.rs (L336-356)
```rust
                if let Some(max) = max_fun
                    && fn_total > max
                {
                    return Err(
                        PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).with_message(format!(
                            "function exceeds generic-instantiation budget: {} > {}",
                            fn_total, max
                        )),
                    );
                }

                if let Some(max) = max_mod
                    && module_total > max
                {
                    return Err(
                        PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).with_message(format!(
                            "module exceeds generic-instantiation budget: {} > {}",
                            module_total, max
                        )),
                    );
                }
```
