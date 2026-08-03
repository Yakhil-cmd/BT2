[1](#0-0)

### Citations

**File:** third_party/move/move-bytecode-verifier/src/instruction_consistency.rs (L101-109)
```rust
                PackClosure(idx, mask) => {
                    self.check_function_op(offset, *idx, /* generic */ false)?;
                    self.check_closure_mask(offset, *idx, *mask)?
                },
                PackClosureGeneric(idx, mask) => {
                    let func_inst = self.resolver.function_instantiation_at(*idx);
                    self.check_function_op(offset, func_inst.handle, /* generic */ true)?;
                    self.check_closure_mask(offset, func_inst.handle, *mask)?
                },
```
