[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** external-crates/move/crates/move-binary-format/src/check_bounds.rs (L201-226)
```rust
    fn check_function_handle(&self, function_handle: &FunctionHandle) -> PartialVMResult<()> {
        check_bounds_impl(self.module.module_handles(), function_handle.module)?;
        check_bounds_impl(self.module.identifiers(), function_handle.name)?;
        check_bounds_impl(self.module.signatures(), function_handle.parameters)?;
        check_bounds_impl(self.module.signatures(), function_handle.return_)?;
        // function signature type paramters must be in bounds to the function type parameters
        let type_param_count = function_handle.type_parameters.len();
        if let Some(sig) = self
            .module
            .signatures()
            .get(function_handle.parameters.into_index())
        {
            for ty in &sig.0 {
                self.check_type_parameter(ty, type_param_count)?
            }
        }
        if let Some(sig) = self
            .module
            .signatures()
            .get(function_handle.return_.into_index())
        {
            for ty in &sig.0 {
                self.check_type_parameter(ty, type_param_count)?
            }
        }
        Ok(())
```

**File:** external-crates/move/crates/move-binary-format/src/check_bounds.rs (L502-520)
```rust
                CallGeneric(idx) => {
                    self.check_code_unit_bounds_impl(
                        self.module.function_instantiations(),
                        *idx,
                        bytecode_offset,
                    )?;
                    // check type parameters in call are bound to the function type parameters
                    if let Some(func_inst) =
                        self.module.function_instantiations().get(idx.into_index())
                        && let Some(sig) = self
                            .module
                            .signatures()
                            .get(func_inst.type_parameters.into_index())
                    {
                        for ty in &sig.0 {
                            self.check_type_parameter(ty, type_param_count)?
                        }
                    }
                }
```

**File:** external-crates/move/crates/move-binary-format/src/check_bounds.rs (L609-628)
```rust
                // Instructions that refer to a signature
                VecPack(idx, _)
                | VecLen(idx)
                | VecImmBorrow(idx)
                | VecMutBorrow(idx)
                | VecPushBack(idx)
                | VecPopBack(idx)
                | VecUnpack(idx, _)
                | VecSwap(idx) => {
                    self.check_code_unit_bounds_impl(
                        self.module.signatures(),
                        *idx,
                        bytecode_offset,
                    )?;
                    if let Some(sig) = self.module.signatures().get(idx.into_index()) {
                        for ty in &sig.0 {
                            self.check_type_parameter(ty, type_param_count)?;
                        }
                    }
                }
```

**File:** external-crates/move/crates/move-binary-format/src/check_bounds.rs (L752-789)
```rust
    fn check_type_parameter(
        &self,
        ty: &SignatureToken,
        type_param_count: usize,
    ) -> PartialVMResult<()> {
        use self::SignatureToken::*;

        for ty in ty.preorder_traversal() {
            match ty {
                SignatureToken::TypeParameter(idx) => {
                    if *idx as usize >= type_param_count {
                        return Err(bounds_error(
                            StatusCode::INDEX_OUT_OF_BOUNDS,
                            IndexKind::TypeParameter,
                            *idx,
                            type_param_count,
                        ));
                    }
                }

                Bool
                | U8
                | U16
                | U32
                | U64
                | U128
                | U256
                | Address
                | Signer
                | Datatype(_)
                | Reference(_)
                | MutableReference(_)
                | Vector(_)
                | DatatypeInstantiation(_) => (),
            }
        }
        Ok(())
    }
```

**File:** external-crates/move/crates/bytecode-verifier-tests/src/unit_tests/bounds_tests.rs (L42-56)
```rust
#[test]
fn invalid_type_param_in_fn_return_() {
    use SignatureToken::*;

    let mut m = basic_test_module();
    m.function_handles[0].return_ = SignatureIndex(1);
    m.signatures.push(Signature(vec![TypeParameter(0)]));
    assert_eq!(m.signatures.len(), 2);
    assert_eq!(
        BoundsChecker::verify_module(&m, /* deprecate_global_storage_ops */ true)
            .unwrap_err()
            .major_status(),
        StatusCode::INDEX_OUT_OF_BOUNDS
    );
}
```
