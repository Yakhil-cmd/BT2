No vulnerability found for this question.

**Analysis:** The premise of the question is incorrect, and even if it were correct, it would fall outside the transaction-admission boundary conditions.

The bytecode verifier's `CodeUnitVerifier::verify_module_impl` iterates over **all** function definitions in a module unconditionally, calling `Self::verify_function` (which runs reference-safety/borrow-graph analysis) for every entry in `module.function_defs()` regardless of `visibility` or `is_entry`: [1](#0-0) 

There is no branch that skips or weakens reference analysis for `Public`/`is_entry: false` functions versus entry functions — the loop applies identical rigor to every function definition. The regression tests cited in the question (`unbalanced_stack_crash`, `borrow_graph`) actually demonstrate this: both use `visibility: Visibility::Public, is_entry: false` functions specifically to confirm that `crate::verify_module` still catches dangling-reference/borrow-graph issues (`GLOBAL_REFERENCE_ERROR`) or correctly accepts safe code, proving the invariant holds rather than being violated: [2](#0-1) [3](#0-2) 

The only place `is_entry`/`Visibility` gates a check is in the separate, narrower `script_signature::verify_module` pass, which additionally enforces script-callable signature constraints on entry functions — it does not gate or replace the core reference-safety pass: [4](#0-3) 

Additionally, this is module-publishing bytecode verification, not a transaction-admission path governing sender/signer/sequence/chain-id/replay/domain binding, so per the review's boundary conditions it would be out of scope even if the described bypass existed.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L69-95)
```rust
        let mut total_back_edges = 0;
        for (idx, function_definition) in module.function_defs().iter().enumerate() {
            let index = FunctionDefinitionIndex(idx as TableIndex);

            // SECURITY: Check struct API attributes BEFORE verify_function runs.
            // This ensures that reference_safety (which runs inside verify_function) can
            // safely trust BorrowFieldMutable attributes, since they've been validated
            // to accurately match the bytecode before reference_safety sees them.
            // Only runs for VERSION_10+ modules (see guard above).
            if let Some(ctx) = &struct_api_ctx {
                struct_api_checker::check_function(module, function_definition, ctx)
                    .map_err(|err| err.at_index(IndexKind::FunctionDefinition, index.0))?;
            }

            // Now reference_safety can safely trust that BorrowFieldMutable attributes
            // accurately describe which field is being borrowed
            let num_back_edges = Self::verify_function(
                verifier_config,
                index,
                function_definition,
                module,
                &name_def_map,
                &mut meter,
            )
            .map_err(|err| err.at_index(IndexKind::FunctionDefinition, index.0))?;
            total_back_edges += num_back_edges;
        }
```

**File:** third_party/move/move-bytecode-verifier/src/regression_tests/reference_analysis.rs (L100-112)
```rust
    let fun_def = FunctionDefinition {
        code: Some(code_unit),
        function: FunctionHandleIndex(0),
        visibility: Visibility::Public,
        is_entry: false,
        acquires_global_resources: vec![],
    };

    module.function_defs.push(fun_def);
    match crate::verify_module(&module) {
        Ok(_) => {},
        Err(e) => assert_eq!(e.major_status(), StatusCode::GLOBAL_REFERENCE_ERROR),
    }
```

**File:** third_party/move/move-bytecode-verifier/src/regression_tests/reference_analysis.rs (L210-227)
```rust
        function_defs: vec![FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![MoveLoc(0), MoveLoc(1), StLoc(0), StLoc(1), Branch(0)],
            }),
        }],
        struct_variant_handles: vec![],
        struct_variant_instantiations: vec![],
        variant_field_handles: vec![],
        variant_field_instantiations: vec![],
    };

    let res = crate::verify_module(&module);
    assert!(res.is_ok());
```

**File:** third_party/move/move-bytecode-verifier/src/script_signature.rs (L52-74)
```rust
pub fn verify_module(
    module: &CompiledModule,
    check_signature: FnCheckScriptSignature,
) -> VMResult<()> {
    // important for not breaking old modules
    if module.version < VERSION_5 {
        return Ok(());
    }

    for (idx, _fdef) in module
        .function_defs()
        .iter()
        .enumerate()
        .filter(|(_idx, fdef)| fdef.is_entry)
    {
        verify_module_function_signature(
            module,
            FunctionDefinitionIndex(idx as TableIndex),
            check_signature,
        )?
    }
    Ok(())
}
```
