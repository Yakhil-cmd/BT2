[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** external-crates/move/crates/move-vm-runtime/src/validation/deserialization/translate.rs (L28-31)
```rust
    let mut modules = BTreeMap::new();
    for (mname, module) in pkg.modules.iter() {
        let module = CompiledModule::deserialize_with_config(module, &vm_config.binary_config)
            .map_err(|err| err.finish(Location::Package(pkg.version_id)))?;
```

**File:** sui-execution/latest/sui-adapter/src/static_programmable_transactions/env.rs (L620-628)
```rust
        let binary_config = self.protocol_config.binary_config(None);
        let deserialized_modules = module_bytes
            .iter()
            .map(|b| {
                CompiledModule::deserialize_with_config(b, &binary_config)
                    .map_err(|e| e.finish(Location::Undefined))
            })
            .collect::<VMResult<Vec<CompiledModule>>>()
            .map_err(|e| self.convert_vm_error(e))?;
```

**File:** sui-execution/v2/sui-adapter/src/programmable_transactions/execution.rs (L812-820)
```rust
        let binary_config = context.protocol_config.binary_config(None);
        let modules = module_bytes
            .iter()
            .map(|b| {
                CompiledModule::deserialize_with_config(b, &binary_config)
                    .map_err(|e| e.finish(Location::Undefined))
            })
            .collect::<VMResult<Vec<CompiledModule>>>()
            .map_err(|e| context.convert_vm_error(e))?;
```

**File:** external-crates/move/crates/move-binary-format/src/deserializer.rs (L37-44)
```rust
    pub fn deserialize_with_config(
        binary: &[u8],
        binary_config: &BinaryConfig,
    ) -> BinaryLoaderResult<Self> {
        let module = deserialize_compiled_module(binary, binary_config)?;
        BoundsChecker::verify_module(&module, binary_config.deprecate_global_storage_ops)?;
        Ok(module)
    }
```

**File:** external-crates/move/crates/move-binary-format/src/unit_tests/deserializer_tests.rs (L524-554)
```rust
#[test]
fn deserialize_deprecated_global_storage() {
    let basic_module = {
        let mut m = basic_test_module();
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(0),
            type_parameters: SignatureIndex(0),
        });
        m
    };
    let test = |bytes: Vec<u8>| {
        // ok with flag false
        CompiledModule::deserialize_with_config(
            &bytes,
            &BinaryConfig::legacy_with_flags(
                /* check_no_extraneous_bytes */ false,
                /* deprecate_global_storage_ops */ false,
            ),
        )
        .unwrap();
        // error with flag true
        let status_code = CompiledModule::deserialize_with_config(
            &bytes,
            &BinaryConfig::legacy_with_flags(
                /* check_no_extraneous_bytes */ false,
                /* deprecate_global_storage_ops */ true,
            ),
        )
        .unwrap_err()
        .major_status();
        assert_eq!(status_code, StatusCode::DEPRECATED_BYTECODE_FORMAT);
```
