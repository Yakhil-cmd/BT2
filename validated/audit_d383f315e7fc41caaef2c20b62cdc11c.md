[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [1](#0-0)

### Citations

**File:** third_party/move/tools/move-asm/src/disassembler.rs (L37-40)
```rust
pub fn disassemble_script<T: fmt::Write>(out: T, script: &CompiledScript) -> anyhow::Result<T> {
    let script_as_module = script_into_module(script.clone(), "main");
    Disassembler::run(out, &script_as_module, None)
}
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/mod.rs (L80-89)
```rust
                if options.experiment_on(Experiment::ATTACH_COMPILED_MODULE) {
                    let module_name =
                        ModuleName::pseudo_script_name(env.symbol_pool(), script_index);
                    script_index += 1;
                    let module = module_script_conversion::script_into_module(
                        script.clone(),
                        &module_name.name().display(env.symbol_pool()).to_string(),
                    );
                    script_module_data.insert(module_env.get_id(), (module, source_map.clone()));
                }
```

**File:** third_party/move/tools/move-asm/src/module_builder.rs (L427-437)
```rust
    fn is_script(&self) -> bool {
        self.module.borrow().self_module_handle_idx == Self::pseudo_script_module_index()
    }

    fn pseudo_script_module_index() -> ModuleHandleIndex {
        ModuleHandleIndex::new(TableIndex::MAX)
    }

    fn pseudo_script_function_index() -> FunctionHandleIndex {
        FunctionHandleIndex::new(TableIndex::MAX)
    }
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L3509-3515)
```rust
pub struct CompiledModule {
    /// Version number found during deserialization
    pub version: u32,
    /// Handle to self.
    pub self_module_handle_idx: ModuleHandleIndex,
    /// Handles to external dependency modules and self.
    pub module_handles: Vec<ModuleHandle>,
```
