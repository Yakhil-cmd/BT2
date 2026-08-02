[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** aptos-move/framework/natives/src/function_info.rs (L220-237)
```rust
fn native_load_function_impl(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(arguments.len() == 1);

    context.charge(FUNCTION_INFO_LOAD_FUNCTION_BASE)?;
    let (module_name, _) = extract_function_info(&mut arguments)?;

    if context.has_direct_gas_meter_access_in_native_context() {
        context.charge_gas_for_dependencies(module_name)?;
        Ok(smallvec![])
    } else {
        // Legacy flow, VM will charge gas for module loading.
        Err(SafeNativeError::LoadModule { module_name })
    }
}
```

**File:** third_party/move/move-vm/runtime/src/module_traversal.rs (L25-32)
```rust
pub struct TraversalContext<'a> {
    visited: BTreeMap<(&'a AccountAddress, &'a IdentStr), ()>,

    pub referenced_scripts: &'a Arena<Arc<CompiledScript>>,
    pub referenced_modules: &'a Arena<Arc<CompiledModule>>,
    pub referenced_module_ids: &'a Arena<ModuleId>,
    pub referenced_module_bundles: &'a Arena<Vec<CompiledModule>>,
}
```

**File:** third_party/move/move-vm/runtime/src/module_traversal.rs (L58-87)
```rust
    /// If the specified address is not special, adds the address-name pair to the visited set.
    /// If the address is special, or if the set already contains the pair, returns false. Returns
    /// true otherwise.
    pub fn visit_if_not_special_address(
        &mut self,
        addr: &'a AccountAddress,
        name: &'a IdentStr,
    ) -> bool {
        !addr.is_special() && self.visited.insert((addr, name), ()).is_none()
    }

    /// If the address of the specified module id is not special, adds the address-name pair to the
    /// visited set and returns true. If the address is special, or if the set already contains the
    /// pair, returns false.
    pub fn visit_if_not_special_module_id(&mut self, module_id: &ModuleId) -> bool {
        let addr = module_id.address();
        if addr.is_special() {
            return false;
        }

        let name = module_id.name();
        if self.visited.contains_key(&(addr, name)) {
            false
        } else {
            let module_id = self.referenced_module_ids.alloc(module_id.clone());
            self.visited
                .insert((module_id.address(), module_id.name()), ());
            true
        }
    }
```
