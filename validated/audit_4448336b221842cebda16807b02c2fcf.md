[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L173-199)
```rust
    fn load_resource_mut(
        &mut self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        addr: &AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(&mut GlobalValue, Option<NumBytes>)> {
        let bytes_loaded = if !self.data_cache.contains_resource(addr, ty) {
            let (entry, bytes_loaded) = TransactionDataCache::create_data_cache_entry(
                self.loader,
                &LayoutConverter::new(self.loader),
                gas_meter,
                traversal_context,
                self.loader.unmetered_module_storage(),
                self.resource_resolver,
                addr,
                ty,
            )?;
            self.data_cache.insert_resource(*addr, ty.clone(), entry)?;
            Some(bytes_loaded)
        } else {
            None
        };

        let gv = self.data_cache.get_resource_mut(addr, ty)?;
        Ok((gv, bytes_loaded))
    }
```

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L376-402)
```rust
    /// Returns true if resource has been inserted into the cache. Otherwise, returns false. The
    /// state of the cache does not chang when calling this function.
    fn contains_resource(&self, addr: &AccountAddress, ty: &Type) -> bool {
        self.account_map
            .get(addr)
            .is_some_and(|account_cache| account_cache.contains_key(ty))
    }

    /// Stores a new entry for loaded resource into the data cache. Returns an error if there is an
    /// entry already for the specified address-type pair.
    fn insert_resource(
        &mut self,
        addr: AccountAddress,
        ty: Type,
        data_cache_entry: DataCacheEntry,
    ) -> PartialVMResult<()> {
        match self.account_map.entry(addr).or_default().entry(ty.clone()) {
            Entry::Vacant(entry) => entry.insert(data_cache_entry),
            Entry::Occupied(_) => {
                let msg = format!("Entry for {:?} at {} already exists", ty, addr);
                let err = PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(msg);
                return Err(err);
            },
        };
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L40-65)
```rust
pub static APTOS_TRANSACTION_VALIDATION: Lazy<TransactionValidation> =
    Lazy::new(|| TransactionValidation {
        module_addr: CORE_CODE_ADDRESS,
        module_name: Identifier::new("transaction_validation").unwrap(),
        fee_payer_prologue_name: Identifier::new("fee_payer_script_prologue").unwrap(),
        script_prologue_name: Identifier::new("script_prologue").unwrap(),
        multi_agent_prologue_name: Identifier::new("multi_agent_script_prologue").unwrap(),
        user_epilogue_name: Identifier::new("epilogue").unwrap(),
        user_epilogue_gas_payer_name: Identifier::new("epilogue_gas_payer").unwrap(),
        fee_payer_prologue_extended_name: Identifier::new("fee_payer_script_prologue_extended")
            .unwrap(),
        script_prologue_extended_name: Identifier::new("script_prologue_extended").unwrap(),
        multi_agent_prologue_extended_name: Identifier::new("multi_agent_script_prologue_extended")
            .unwrap(),
        user_epilogue_extended_name: Identifier::new("epilogue_extended").unwrap(),
        user_epilogue_gas_payer_extended_name: Identifier::new("epilogue_gas_payer_extended")
            .unwrap(),
        unified_prologue_name: Identifier::new("unified_prologue").unwrap(),
        unified_prologue_fee_payer_name: Identifier::new("unified_prologue_fee_payer").unwrap(),
        unified_epilogue_name: Identifier::new("unified_epilogue").unwrap(),

        unified_prologue_v2_name: Identifier::new("unified_prologue_v2").unwrap(),
        unified_prologue_fee_payer_v2_name: Identifier::new("unified_prologue_fee_payer_v2")
            .unwrap(),
        unified_epilogue_v2_name: Identifier::new("unified_epilogue_v2").unwrap(),
    });
```
