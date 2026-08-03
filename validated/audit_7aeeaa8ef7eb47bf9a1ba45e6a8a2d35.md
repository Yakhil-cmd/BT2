[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L173-204)
```rust
fn native_constant_serialized_size(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    _args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.len() == 1);

    context.charge(BCS_CONSTANT_SERIALIZED_SIZE_BASE)?;

    let ty = &ty_args[0];
    let ty_layout = context.type_to_type_layout(ty)?;

    let use_local_struct_cache =
        context.timed_feature_enabled(TimedFeatureFlag::ConstantSerializedSizeLocalCache);
    let (visited_count, serialized_size_result) =
        constant_serialized_size(&ty_layout, use_local_struct_cache);
    context
        .charge(BCS_CONSTANT_SERIALIZED_SIZE_PER_TYPE_NODE * NumTypeNodes::new(visited_count))?;

    let enum_option_enabled = context.get_feature_flags().is_enum_option_enabled();
    let result = match serialized_size_result {
        Ok(value) => create_option_u64(enum_option_enabled, value.map(|v| v as u64)),
        Err(_) => {
            context.charge(BCS_SERIALIZED_SIZE_FAILURE)?;

            // Re-use the same abort code as bcs::to_bytes.
            return Err(SafeNativeError::abort(NFE_BCS_SERIALIZATION_FAILURE));
        },
    };

    Ok(smallvec![result])
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/move_stdlib.rs (L47-48)
```rust
        [bcs_constant_serialized_size_base: InternalGas, { RELEASE_V1_24.. => "bcs.constant_serialized_size.base" }, 7350],
        [bcs_constant_serialized_size_per_type_node: InternalGasPerTypeNode, { RELEASE_V1_24.. => "bcs.constant_serialized_size.per_type_node" }, 400],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L32-46)
```rust
        impl $crate::traits::FromOnChainGasSchedule for $params_name {
            #[allow(unused)]
            fn from_on_chain_gas_schedule(gas_schedule: &std::collections::BTreeMap<String, u64>, feature_version: u64) -> Result<Self, String> {
                let mut params = $params_name::zeros();

                $(
                    if let Some(key) = $crate::gas_schedule::macros::define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
                        let name = format!("{}.{}", $prefix, key);
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
                    }
                )*

                Ok(params)
            }
        }
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L89-108)
```rust
pub const LATEST_GAS_FEATURE_VERSION: u64 = gas_feature_versions::RELEASE_V1_50;

pub mod gas_feature_versions {
    pub const RELEASE_V1_8: u64 = 11;
    pub const RELEASE_V1_9_SKIPPED: u64 = 12;
    pub const RELEASE_V1_9: u64 = 13;
    pub const RELEASE_V1_10: u64 = 15;
    pub const RELEASE_V1_11: u64 = 16;
    pub const RELEASE_V1_12: u64 = 17;
    pub const RELEASE_V1_13: u64 = 18;
    pub const RELEASE_V1_14: u64 = 19;
    pub const RELEASE_V1_15: u64 = 20;
    pub const RELEASE_V1_16: u64 = 21;
    pub const RELEASE_V1_18: u64 = 22;
    pub const RELEASE_V1_19: u64 = 23;
    pub const RELEASE_V1_20: u64 = 24;
    pub const RELEASE_V1_21: u64 = 25;
    pub const RELEASE_V1_22: u64 = 26;
    pub const RELEASE_V1_23: u64 = 27;
    pub const RELEASE_V1_24: u64 = 28;
```
