[1](#0-0)

### Citations

**File:** aptos-move/framework/natives/src/util.rs (L38-55)
```rust
    // TODO(Gas): charge for getting the layout
    let layout = context.type_to_type_layout(&ty_args[0])?;

    let bytes = safely_pop_arg!(args, Vec<u8>);
    context.charge(
        UTIL_FROM_BYTES_BASE + UTIL_FROM_BYTES_PER_BYTE * NumBytes::new(bytes.len() as u64),
    )?;

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    let val = match ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .deserialize(&bytes, &layout)
    {
        Some(val) => val,
        None => return Err(SafeNativeError::abort(EFROM_BYTES)),
    };
```
