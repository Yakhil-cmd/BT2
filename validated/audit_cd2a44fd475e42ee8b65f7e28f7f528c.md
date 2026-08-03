No vulnerability found for this question.

**Rationale:**

The exploit premise requires a downstream lookup that (a) accepts a `function_name` string different from `VERSIONED_PROLOGUE_NAME`/`VERSIONED_EPILOGUE_NAME` yet is treated as equal, and (b) is influenced by unprivileged transaction input. Neither condition holds in this codebase:

1. **The prologue/epilogue name is never derived from user input.** `VERSIONED_PROLOGUE_NAME` and `VERSIONED_EPILOGUE_NAME` are compile-time `&'static IdentStr` constants built by the `ident_str!` macro, and `run_prologue`/epilogue execution calls `execute_function_bypass_visibility` with these hardcoded constants directly: [1](#0-0) [2](#0-1) . Selection among prologue/epilogue variants (`unified_prologue` vs `unified_prologue_v2`, etc.) is decided purely by internal feature flags like `features.is_transaction_payload_v2_enabled()`, never by any attacker-supplied string: [3](#0-2) .

2. **`Identifier`/`IdentStr` equality is exact, not fuzzy.** `Identifier::is_valid` validates the *entire* byte string (via `all_bytes_valid` over the whole remaining slice), so it cannot accept a string that differs from a target identifier by "validator-invisible" trailing characters while still comparing equal to it — any extra valid characters produce a genuinely different (longer) string, and `Identifier`/`IdentStr` derive standard `PartialEq` over the underlying bytes: [4](#0-3) [5](#0-4) . The `<SELF>_[0-9]+` exception only applies to script "self" module names, unrelated to prologue/epilogue names.

3. **User-supplied entry function names never reach the prologue/epilogue dispatch path.** For ordinary entry-function transactions, the target function is resolved via `loader.load_instantiated_function(...)` against the actual compiled module's function table using exact `IdentStr` lookup, and execution requires `function.is_entry_or_err()`: [6](#0-5) [7](#0-6) . `versioned_prologue`/`versioned_epilogue` are private functions in `transaction_validation.move`, invoked only by the VM adapter via `execute_function_bypass_visibility` with hardcoded constants — they are not reachable through user-supplied `function_name` strings in a transaction payload at all.

Since no code path exists where an attacker-controlled `function_name` string is compared against `VERSIONED_PROLOGUE_NAME`/`VERSIONED_EPILOGUE_NAME` (or any transaction-validation function name) using anything other than exact identifier equality, and since the prologue/epilogue selection is fully internal to the VM, the described exploit path does not correspond to real code.

### Citations

**File:** aptos-move/aptos-vm/src/system_module_names.rs (L92-93)
```rust
pub const VERSIONED_PROLOGUE_NAME: &IdentStr = ident_str!("versioned_prologue");
pub const VERSIONED_EPILOGUE_NAME: &IdentStr = ident_str!("versioned_epilogue");
```

**File:** aptos-move/aptos-vm/src/transaction_validation_versioned.rs (L133-146)
```rust
    session
        .execute_function_bypass_visibility(
            &TRANSACTION_VALIDATION_MODULE,
            VERSIONED_PROLOGUE_NAME,
            vec![],
            vec![sender, fee_payer, args],
            &mut UnmeteredGasMeter,
            traversal_context,
            module_storage,
        )
        .map(|_return_vals| ())
        .map_err(expect_no_verification_errors)
        .or_else(|err| convert_prologue_error(err, log_context))
}
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L209-217)
```rust
            (
                if features.is_transaction_payload_v2_enabled() {
                    &APTOS_TRANSACTION_VALIDATION.unified_prologue_fee_payer_v2_name
                } else {
                    &APTOS_TRANSACTION_VALIDATION.unified_prologue_fee_payer_name
                },
                serialized_args,
            )
        } else {
```

**File:** third_party/move/move-core/types/src/identifier.rs (L83-95)
```rust
pub const fn is_valid(s: &str) -> bool {
    // Rust const fn's don't currently support slicing or indexing &str's, so we
    // have to operate on the underlying byte slice. This is not a problem as
    // valid identifiers are (currently) ASCII-only.
    let b = s.as_bytes();
    match b {
        b"<SELF>" => true,
        [b'<', b'S', b'E', b'L', b'F', b'>', b'_', ..] if b.len() > 7 => all_bytes_numeric(b, 7),
        [b'a'..=b'z', ..] | [b'A'..=b'Z', ..] => all_bytes_valid(b, 1),
        [b'_', ..] | [b'$', ..] if b.len() > 1 => all_bytes_valid(b, 1),
        _ => false,
    }
}
```

**File:** third_party/move/move-core/types/src/identifier.rs (L173-184)
```rust
impl FromStr for Identifier {
    type Err = anyhow::Error;

    fn from_str(data: &str) -> Result<Self> {
        Self::new(data)
    }
}

impl From<&IdentStr> for Identifier {
    fn from(ident_str: &IdentStr) -> Self {
        ident_str.to_owned()
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1036-1043)
```rust
            let function = loader.load_instantiated_function(
                &legacy_loader_config,
                gas_meter,
                traversal_context,
                entry_fn.module(),
                entry_fn.function(),
                entry_fn.ty_args(),
            )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1080-1081)
```rust
            // Execute the function. The function also must be an entry function!
            function.is_entry_or_err()?;
```
