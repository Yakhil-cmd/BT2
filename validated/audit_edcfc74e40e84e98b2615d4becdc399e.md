## Finding: Legacy `private_generics` verifier (v1) omits the `std::internal::permit` check that v2 enforces [1](#0-0) 

### Summary

`sui_verify_module_metered` dispatches to one of two mutually-exclusive verifier implementations based on the `private_generics_verifier_v2` protocol flag: the legacy `private_generics::verify_module` when the flag is `false`, or `private_generics_verifier_v2::verify_module` when `true`. [2](#0-1) 

These two implementations are **not equivalent**. The legacy verifier only inspects calls into `sui::transfer`, `sui::event`, and `sui::coin_registry`, checking that "internal" type parameters resolve to types defined in the caller's own module. [3](#0-2) 

The v2 verifier's `FUNCTIONS_TO_CHECK` table additionally guards `std::internal::permit`, marking its sole type parameter as "internal" (must be defined in the caller's module). [4](#0-3) 

`std::internal::Permit<T>` is documented as "A privileged witness of the `T` type. Instances can only be created by the module that defines the type `T`" — a capability primitive intended for other framework/user modules (e.g. `sui::scratch::permit<K>`) to gate privileged, type-keyed operations. [5](#0-4) 

### Finding Description

The *source-level* Move compiler does enforce this restriction (`check_internal_permit` in `move-compiler/src/sui_mode/typing.rs`), rejecting `internal::permit<T>()` calls where `T` is not declared in the current module. [6](#0-5) 

However, package publication on Sui accepts pre-compiled bytecode directly — the compiler's typing pass is not itself a trust boundary; the bytecode verifier (`sui_verify_module_metered`, run during publish) is the actual enforcement point for hand-crafted or non-standard-toolchain bytecode. When `private_generics_verifier_v2` is `false` (this is the compiled-in default in `VerifierConfig::default()` and in every `production_config()` used by the legacy execution versions v0–v3), the legacy `private_generics::verify_module` runs instead of v2, and it has no knowledge of `std::internal::INTERNAL_MODULE`/`permit` at all — it only special-cases `TRANSFER_MODULE`, `EVENT_MODULE`, `COIN_REGISTRY_MODULE`. [7](#0-6) [8](#0-7) 

An attacker who publishes hand-crafted bytecode (skipping the reference compiler) containing a `CallGeneric` to `std::internal::permit<VictimType>()`, where `VictimType` is a datatype defined in a completely different (victim) module, will pass the legacy verifier unmodified, producing a forged `std::internal::Permit<VictimType>` value at runtime — a value the framework's own doc-comment states "can only be created by the module that defines the type."

### Impact Explanation

Any current or future framework/user code that treats possession of `Permit<T>` as proof of authorization over type `T` (the documented use case, exemplified by `sui::scratch::permit<K>` → `sui::scratch::add`) can be tricked into granting the attacker privileged, type-keyed access/state-mutation rights they should not have. This maps directly onto the bounty's "capability, protected-object, or restricted-call invariant bypass" class, since the entire security property of the `Permit<T>` witness is defeated when the runtime verifier omits the check that the compiler enforces only for well-behaved toolchains.

### Likelihood Explanation

This is reachable purely through a public, unprivileged package-publish transaction with attacker-authored bytecode — no validator, admin, or governance trust is required. The actual severity is gated on two facts I could not fully confirm from static inspection alone:
1. Whether `private_generics_verifier_v2` is actually `false` (legacy path active) at the current live mainnet protocol version, versus already flipped to `true` in a protocol-config version update (I found the flag's declaration and default but not the specific per-version activation history entries in `crates/sui-protocol-config/src/lib.rs`).
2. Whether any framework module beyond the example `sui::scratch` (whose maturity/deployment status is unclear) currently relies on `Permit<T>` for a security-critical guard on mainnet.

If the flag is still `false` in production and `Permit<T>`-gated framework code is live, this is a genuine High-severity capability-forgery bug; if v2 is already the active path, or no live consumer trusts `Permit<T>`, the practical impact is currently null even though the code path exists.

### Recommendation
- Confirm the live-mainnet value of `private_generics_verifier_v2` and, if `false`, either enable v2 or backport the `std::internal::permit` check into the legacy `private_generics.rs` path so both verifier implementations enforce identical rules.
- Audit all framework/user modules for reliance on `std::internal::Permit<T>` as a security witness and ensure the check is active for any protocol version that ships such consumers.

### Proof of Concept
1. Hand-author (or programmatically emit via `move-binary-format`) a module `attacker::exploit` containing a public function with a `CallGeneric` instruction invoking `std::internal::permit<victim::mod::VictimType>()`, bypassing the Move source compiler's `check_internal_permit` diagnostic.
2. Run `sui_verify_module_metered` with a `VerifierConfig { private_generics_verifier_v2: false, .. }` (the default) — verification succeeds.
3. Run the same module with `private_generics_verifier_v2: true` — verification fails with the "Type argument #0 must be a type defined in the current module" error from `verify_call` in `private_generics_verifier_v2.rs`. [9](#0-8) 

This demonstrates the concrete divergence: the same malicious bytecode is accepted under the legacy (default) verifier and rejected only under v2, confirming the invariant-bypass exists whenever the legacy path is active.

### Citations

**File:** sui-execution/latest/sui-verifier/src/verifier.rs (L19-35)
```rust
pub fn sui_verify_module_metered(
    module: &CompiledModule,
    fn_info_map: &FnInfoMap,
    meter: &mut (impl Meter + ?Sized),
    verifier_config: &VerifierConfig,
) -> Result<(), ExecutionError> {
    struct_with_key_verifier::verify_module(module)?;
    global_storage_access_verifier::verify_module(module)?;
    id_leak_verifier::verify_module(module, meter)?;
    if verifier_config.private_generics_verifier_v2 {
        private_generics_verifier_v2::verify_module(module, verifier_config)?;
    } else {
        private_generics::verify_module(module, verifier_config)?;
    }
    entry_points_verifier::verify_module(module, fn_info_map, verifier_config)?;
    tx_context_restrictions_verifier::verify_module(module, verifier_config)?;
    one_time_witness_verifier::verify_module(module, fn_info_map)
```

**File:** sui-execution/latest/sui-verifier/src/private_generics.rs (L90-112)
```rust
    for instr in &code.code {
        if let Bytecode::CallGeneric(finst_idx) = instr {
            let FunctionInstantiation {
                handle,
                type_parameters,
            } = view.function_instantiation_at(*finst_idx);

            let fhandle = view.function_handle_at(*handle);
            let mhandle = view.module_handle_at(fhandle.module);

            let type_arguments = &view.signature_at(*type_parameters).0;
            let ident = addr_module(view, mhandle);
            if ident == (SUI_FRAMEWORK_ADDRESS, TRANSFER_MODULE) {
                verify_private_transfer(view, fhandle, type_arguments, allow_receiving_object_id)?
            } else if ident == (SUI_FRAMEWORK_ADDRESS, EVENT_MODULE) {
                verify_private_event_emit(view, fhandle, type_arguments)?
            } else if ident == (SUI_FRAMEWORK_ADDRESS, COIN_REGISTRY_MODULE) {
                verify_dynamic_coin_creation(view, fhandle, type_arguments)?
            }
        }
    }
    Ok(())
}
```

**File:** sui-execution/latest/sui-verifier/src/private_generics_verifier_v2.rs (L120-145)
```rust
// A list of all functions to check for internal rules. A boolean for each type parameter indicates
// if the type parameter is `internal`
pub const FUNCTIONS_TO_CHECK: &[(FunctionIdent, &[/* is internal */ bool])] = &[
    // stdlib functions
    (MOVE_STDLIB_INTERNAL_PERMIT, &[true]),
    // event functions
    (SUI_EVENT_EMIT_EVENT, &[true]),
    (SUI_EVENT_EMIT_AUTHENTICATED, &[true]),
    (SUI_EVENT_NUM_EVENTS, &[]),
    (SUI_EVENT_EVENTS_BY_TYPE, &[false]),
    // public transfer functions
    (SUI_TRANSFER_PUBLIC_TRANSFER, &[false]),
    (SUI_TRANSFER_PUBLIC_FREEZE_OBJECT, &[false]),
    (SUI_TRANSFER_PUBLIC_SHARE_OBJECT, &[false]),
    (SUI_TRANSFER_PUBLIC_RECEIVE, &[false]),
    (SUI_TRANSFER_RECEIVING_OBJECT_ID, &[false]),
    (SUI_TRANSFER_PUBLIC_PARTY_TRANSFER, &[false]),
    // private transfer functions
    (SUI_TRANSFER_TRANSFER, &[true]),
    (SUI_TRANSFER_FREEZE_OBJECT, &[true]),
    (SUI_TRANSFER_SHARE_OBJECT, &[true]),
    (SUI_TRANSFER_RECEIVE, &[true]),
    (SUI_TRANSFER_PARTY_TRANSFER, &[true]),
    // coin registry functions
    (SUI_COIN_REGISTRY_NEW_CURRENCY, &[true]),
];
```

**File:** sui-execution/latest/sui-verifier/src/private_generics_verifier_v2.rs (L259-273)
```rust
    for (idx, (ty_arg, &is_internal)) in ty_args.iter().zip_debug_eq(internal_flags).enumerate() {
        if !is_internal {
            continue;
        }
        if !is_defined_in_current_module(module, ty_arg) {
            let callee_package_name = callee_package_name(&callee_addr);
            let help = help_message(&callee_addr, callee_module, callee_function);
            return Err(Error::User(format!(
                "Invalid call to '{callee_package_name}::{callee_module}::{callee_function}'. \
                Type argument #{idx} must be a type defined in the current module, found '{}'.\
                {help}",
                format_signature_token(module, ty_arg),
            )));
        }
    }
```

**File:** crates/sui-framework/packages/move-stdlib/sources/internal.move (L30-38)
```text
module std::internal;

/// A privileged witness of the `T` type.
/// Instances can only be created by the module that defines the type `T`.
public struct Permit<phantom T>() has drop;

/// Construct a new `Permit` for the type `T`.
/// Can only be called by the module that defines the type `T`.
public fun permit<T>(): Permit<T> { Permit() }
```

**File:** external-crates/move/crates/move-compiler/src/sui_mode/typing.rs (L883-921)
```rust
fn check_internal_permit(context: &mut Context, loc: Loc, mcall: &ModuleCall) {
    let ModuleCall {
        module,
        name,
        type_arguments,
        ..
    } = mcall;
    let current_module = context.current_module();
    let Some(first_ty) = type_arguments.first() else {
        // invalid arity
        debug_assert!(false, "ICE arity should have been expanded for errors");
        return;
    };
    let (in_current_module, first_ty_tn) = match first_ty.value.type_name() {
        Some(sp!(_, TypeName_::Multiple(_))) | Some(sp!(_, TypeName_::Builtin(_))) | None => {
            (false, None)
        }
        Some(sp!(_, TypeName_::ModuleType(m, n))) => (m.as_ref() == current_module, Some((m, n))),
    };
    if !in_current_module {
        let mut msg = format!(
            "Invalid call to an internal function. \
            The function '{}::{}' is restricted to being called in the module that defines the type",
            module, name,
        );
        if let Some((first_ty_module, _)) = &first_ty_tn {
            msg = format!("{}, '{}'", msg, first_ty_module);
        };
        let ty_msg = format!(
            "The type {} is not declared in the current module",
            error_format(first_ty, &Subst::empty()),
        );
        let diag = diag!(
            INTERNAL_PERMIT_CALL_DIAG,
            (loc, msg),
            (first_ty.loc, ty_msg)
        );
        context.add_diag(diag)
    }
```

**File:** external-crates/move/crates/move-vm-config/src/verifier.rs (L94-97)
```rust
            additional_borrow_checks: true,
            better_loader_errors: true,
            private_generics_verifier_v2: false,
            sanity_check_with_regex_reference_safety: Some(8_000_000),
```
