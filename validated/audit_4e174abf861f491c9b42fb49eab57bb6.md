### Title
Precompile System Hooks Do Not Revert on Non-Zero `nominal_token_value`, Permanently Locking Native ETH - (File: `system_hooks/src/call_hooks/precompiles.rs`)

---

### Summary

`pure_system_function_hook_impl`, the generic handler for all EVM precompile system hooks (ecrecover, sha256, ripemd-160, identity, modexp, ecadd, ecmul, ecpairing, P256), silently ignores `nominal_token_value` in the incoming `ExternalCallRequest`. Every other system hook in the codebase explicitly reverts when called with non-zero value. Because the precompile hook succeeds without reverting, any ETH sent to a precompile address is committed to that address's balance and permanently locked, since system hook addresses have no withdrawal mechanism.

---

### Finding Description

In `pure_system_function_hook_impl`, the `ExternalCallRequest` is destructured using `..`, which silently discards `nominal_token_value`:

```rust
let ExternalCallRequest {
    available_resources,
    input: calldata,
    modifier,
    ..          // nominal_token_value is silently dropped here
} = request;
``` [1](#0-0) 

Every other system call hook in the codebase performs an explicit zero-value guard before proceeding:

- `l1_messenger_hook`: `error |= nominal_token_value != U256::ZERO;` [2](#0-1) 

- `mint_base_token_hook`: `error |= nominal_token_value != U256::ZERO;` [3](#0-2) 

- `set_bytecode_on_address_hook`: `let mut error = nominal_token_value != U256::ZERO;` [4](#0-3) 

- `contract_deployer_temp_hook`: `let mut error = nominal_token_value != U256::ZERO;` [5](#0-4) 

The precompile hook is the sole exception. When the hook returns success, the EVM interpreter commits the value transfer to the precompile address. Precompile addresses (`0x0001`–`0x000a`, `0x100`, etc.) are registered as system hooks with no deployed bytecode and no withdrawal function, so any ETH credited to them is irrecoverable.

The nine precompile hooks registered via `add_precompiles` and `add_precompile_ext` all route through `pure_system_function_hook_impl`: [6](#0-5) 

---

### Impact Explanation

Any ETH sent to a precompile address (e.g., `0x0001` for ecrecover) is transferred by the EVM interpreter before the hook executes. Because the hook succeeds without reverting, the transfer is committed. The precompile address has no code and no withdrawal path, so the ETH is permanently frozen. This is a direct, irreversible user-fund loss reachable by any unprivileged transaction sender.

---

### Likelihood Explanation

Medium. A user or contract that calls ecrecover (or any other precompile) for signature verification while also forwarding ETH — a common pattern in payable contract flows — will silently lose the forwarded ETH. The mistake is easy to make and the protocol provides no protection against it, unlike every other system hook which reverts defensively.

---

### Recommendation

Add the same zero-value guard used by all other system hooks inside `pure_system_function_hook_impl`, before any execution proceeds:

```rust
let ExternalCallRequest {
    available_resources,
    input: calldata,
    modifier,
    nominal_token_value,   // extract instead of ignoring
    ..
} = request;

if nominal_token_value != U256::ZERO {
    return Ok((make_error_return_state(available_resources), return_memory));
}
``` [7](#0-6) 

---

### Proof of Concept

1. A user constructs a transaction calling `ecrecover` at address `0x0001` with `msg.value = 1 ETH` and valid ecrecover calldata.
2. The EVM interpreter deducts 1 ETH from the caller's balance and credits it to `0x0001` before dispatching to the hook.
3. `pure_system_function_hook_impl` is invoked; it ignores `nominal_token_value` and executes the ecrecover computation normally.
4. The hook returns `CallResult::Successful`, so the EVM interpreter commits the value transfer.
5. 1 ETH now resides at address `0x0001`, which is a system hook address with no bytecode and no withdrawal function.
6. The ETH is permanently locked and unrecoverable.

### Citations

**File:** system_hooks/src/call_hooks/precompiles.rs (L40-103)
```rust
pub fn pure_system_function_hook_impl<'a, F, E, S>(
    request: ExternalCallRequest<S>,
    _caller_ee: u8,
    system: &mut System<S>,
    return_memory: &'a mut [MaybeUninit<u8>],
) -> Result<(CompletedExecution<'a, S>, &'a mut [MaybeUninit<u8>]), SystemError>
where
    F: SystemFunctionInvocation<S, E>,
    S: EthereumLikeTypes,
    S::IO: IOSubsystemExt,
    E: Subsystem,
{
    let ExternalCallRequest {
        available_resources,
        input: calldata,
        modifier,
        ..
    } = request;

    // We allow static calls as we are "pure" hook
    if modifier == CallModifier::Constructor {
        return Err(internal_error!("precompile called with constructor modifier").into());
    }

    let mut resources = available_resources;

    let allocator = system.get_allocator();

    let mut return_vec = SliceVec::new(return_memory);
    let mut logger = system.get_logger();
    let result = F::invoke(
        system.io.oracle(),
        &mut logger,
        &calldata,
        &mut return_vec,
        &mut resources,
        allocator,
    );

    match result {
        Ok(()) => {
            let (returndata, rest) = return_vec.destruct();
            Ok((
                make_return_state_from_returndata_region(resources, returndata),
                rest,
            ))
        }
        Err(e) => match e.root_cause() {
            // Following EVM precompiles, we burn all gas on out-of-gas or invalid inputs
            RootCause::Runtime(RuntimeError::OutOfErgs(_)) | RootCause::Usage(_) => {
                system_log!(system, "Out of gas during system hook\nError:{e:?}");
                resources.exhaust_ergs();
                let (_, rest) = return_vec.destruct();
                Ok((make_error_return_state(resources), rest))
            }
            // Internal error means something is fatally wrong inside the hook, so we propagate it
            RootCause::Internal(e) => Err(e.clone_or_copy().into()),
            // On fatal runtime error (e.g., out of return memory or native resources) we also propagate the error
            RootCause::Runtime(e @ RuntimeError::FatalRuntimeError(_)) => {
                Err(e.clone_or_copy().into())
            }
        },
    }
}
```

**File:** system_hooks/src/call_hooks/l1_messenger.rs (L61-62)
```rust
    // This hook doesn't accept any native token value
    error |= nominal_token_value != U256::ZERO;
```

**File:** system_hooks/src/call_hooks/mint_base_token.rs (L49-50)
```rust
    // This hook doesn't accept any native token value
    error |= nominal_token_value != U256::ZERO;
```

**File:** system_hooks/src/call_hooks/set_bytecode_on_address.rs (L56-56)
```rust
    let mut error = nominal_token_value != U256::ZERO;
```

**File:** system_hooks/src/call_hooks/contract_deployer_temp.rs (L52-52)
```rust
    let mut error = nominal_token_value != U256::ZERO;
```

**File:** system_hooks/src/lib.rs (L125-203)
```rust
pub fn add_precompiles<S: EthereumLikeTypes, A: Allocator + Clone>(
    hooks: &mut HooksStorage<S, A>,
) -> Result<(), InternalError>
where
    S::IO: IOSubsystemExt,
{
    add_precompile::<
        _,
        _,
        <S::SystemFunctions as SystemFunctions<_>>::Secp256k1ECRecover,
        Secp256k1ECRecoverErrors,
    >(hooks, ECRECOVER_HOOK_ADDRESS_LOW)?;
    add_precompile::<_, _, <S::SystemFunctions as SystemFunctions<_>>::Sha256, Sha256Errors>(
        hooks,
        SHA256_HOOK_ADDRESS_LOW,
    )?;
    add_precompile::<_, _, <S::SystemFunctions as SystemFunctions<_>>::RipeMd160, RipeMd160Errors>(
        hooks,
        RIPEMD160_HOOK_ADDRESS_LOW,
    )?;
    add_precompile::<_, _, IdentityPrecompile, IdentityPrecompileErrors>(
        hooks,
        ID_HOOK_ADDRESS_LOW,
    )?;
    add_precompile_ext::<
        _,
        _,
        <S::SystemFunctionsExt as SystemFunctionsExt<_>>::ModExp,
        ModExpErrors,
    >(hooks, MODEXP_HOOK_ADDRESS_LOW)?;
    add_precompile::<_, _, <S::SystemFunctions as SystemFunctions<_>>::Bn254Add, Bn254AddErrors>(
        hooks,
        ECADD_HOOK_ADDRESS_LOW,
    )?;
    add_precompile::<_, _, <S::SystemFunctions as SystemFunctions<_>>::Bn254Mul, Bn254MulErrors>(
        hooks,
        ECMUL_HOOK_ADDRESS_LOW,
    )?;
    add_precompile::<
        _,
        _,
        <S::SystemFunctions as SystemFunctions<_>>::Bn254PairingCheck,
        Bn254PairingCheckErrors,
    >(hooks, ECPAIRING_HOOK_ADDRESS_LOW)?;
    #[cfg(feature = "mock-unsupported-precompiles")]
    {
        add_precompile::<
            _,
            _,
            crate::call_hooks::mock_precompiles::mock_precompiles::Blake2f,
            MissingSystemFunctionErrors,
        >(hooks, BLAKE2F_HOOK_ADDRESS_LOW)?;

        #[cfg(not(feature = "point_eval_precompile"))]
        add_precompile::<
            _,
            _,
            crate::call_hooks::mock_precompiles::mock_precompiles::PointEvaluation,
            MissingSystemFunctionErrors,
        >(hooks, POINT_EVAL_HOOK_ADDRESS_LOW)?;
    }
    #[cfg(feature = "point_eval_precompile")]
    add_precompile::<
        _,
        _,
        <S::SystemFunctions as SystemFunctions<_>>::PointEvaluation,
        PointEvaluationErrors,
    >(hooks, POINT_EVAL_HOOK_ADDRESS_LOW)?;

    #[cfg(feature = "p256_precompile")]
    {
        add_precompile::<
            _,
            _,
            <S::SystemFunctions as SystemFunctions<_>>::P256Verify,
            P256VerifyErrors,
        >(hooks, P256_VERIFY_PREHASH_HOOK_ADDRESS_LOW)?;
    }
    Ok(())
```
