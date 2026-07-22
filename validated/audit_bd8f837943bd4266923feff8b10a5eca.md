### Title
`vm_resources_to_execution_resources` Rejects Valid Traces for Transactions Using `range_check96`, `add_mod`, or `mul_mod` Builtins — (`crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

The `vm_resources_to_execution_resources` function has an explicit `_` catch-all arm that returns `Err(ExecutionError::UnknownBuiltin)` for `BuiltinName::range_check96`, `BuiltinName::add_mod`, and `BuiltinName::mul_mod`. These are real, production-supported Cairo VM builtins. Any transaction that blockifier executes successfully using these builtins will cause `starknet_simulateTransactions` and `starknet_traceTransaction` to return an error instead of a valid trace.

---

### Finding Description

In `crates/apollo_rpc_execution/src/objects.rs`, the function `vm_resources_to_execution_resources` (lines 363–401) iterates over `vm_resources.builtin_instance_counter` and maps each `BuiltinName` to a `Builtin` enum variant. The match arm explicitly handles `output`, `pedersen`, `range_check`, `ecdsa`, `bitwise`, `ec_op`, `keccak`, `poseidon`, and `segment_arena`, but falls through to:

```rust
// TODO(DanB): what about the following?
// BuiltinName::range_check96 => todo!(),
// BuiltinName::add_mod => todo!(),
// BuiltinName::mul_mod => todo!(),
_ => {
    return Err(ExecutionError::UnknownBuiltin { builtin_name });
}
``` [1](#0-0) 

These three builtins are not hypothetical. `starknet_api::execution_resources::Builtin` defines `AddMod`, `MulMod`, and `RangeCheck96` as first-class variants: [2](#0-1) 

The `apollo_starknet_client` also handles them in its own `Builtin` enum and conversion logic: [3](#0-2) 

The blockifier bouncer and versioned constants reference these builtins for gas/resource accounting, confirming they are emitted by real contract executions.

The error propagates through `FunctionInvocation::try_from((CallInfo, GasVector))`, which calls `vm_resources_to_execution_resources` with a `?` operator: [4](#0-3) 

This `TryFrom` is invoked recursively for all inner calls (line 329–334), meaning even a single inner call using one of these builtins causes the entire trace to fail. The `get_trace_constructor` function in `execution_utils.rs` returns closures that call `execution_info.try_into()`, which chains into this path for all transaction types (`Invoke`, `Declare`, `DeployAccount`, `L1Handler`): [5](#0-4) 

---

### Impact Explanation

Any unprivileged user can deploy or invoke a Sierra contract that uses `range_check96` (used by modular arithmetic in Cairo 1.x), `add_mod`, or `mul_mod` builtins. Blockifier will execute the transaction successfully and include it in a block. However:

- `starknet_simulateTransactions` will return `ExecutionError::UnknownBuiltin` instead of a valid simulation trace.
- `starknet_traceTransaction` will return the same error for already-confirmed transactions.

This violates the invariant that any successfully executed transaction can be traced. The RPC node returns an authoritative-looking error for a valid, confirmed transaction, which is a **High** impact per the allowed scope: *"RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."*

---

### Likelihood Explanation

`range_check96` is used by Cairo's native modular arithmetic operations (e.g., `u96` range checks in Sierra-compiled contracts). Any Sierra contract using these operations will trigger this path. The likelihood is **High** — this is not an edge case; it affects a class of contracts that is increasingly common as Cairo 1.x adoption grows.

---

### Recommendation

Add explicit match arms for the three missing builtins. Since `starknet_api::execution_resources::Builtin` already has `AddMod`, `MulMod`, and `RangeCheck96` variants, the fix is straightforward:

```rust
BuiltinName::range_check96 => {
    builtin_instance_counter.insert(Builtin::RangeCheck96, count)
}
BuiltinName::add_mod => {
    builtin_instance_counter.insert(Builtin::AddMod, count)
}
BuiltinName::mul_mod => {
    builtin_instance_counter.insert(Builtin::MulMod, count)
}
```

The TODO comment at lines 385–388 already identifies this gap; it should be resolved rather than left as a silent runtime failure. [6](#0-5) 

---

### Proof of Concept

A Rust unit test demonstrating the failure:

```rust
#[test]
fn test_range_check96_causes_unknown_builtin_error() {
    use cairo_vm::types::builtin_name::BuiltinName;
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
    use std::collections::HashMap;
    use starknet_api::execution_resources::GasVector;

    let mut counter = HashMap::new();
    counter.insert(BuiltinName::range_check96, 5usize);

    let vm_resources = ExecutionResources {
        n_steps: 100,
        n_memory_holes: 0,
        builtin_instance_counter: counter,
    };

    let result = vm_resources_to_execution_resources(
        vm_resources,
        GasVector::default(),
    );

    assert!(
        matches!(result, Err(ExecutionError::UnknownBuiltin { .. })),
        "Expected UnknownBuiltin error for range_check96"
    );
}
```

This test will pass against the current code, confirming that a transaction whose `CallInfo` contains `range_check96` usage will cause the entire trace conversion to fail with `UnknownBuiltin`.

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L352-355)
```rust
            execution_resources: vm_resources_to_execution_resources(
                call_info.resources.vm_resources,
                gas_vector,
            )?,
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L385-392)
```rust
            // TODO(DanB): what about the following?
            // BuiltinName::range_check96 => todo!(),
            // BuiltinName::add_mod => todo!(),
            // BuiltinName::mul_mod => todo!(),
            _ => {
                return Err(ExecutionError::UnknownBuiltin { builtin_name });
            }
        };
```

**File:** crates/starknet_api/src/execution_resources.rs (L257-263)
```rust
    #[serde(rename = "add_mod_builtin")]
    AddMod,
    #[serde(rename = "mul_mod_builtin")]
    MulMod,
    #[serde(rename = "range_check96_builtin")]
    RangeCheck96,
}
```

**File:** crates/apollo_starknet_client/src/reader/objects/transaction.rs (L697-703)
```rust
    #[serde(rename = "add_mod_builtin")]
    AddMod,
    #[serde(rename = "mul_mod_builtin")]
    MulMod,
    #[serde(rename = "range_check96_builtin")]
    RangeCheck96,
}
```

**File:** crates/apollo_rpc_execution/src/execution_utils.rs (L97-123)
```rust
pub fn get_trace_constructor(
    tx: &ExecutableTransactionInput,
) -> fn(TransactionExecutionInfo) -> ExecutionResult<TransactionTrace> {
    match tx {
        ExecutableTransactionInput::Invoke(..) => {
            |execution_info| Ok(TransactionTrace::Invoke(execution_info.try_into()?))
        }
        ExecutableTransactionInput::DeclareV0(..) => {
            |execution_info| Ok(TransactionTrace::Declare(execution_info.try_into()?))
        }
        ExecutableTransactionInput::DeclareV1(..) => {
            |execution_info| Ok(TransactionTrace::Declare(execution_info.try_into()?))
        }
        ExecutableTransactionInput::DeclareV2(..) => {
            |execution_info| Ok(TransactionTrace::Declare(execution_info.try_into()?))
        }
        ExecutableTransactionInput::DeclareV3(..) => {
            |execution_info| Ok(TransactionTrace::Declare(execution_info.try_into()?))
        }
        ExecutableTransactionInput::DeployAccount(..) => {
            |execution_info| Ok(TransactionTrace::DeployAccount(execution_info.try_into()?))
        }
        ExecutableTransactionInput::L1Handler(..) => {
            |execution_info| Ok(TransactionTrace::L1Handler(execution_info.try_into()?))
        }
    }
}
```
