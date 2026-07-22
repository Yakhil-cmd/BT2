The code confirms this is a real issue. Here is the analysis:

---

### Title
`vm_resources_to_execution_resources` returns `UnknownBuiltin` for `add_mod`, `mul_mod`, `range_check96`, breaking RPC simulation/tracing for valid transactions — (`crates/apollo_rpc_execution/src/objects.rs`)

### Summary

`vm_resources_to_execution_resources` has an incomplete `match` over `BuiltinName` variants. The three builtins `add_mod`, `mul_mod`, and `range_check96` fall through to the wildcard arm and return `Err(ExecutionError::UnknownBuiltin)`. Any transaction whose execution uses one of these builtins causes `simulate_transactions` or `trace_transaction` to fail with an internal error instead of returning a valid trace.

### Finding Description

In `crates/apollo_rpc_execution/src/objects.rs`, the function `vm_resources_to_execution_resources` iterates over `vm_resources.builtin_instance_counter` and maps each `BuiltinName` to a `Builtin` enum variant: [1](#0-0) 

The match arm at line 389–391 is the catch-all:

```rust
_ => {
    return Err(ExecutionError::UnknownBuiltin { builtin_name });
}
```

The three builtins `range_check96`, `add_mod`, and `mul_mod` are explicitly acknowledged as unhandled in the TODO comments at lines 385–388 but are left to fall through to this error arm: [2](#0-1) 

`FunctionInvocation::try_from` at line 352–355 calls this function and propagates the error with `?`, so the entire trace construction fails: [3](#0-2) 

Note that the **receipt/output path** in `transaction.rs` is unaffected — it uses `filter_map(...ok())` which silently drops unknown builtins: [4](#0-3) 

This means the two paths diverge: receipts succeed, but traces/simulations fail.

### Impact Explanation

Any user (no privileges required) who deploys or calls a contract that uses `add_mod`, `mul_mod`, or `range_check96` builtins — all valid Cairo VM builtins used in modular arithmetic operations in newer Cairo programs — will receive an internal error from `simulate_transactions` or `trace_transaction`. The simulation result is corrupted (error instead of valid trace). This maps to **High: RPC simulation fails for valid transactions using new builtins**.

### Likelihood Explanation

`add_mod`, `mul_mod`, and `range_check96` are standard Cairo VM builtins actively used by newer Cairo contracts (e.g., for efficient modular arithmetic). Any contract using these builtins on a live network would trigger this path for every simulation or trace call. The trigger requires no special privileges — just submitting or simulating a transaction that calls such a contract.

### Recommendation

Add the three missing match arms in `vm_resources_to_execution_resources`, mapping them to their corresponding `Builtin` enum variants (or silently skipping them with `continue` if they are intentionally excluded from the RPC representation, consistent with how `output` is handled at line 374):

```rust
BuiltinName::range_check96 => builtin_instance_counter.insert(Builtin::RangeCheck96, count),
BuiltinName::add_mod => builtin_instance_counter.insert(Builtin::AddMod, count),
BuiltinName::mul_mod => builtin_instance_counter.insert(Builtin::MulMod, count),
```

If the `Builtin` enum does not yet have these variants, they should be added. Alternatively, if these builtins are intentionally not exposed in the RPC spec, replace the `_` wildcard with explicit `continue` arms for each known-but-excluded builtin, and keep the wildcard only for truly unexpected names.

### Proof of Concept

```rust
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use cairo_vm::types::builtin_name::BuiltinName;
use std::collections::HashMap;

let mut counter = HashMap::new();
counter.insert(BuiltinName::add_mod, 1usize);
let vm_resources = VmExecutionResources {
    n_steps: 100,
    n_memory_holes: 0,
    builtin_instance_counter: counter,
};
// This returns Err(ExecutionError::UnknownBuiltin { builtin_name: BuiltinName::add_mod })
let result = vm_resources_to_execution_resources(vm_resources, GasVector::default());
assert!(result.is_err());
```

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L352-356)
```rust
            execution_resources: vm_resources_to_execution_resources(
                call_info.resources.vm_resources,
                gas_vector,
            )?,
        })
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L363-401)
```rust
fn vm_resources_to_execution_resources(
    vm_resources: VmExecutionResources,
    GasVector { l1_gas, l1_data_gas, l2_gas }: GasVector,
) -> ExecutionResult<ExecutionResources> {
    let mut builtin_instance_counter = HashMap::new();
    for (builtin_name, count) in vm_resources.builtin_instance_counter {
        if count == 0 {
            continue;
        }
        let count = u64_from_usize(count);
        match builtin_name {
            BuiltinName::output => continue,
            BuiltinName::pedersen => builtin_instance_counter.insert(Builtin::Pedersen, count),
            BuiltinName::range_check => builtin_instance_counter.insert(Builtin::RangeCheck, count),
            BuiltinName::ecdsa => builtin_instance_counter.insert(Builtin::Ecdsa, count),
            BuiltinName::bitwise => builtin_instance_counter.insert(Builtin::Bitwise, count),
            BuiltinName::ec_op => builtin_instance_counter.insert(Builtin::EcOp, count),
            BuiltinName::keccak => builtin_instance_counter.insert(Builtin::Keccak, count),
            BuiltinName::poseidon => builtin_instance_counter.insert(Builtin::Poseidon, count),
            BuiltinName::segment_arena => {
                builtin_instance_counter.insert(Builtin::SegmentArena, count)
            }
            // TODO(DanB): what about the following?
            // BuiltinName::range_check96 => todo!(),
            // BuiltinName::add_mod => todo!(),
            // BuiltinName::mul_mod => todo!(),
            _ => {
                return Err(ExecutionError::UnknownBuiltin { builtin_name });
            }
        };
    }
    Ok(ExecutionResources {
        steps: u64_from_usize(vm_resources.n_steps),
        builtin_instance_counter,
        memory_holes: u64_from_usize(vm_resources.n_memory_holes),
        da_gas_consumed: StarknetApiGasVector { l1_gas, l2_gas, l1_data_gas },
        gas_consumed: StarknetApiGasVector::default(),
    })
}
```

**File:** crates/apollo_rpc/src/v0_8/transaction.rs (L1003-1007)
```rust
            builtin_instance_counter: value
                .builtin_instance_counter
                .into_iter()
                .filter_map(|(k, v)| k.try_into().ok().zip(v.try_into().ok()))
                .collect(),
```
