The code confirms the claim. At line 399, `gas_consumed` is unconditionally hardcoded to `StarknetApiGasVector::default()` (all zeros), while the `GasVector` parameter is only used to populate `da_gas_consumed`. [1](#0-0) 

Additionally, in `FunctionInvocation::try_from`, the same transaction-level `gas_vector` is propagated unchanged to every inner call recursively, meaning `da_gas_consumed` is also wrong for nested calls (all get the transaction-level value). [2](#0-1) 

---

### Title
`gas_consumed` Always Zero in Every `FunctionInvocation.execution_resources` for RPC Simulation/Tracing — (`crates/apollo_rpc_execution/src/objects.rs`)

### Summary
`vm_resources_to_execution_resources` unconditionally emits `gas_consumed: StarknetApiGasVector::default()` (all zeros) for every call frame in RPC simulation and tracing output, regardless of actual L2 gas consumed by the call.

### Finding Description
In `vm_resources_to_execution_resources` (line 363–401), the function receives a `GasVector { l1_gas, l1_data_gas, l2_gas }` parameter and correctly maps it to `da_gas_consumed`. However, `gas_consumed` — the field representing actual execution gas consumed by the call — is hardcoded to `StarknetApiGasVector::default()` at line 399 with no conditional logic, no TODO, and no fallback. [3](#0-2) 

This affects every `FunctionInvocation` produced by `TryFrom<(CallInfo, GasVector)>`, including all nested inner calls, because the same `gas_vector` (the transaction-level `receipt.da_gas`) is passed recursively to all inner calls at line 332. [4](#0-3) 

### Impact Explanation
Any RPC caller invoking `starknet_simulateTransactions`, `starknet_traceTransaction`, or `starknet_traceBlockTransactions` receives `execution_resources.gas_consumed = {l1_gas: 0, l2_gas: 0, l1_data_gas: 0}` for every call frame, regardless of actual L2 gas consumed. This is an authoritative-looking wrong value. Tooling, wallets, and developers relying on per-call `gas_consumed` for gas profiling, fee estimation breakdowns, or debugging will receive systematically incorrect data.

This fits the allowed High impact: **"RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."**

### Likelihood Explanation
Triggered by any contract that consumes L2 gas — which includes all Cairo 1 contracts under a block context with nonzero `l2_gas_price`. No special attacker capability is required; any unprivileged user calling the simulation/tracing RPC endpoints observes this.

### Recommendation
In `vm_resources_to_execution_resources`, populate `gas_consumed` from the per-call `CallInfo` resources rather than hardcoding `default()`. The blockifier's `CallInfo` already tracks per-call gas consumption; the conversion layer needs to extract and map it correctly instead of discarding it.

### Proof of Concept
Execute any Cairo 1 contract that consumes nonzero L2 gas via `starknet_simulateTransactions`. Inspect the returned `execution_resources.gas_consumed` field in the `FunctionInvocation` — it will be `{l1_gas: "0x0", l2_gas: "0x0", l1_data_gas: "0x0"}` regardless of actual consumption. This is directly reproducible by reading line 399 of `crates/apollo_rpc_execution/src/objects.rs`. [5](#0-4)

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L329-355)
```rust
            calls: call_info
                .inner_calls
                .into_iter()
                .map(|call_info| (call_info, gas_vector))
                .map(Self::try_from)
                .collect::<Result<_, _>>()?,
            events: call_info
                .execution
                .events
                .into_iter()
                .sorted_by_key(|ordered_event| ordered_event.order)
                .map(OrderedEvent::from)
                .collect(),
            messages: call_info
                .execution
                .l2_to_l1_messages
                .into_iter()
                .sorted_by_key(|ordered_message| ordered_message.order)
                .map(|ordered_message| {
                    // TODO(yair): write a test that verifies that the from_address is correct.
                    OrderedL2ToL1Message::from(ordered_message, call_info.call.storage_address)
                })
                .collect(),
            execution_resources: vm_resources_to_execution_resources(
                call_info.resources.vm_resources,
                gas_vector,
            )?,
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
