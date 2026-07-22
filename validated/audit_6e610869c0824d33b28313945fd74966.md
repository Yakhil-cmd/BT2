The code is clear and the behavior is confirmed. Let me verify the call site where `receipt.da_gas` is first passed in, and whether `CallInfo` carries any per-call DA gas that is being ignored.

The code is unambiguous. Let me confirm the `ExtendedExecutionResources` structure to verify there is no per-call DA gas field being ignored.

The analysis is complete. Here is the verdict:

---

### Title
Transaction-Level `da_gas` Uniformly Stamped on Every Inner `FunctionInvocation` Frame in RPC Trace/Simulation Output — (`crates/apollo_rpc_execution/src/objects.rs`)

### Summary

`FunctionInvocation::try_from` receives the transaction-level `receipt.da_gas` as its `gas_vector` argument and propagates it unchanged to every inner call frame recursively. Every node in the call tree — including deeply nested inner calls — ends up with `execution_resources.da_gas_consumed` equal to the full transaction-level DA gas, not the per-call DA gas contribution. This is a confirmed, concrete wrong value returned by `starknet_simulateTransactions` and `starknet_traceTransaction`.

### Finding Description

In `InvokeTransactionTrace::try_from`, the transaction-level `receipt.da_gas` is passed as the second element of the tuple to `FunctionInvocation::try_from`: [1](#0-0) 

Inside `FunctionInvocation::try_from`, the same `gas_vector` is fanned out to every element of `inner_calls` without modification: [2](#0-1) 

Each inner call then passes that same `gas_vector` into `vm_resources_to_execution_resources`, which writes it directly into `da_gas_consumed`: [3](#0-2) [4](#0-3) 

The same pattern applies to `validate_invocation` and `fee_transfer_invocation` at the top level: [5](#0-4) 

`CallInfo.resources` is `ExtendedExecutionResources`, which contains only `vm_resources` (steps, builtins, memory holes) and `opcode_instance_counter` — there is no per-call DA gas field: [6](#0-5) 

DA gas is a transaction-level concept derived from state diffs. Because `CallInfo` carries no per-call DA gas, the code has no correct value to substitute — but instead of emitting zero (or omitting the field), it stamps the full transaction-level `receipt.da_gas` onto every frame.

### Impact Explanation

Any call to `starknet_simulateTransactions` or `starknet_traceTransaction` for a transaction with inner calls returns a trace where every `FunctionInvocation.execution_resources.da_gas_consumed` is identical and equal to the transaction-level DA gas. For a two-level call tree with N inner calls, each inner node reports the same inflated DA gas figure. Tooling, block explorers, and developers that consume these fields to attribute per-call DA costs will receive authoritative-looking but incorrect data. This falls squarely under **High — RPC simulation/tracing returns an authoritative-looking wrong value**.

### Likelihood Explanation

This triggers for every transaction that has at least one inner call — which is the common case for any non-trivial Invoke transaction. No special attacker action is required; submitting any ordinary multi-call transaction is sufficient to observe the corrupted trace.

### Recommendation

Since `CallInfo` carries no per-call DA gas, the correct fix is to emit `GasVector::ZERO` (or `StarknetApiGasVector::default()`) for `da_gas_consumed` on all inner call frames, reserving the transaction-level value only for the top-level frame. Alternatively, track per-call state-diff contributions in `CallInfo` and propagate those instead. The current behavior of stamping the transaction total on every node is strictly worse than zero because it implies each call independently consumed the full transaction DA gas.

### Proof of Concept

Build a two-level call tree via `simulate_transactions`. Extract all `FunctionInvocation` nodes recursively from the returned trace. Assert that every inner node's `execution_resources.da_gas_consumed` equals `receipt.da_gas` of the transaction — which it will, demonstrating the bug. The inner calls' `vm_resources` (steps, builtins) will correctly differ per call, confirming the DA gas field alone is wrong.

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L130-138)
```rust
            None => FunctionInvocationResult::Ok(
                (
                    transaction_execution_info
                        .execute_call_info
                        .expect("Invoke transaction execution should contain execute_call_info."),
                    transaction_execution_info.receipt.da_gas,
                )
                    .try_into()?,
            ),
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L142-154)
```rust
            validate_invocation: match transaction_execution_info.validate_call_info {
                None => None,
                Some(call_info) => {
                    Some((call_info, transaction_execution_info.receipt.da_gas).try_into()?)
                }
            },
            execute_invocation,
            fee_transfer_invocation: match transaction_execution_info.fee_transfer_call_info {
                None => None,
                Some(call_info) => {
                    Some((call_info, transaction_execution_info.receipt.da_gas).try_into()?)
                }
            },
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L329-334)
```rust
            calls: call_info
                .inner_calls
                .into_iter()
                .map(|call_info| (call_info, gas_vector))
                .map(Self::try_from)
                .collect::<Result<_, _>>()?,
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L352-355)
```rust
            execution_resources: vm_resources_to_execution_resources(
                call_info.resources.vm_resources,
                gas_vector,
            )?,
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L394-399)
```rust
    Ok(ExecutionResources {
        steps: u64_from_usize(vm_resources.n_steps),
        builtin_instance_counter,
        memory_holes: u64_from_usize(vm_resources.n_memory_holes),
        da_gas_consumed: StarknetApiGasVector { l1_gas, l2_gas, l1_data_gas },
        gas_consumed: StarknetApiGasVector::default(),
```

**File:** crates/blockifier/src/execution/call_info.rs (L272-277)
```rust
pub struct ExtendedExecutionResources {
    #[serde(flatten)]
    pub vm_resources: ExecutionResources,
    #[serde(default, skip_serializing_if = "OpcodeCounterMap::is_empty")]
    pub opcode_instance_counter: OpcodeCounterMap,
}
```
