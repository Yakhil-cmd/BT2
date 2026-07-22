### Title
Top-Level `receipt.da_gas` Stamped on Every Inner Call's `da_gas_consumed` in RPC Trace — (`crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

`FunctionInvocation::try_from` receives the transaction-level `GasVector` (sourced from `receipt.da_gas`) and passes it **unchanged** to every recursive inner call. As a result, every node in the call tree — regardless of depth or actual DA gas consumed — reports the same `da_gas_consumed` value as the top-level transaction receipt.

---

### Finding Description

In `FunctionInvocation::try_from`, the `gas_vector` argument is the whole-transaction `receipt.da_gas`: [1](#0-0) 

```rust
calls: call_info
    .inner_calls
    .into_iter()
    .map(|call_info| (call_info, gas_vector))   // ← same gas_vector for every child
    .map(Self::try_from)
    .collect::<Result<_, _>>()?,
```

That same `gas_vector` is then written into each node's `execution_resources.da_gas_consumed`: [2](#0-1) [3](#0-2) 

```rust
execution_resources: vm_resources_to_execution_resources(
    call_info.resources.vm_resources,
    gas_vector,   // ← top-level receipt.da_gas, not this call's own DA gas
)?,
// ...
da_gas_consumed: StarknetApiGasVector { l1_gas, l2_gas, l1_data_gas },
```

The callers all pass `transaction_execution_info.receipt.da_gas` as the seed value: [4](#0-3) [5](#0-4) 

There is no per-call DA gas field in `CallInfo` being consulted; the same scalar is cloned down the entire tree.

---

### Impact Explanation

Any RPC caller invoking `starknet_simulateTransactions`, `starknet_traceTransaction`, or `starknet_traceBlockTransactions` on a transaction with inner calls receives a trace where **every** `FunctionInvocation.execution_resources.da_gas_consumed` equals the top-level transaction's total DA gas. Inner calls that consumed zero DA gas appear to have consumed the full transaction amount, and the values do not sum correctly across the tree. This is an authoritative-looking wrong value returned by the RPC layer.

Impact: **High** — matches "RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."

---

### Likelihood Explanation

Any unprivileged user can submit an invoke transaction whose `__execute__` makes one or more inner contract calls. No special privileges are required. The corruption is deterministic and affects every such transaction's simulation/trace response.

---

### Recommendation

Each `CallInfo` node must carry its own per-call DA gas. The correct fix is to source `da_gas_consumed` from the individual `CallInfo`'s own resource tracking (e.g., `call_info.resources` or a dedicated per-call DA gas field) rather than threading the transaction-level `receipt.da_gas` through the recursive conversion. The `gas_vector` parameter to `FunctionInvocation::try_from` should be removed or replaced with per-node data.

---

### Proof of Concept

Build a `CallInfo` tree where the outer call has `receipt.da_gas = {l1_data_gas: 100, ...}` and one inner call has zero DA gas of its own. Convert via `FunctionInvocation::try_from(outer_call_info, gas_vector_with_100)`. Assert that `result.calls[0].execution_resources.da_gas_consumed.l1_data_gas == 0` — the test will fail, observing `100` instead, confirming the propagation bug.

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L200-213)
```rust
            validate_invocation: match transaction_execution_info.validate_call_info {
                None => None,
                Some(call_info) => {
                    Some((call_info, transaction_execution_info.receipt.da_gas).try_into()?)
                }
            },
            fee_transfer_invocation: match transaction_execution_info.fee_transfer_call_info {
                None => None,
                Some(call_info) => {
                    Some((call_info, transaction_execution_info.receipt.da_gas).try_into()?)
                }
            },
        })
    }
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L236-251)
```rust
                    Some((call_info, transaction_execution_info.receipt.da_gas).try_into()?)
                }
            },
            constructor_invocation: (
                transaction_execution_info.execute_call_info.expect(
                    "Deploy account execution should contain execute_call_info (the constructor \
                     call info).",
                ),
                transaction_execution_info.receipt.da_gas,
            )
                .try_into()?,
            fee_transfer_invocation: match transaction_execution_info.fee_transfer_call_info {
                None => None,
                Some(call_info) => {
                    Some((call_info, transaction_execution_info.receipt.da_gas).try_into()?)
                }
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
