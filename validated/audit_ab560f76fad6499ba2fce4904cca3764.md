The code confirms the behavior described. Here is the analysis:

---

### Title
`vm_resources_to_execution_resources` Hardcodes `gas_consumed` to Zero in Every `FunctionInvocation.execution_resources` — (`crates/apollo_rpc_execution/src/objects.rs`)

### Summary
`vm_resources_to_execution_resources` unconditionally sets `gas_consumed: StarknetApiGasVector::default()` (all-zero) in the returned `ExecutionResources`. Every `FunctionInvocation` produced by RPC simulation and tracing therefore reports zero L2/L1/L1-data gas consumed at the call level, regardless of actual consumption.

### Finding Description

`vm_resources_to_execution_resources` receives a `GasVector` parameter that carries `l1_gas`, `l1_data_gas`, and `l2_gas` values. It correctly maps those values into `da_gas_consumed`, but then hardcodes `gas_consumed` to the default (zero):

```rust
Ok(ExecutionResources {
    steps: u64_from_usize(vm_resources.n_steps),
    builtin_instance_counter,
    memory_holes: u64_from_usize(vm_resources.n_memory_holes),
    da_gas_consumed: StarknetApiGasVector { l1_gas, l2_gas, l1_data_gas },
    gas_consumed: StarknetApiGasVector::default(),   // ← always zero
})
``` [1](#0-0) 

This function is the sole path used to build `execution_resources` for every `FunctionInvocation`:

```rust
execution_resources: vm_resources_to_execution_resources(
    call_info.resources.vm_resources,
    gas_vector,
)?,
``` [2](#0-1) 

`FunctionInvocation::try_from` is called recursively for all inner calls, so the zero value propagates to every nested call in the trace:

```rust
calls: call_info
    .inner_calls
    .into_iter()
    .map(|call_info| (call_info, gas_vector))
    .map(Self::try_from)
    .collect::<Result<_, _>>()?,
``` [3](#0-2) 

The `ExecutionResources` struct in `starknet_api` has two distinct fields — `da_gas_consumed` (data-availability gas) and `gas_consumed` (execution gas) — and both are `GasVector`:

```rust
pub struct ExecutionResources {
    pub steps: u64,
    pub builtin_instance_counter: HashMap<Builtin, u64>,
    pub memory_holes: u64,
    pub da_gas_consumed: GasVector,
    pub gas_consumed: GasVector,
}
``` [4](#0-3) 

The call sites that build `FunctionInvocation` pass `receipt.da_gas` as the `gas_vector` argument, which is the transaction-level DA gas, not per-call execution gas. Even if a per-call execution gas value were available, `gas_consumed` is never populated from it. [5](#0-4) 

### Impact Explanation

Any caller of `starknet_simulateTransactions` or `starknet_traceTransaction` receives `execution_resources.gas_consumed = {l1_gas: 0, l1_data_gas: 0, l2_gas: 0}` for every `FunctionInvocation` in the trace, even when the contract consumed nonzero L2 gas. This is an authoritative-looking wrong value: the RPC response is structurally valid and passes schema validation, but the per-call gas breakdown is silently incorrect. Developers and tooling that rely on per-call `gas_consumed` for gas profiling, cost attribution, or off-chain fee modeling will receive systematically wrong data.

This does **not** affect actual on-chain fee charging or state — the blockifier computes fees from `receipt` directly, not from the trace objects. The impact is confined to the RPC simulation/tracing surface.

### Likelihood Explanation

This is triggered by any simulation or trace of any Cairo 1 contract that consumes L2 gas — no special attacker setup is required. The condition is always true; the field is unconditionally zero.

### Recommendation

Populate `gas_consumed` from the per-call gas consumption tracked in `CallInfo`. The blockifier's `CallInfo` carries `resources` which includes gas usage; the correct per-call L2 gas consumed should be extracted from there (e.g., `call_info.execution.gas_consumed` or equivalent field) rather than left as `default()`. If per-call gas is not yet tracked at the `CallInfo` level, a TODO comment should be added and the field should be documented as approximate/incomplete rather than silently emitting zero.

### Proof of Concept

1. Deploy a Cairo 1 contract with an entry point that performs a gas-consuming operation (e.g., a loop with storage reads).
2. Call `starknet_simulateTransactions` with `SKIP_FEE_CHARGE` and `SKIP_VALIDATE`.
3. Inspect `transaction_trace.execute_invocation.execution_resources.gas_consumed` in the response.
4. Observe `{"l1_gas": "0x0", "l1_data_gas": "0x0", "l2_gas": "0x0"}` regardless of actual L2 gas consumed.
5. Confirm the blockifier's internal receipt shows nonzero L2 gas, proving the discrepancy is in the RPC conversion layer only.

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L248-252)
```rust
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

**File:** crates/apollo_rpc_execution/src/objects.rs (L394-400)
```rust
    Ok(ExecutionResources {
        steps: u64_from_usize(vm_resources.n_steps),
        builtin_instance_counter,
        memory_holes: u64_from_usize(vm_resources.n_memory_holes),
        da_gas_consumed: StarknetApiGasVector { l1_gas, l2_gas, l1_data_gas },
        gas_consumed: StarknetApiGasVector::default(),
    })
```

**File:** crates/starknet_api/src/execution_resources.rs (L230-237)
```rust
#[derive(Debug, Default, Deserialize, Serialize, Clone, Eq, PartialEq)]
pub struct ExecutionResources {
    pub steps: u64,
    pub builtin_instance_counter: HashMap<Builtin, u64>,
    pub memory_holes: u64,
    pub da_gas_consumed: GasVector,
    pub gas_consumed: GasVector,
}
```
