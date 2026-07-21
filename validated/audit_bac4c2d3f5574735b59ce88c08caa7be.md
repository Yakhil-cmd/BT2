The code is clear and the bug is real. Let me confirm the full call chain.

The bug is confirmed and concrete. Here is the full analysis:

---

### Title
Transaction-Level `da_gas` Propagated Unchanged to All Inner Calls in `FunctionInvocation::try_from`, Corrupting `da_gas_consumed` in RPC Simulation Traces - (`crates/apollo_rpc_execution/src/objects.rs`)

### Summary

`FunctionInvocation::try_from` receives the transaction-level `receipt.da_gas` as its `gas_vector` argument and passes that same value unchanged to every inner call recursively. The `vm_resources_to_execution_resources` helper then writes it verbatim into each call's `da_gas_consumed` field. Any transaction with inner calls and nonzero transaction-level DA gas will produce a simulation/trace response where every inner `FunctionInvocation.execution_resources.da_gas_consumed` equals the full transaction DA gas rather than that call's own DA gas.

### Finding Description

The entry point for all transaction trace types passes `transaction_execution_info.receipt.da_gas` as the second element of the tuple fed to `FunctionInvocation::try_from`: [1](#0-0) [2](#0-1) 

Inside `try_from`, the recursive descent over `inner_calls` clones the same `gas_vector` into every child: [3](#0-2) 

`vm_resources_to_execution_resources` then writes that vector directly into `da_gas_consumed` with no per-call adjustment: [4](#0-3) 

The same pattern applies to `DeclareTransactionTrace`, `DeployAccountTransactionTrace`, and `L1HandlerTransactionTrace`: [5](#0-4) [6](#0-5) [7](#0-6) 

`receipt.da_gas` is a transaction-level aggregate computed from all state changes across the entire transaction. It is not a per-call quantity. `CallInfo` carries no per-call DA gas field; the blockifier never computes one. Assigning the transaction total to every node in the call tree is structurally wrong.

### Impact Explanation

Every `starknet_simulateTransactions` or `starknet_traceTransaction` response that contains inner calls and a nonzero transaction DA gas will report the full transaction `da_gas_consumed` on every inner `FunctionInvocation`, regardless of what state changes (if any) that inner call actually caused. A caller reading the trace to attribute DA costs to individual sub-calls (e.g., for gas profiling, fee debugging, or contract tooling) receives authoritative-looking but incorrect data. This falls squarely within the allowed High impact: **RPC simulation/tracing returns an authoritative-looking wrong value**.

### Likelihood Explanation

Any invoke transaction that (a) has at least one inner call and (b) touches storage (producing nonzero `da_gas`) triggers the corruption. This is the common case for real DeFi/DApp transactions. No special privileges are required; any unprivileged user submitting a standard invoke transaction can observe and demonstrate the wrong values via the public RPC.

### Recommendation

The `gas_vector` parameter should not be threaded into inner calls at all. Inner calls should receive `GasVector::ZERO` (or the field should be omitted/zeroed) because per-call DA gas is not tracked by the blockifier. Concretely, change line 332 from:

```rust
.map(|call_info| (call_info, gas_vector))
```

to:

```rust
.map(|call_info| (call_info, GasVector::ZERO))
```

and similarly zero out `da_gas_consumed` in `vm_resources_to_execution_resources` for inner-call invocations, or restructure the API so the top-level call receives the real `da_gas` and inner calls receive zero.

### Proof of Concept

```rust
// Pseudocode unit test (no privileged setup required)
let inner_call_info = CallInfo {
    call: CallEntryPoint { class_hash: Some(class_hash!("0x1")), ..Default::default() },
    inner_calls: vec![],
    ..Default::default()
    // inner call has zero DA gas contribution
};
let outer_call_info = CallInfo {
    call: CallEntryPoint { class_hash: Some(class_hash!("0x2")), ..Default::default() },
    inner_calls: vec![inner_call_info],
    ..Default::default()
};
let tx_da_gas = GasVector {
    l1_gas: GasAmount(1652),
    l1_data_gas: GasAmount(1),
    l2_gas: GasAmount(0),
};

let invocation = FunctionInvocation::try_from((outer_call_info, tx_da_gas)).unwrap();

// Bug: inner call's da_gas_consumed equals the transaction-level da_gas
let inner_inv = &invocation.calls[0];
// Expected: inner_inv.execution_resources.da_gas_consumed == GasVector::ZERO
// Actual:   inner_inv.execution_resources.da_gas_consumed == tx_da_gas  ← WRONG
assert_eq!(
    inner_inv.execution_resources.da_gas_consumed,
    StarknetApiGasVector { l1_gas: GasAmount(0), l1_data_gas: GasAmount(0), l2_gas: GasAmount(0) }
);
// This assertion FAILS, proving the corruption.
```

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L130-137)
```rust
            None => FunctionInvocationResult::Ok(
                (
                    transaction_execution_info
                        .execute_call_info
                        .expect("Invoke transaction execution should contain execute_call_info."),
                    transaction_execution_info.receipt.da_gas,
                )
                    .try_into()?,
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L142-155)
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
        })
```

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

**File:** crates/apollo_rpc_execution/src/objects.rs (L233-254)
```rust
            validate_invocation: match transaction_execution_info.validate_call_info {
                None => None,
                Some(call_info) => {
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
            },
        })
    }
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L264-277)
```rust
impl TryFrom<TransactionExecutionInfo> for L1HandlerTransactionTrace {
    type Error = ExecutionError;
    fn try_from(transaction_execution_info: TransactionExecutionInfo) -> ExecutionResult<Self> {
        Ok(Self {
            function_invocation: (
                transaction_execution_info
                    .execute_call_info
                    .expect("L1Handler execution should contain execute_call_info."),
                transaction_execution_info.receipt.da_gas,
            )
                .try_into()?,
        })
    }
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

**File:** crates/apollo_rpc_execution/src/objects.rs (L394-399)
```rust
    Ok(ExecutionResources {
        steps: u64_from_usize(vm_resources.n_steps),
        builtin_instance_counter,
        memory_holes: u64_from_usize(vm_resources.n_memory_holes),
        da_gas_consumed: StarknetApiGasVector { l1_gas, l2_gas, l1_data_gas },
        gas_consumed: StarknetApiGasVector::default(),
```
