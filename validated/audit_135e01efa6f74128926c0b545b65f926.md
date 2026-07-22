### Title
`vm_resources_to_execution_resources` Returns `UnknownBuiltin` for Valid `RangeCheck96`/`AddMod`/`MulMod` Builtins — (`crates/apollo_rpc_execution/src/objects.rs`)

---

### Summary

The `vm_resources_to_execution_resources` function in `crates/apollo_rpc_execution/src/objects.rs` does not handle `BuiltinName::range_check96`, `BuiltinName::add_mod`, or `BuiltinName::mul_mod`. Any contract using these builtins causes the function to return `Err(ExecutionError::UnknownBuiltin)`, making `starknet_simulateTransactions` and `starknet_traceTransaction` return an error for transactions that were validly accepted and executed on-chain.

---

### Finding Description

The match in `vm_resources_to_execution_resources` covers only 8 builtins and routes everything else to the error arm: [1](#0-0) 

The three missing builtins are explicitly called out in a TODO comment but left unimplemented: [2](#0-1) 

Meanwhile, `starknet_api::execution_resources::Builtin` already defines all three variants, confirming they are part of the intended API surface: [3](#0-2) 

The conversion is called unconditionally inside `FunctionInvocation::try_from` for every call info produced by blockifier: [4](#0-3) 

`FunctionInvocation::try_from` is used by every transaction trace type (`InvokeTransactionTrace`, `DeclareTransactionTrace`, `DeployAccountTransactionTrace`, `L1HandlerTransactionTrace`): [5](#0-4) 

---

### Impact Explanation

The blockifier fully supports `range_check96`, `add_mod`, and `mul_mod` builtins and will execute such contracts successfully, recording them in the chain. However, when any RPC method that calls `FunctionInvocation::try_from` (i.e., `starknet_simulateTransactions`, `starknet_traceTransaction`, `starknet_traceBlockTransactions`) processes a transaction whose call info contains any of these three builtins with a non-zero count, the conversion fails and the RPC returns an error instead of a valid trace/simulation result. This matches the **High** impact category: "RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value."

---

### Likelihood Explanation

`range_check96` is used by the `u96` integer type and by modular arithmetic operations in Cairo. `add_mod` and `mul_mod` are used by the `ModBuiltin` for efficient modular arithmetic. Any contract using these features — which are standard Cairo 1 / Sierra features — will trigger this bug. An attacker can deploy such a contract and invoke it, causing all trace/simulation queries for that transaction to fail permanently.

---

### Recommendation

Add the three missing arms to the match in `vm_resources_to_execution_resources`:

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

Remove the `_ =>` error arm (or replace it with a compile-time exhaustive match) so that future new builtins are caught at compile time rather than at runtime.

---

### Proof of Concept

1. Deploy a Cairo contract that uses `range_check96` (e.g., any contract performing `u96` arithmetic or using `ModBuiltin`).
2. Submit an invoke transaction calling that contract. The blockifier accepts and executes it successfully; the transaction is included in a block.
3. Call `starknet_traceTransaction` or `starknet_simulateTransactions` for that transaction.
4. `FunctionInvocation::try_from` calls `vm_resources_to_execution_resources` with a `builtin_instance_counter` containing `BuiltinName::range_check96 => N` (N > 0).
5. The `_` arm fires, returning `Err(ExecutionError::UnknownBuiltin { builtin_name: BuiltinName::range_check96 })`.
6. The RPC method returns an error for a transaction that is validly on-chain, instead of a correct trace.

### Citations

**File:** crates/apollo_rpc_execution/src/objects.rs (L123-157)
```rust
impl TryFrom<TransactionExecutionInfo> for InvokeTransactionTrace {
    type Error = ExecutionError;
    fn try_from(transaction_execution_info: TransactionExecutionInfo) -> ExecutionResult<Self> {
        let execute_invocation = match transaction_execution_info.revert_error {
            Some(revert_error) => {
                FunctionInvocationResult::Err(RevertReason::RevertReason(revert_error.to_string()))
            }
            None => FunctionInvocationResult::Ok(
                (
                    transaction_execution_info
                        .execute_call_info
                        .expect("Invoke transaction execution should contain execute_call_info."),
                    transaction_execution_info.receipt.da_gas,
                )
                    .try_into()?,
            ),
        };

        Ok(Self {
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
    }
}
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L352-356)
```rust
            execution_resources: vm_resources_to_execution_resources(
                call_info.resources.vm_resources,
                gas_vector,
            )?,
        })
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L373-392)
```rust
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
```

**File:** crates/starknet_api/src/execution_resources.rs (L258-263)
```rust
    AddMod,
    #[serde(rename = "mul_mod_builtin")]
    MulMod,
    #[serde(rename = "range_check96_builtin")]
    RangeCheck96,
}
```
