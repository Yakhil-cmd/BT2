Let me look at the blockifier's revert receipt computation and how `execution_steps_consumed` flows into the fee, and also check `ValidateExecuteCallInfo::new_reverted`.

The code path is real and the discrepancy is confirmed. Here is the full analysis.

---

### Title
Reverted Invoke Transaction Reports Zero Execute-Phase Resources in `InvokeTransactionTrace.execution_resources` While Fee Correctly Charges for Those Resources — (`crates/apollo_rpc/src/v0_8/execution.rs`)

---

### Summary

When an Invoke transaction's execute phase reverts, the RPC aggregation layer in `execution.rs` sets `execute_execution_resources = ExecutionResources::default()` (all zeros). The resulting `InvokeTransactionTrace.execution_resources` is therefore `validate + 0 + fee_transfer`. Meanwhile, the blockifier's `TransactionReceipt` correctly accounts for the reverted execute phase's steps and sierra gas via `n_reverted_steps` / `reverted_sierra_gas`, and the fee charged to the user reflects those costs. The trace's `execution_resources` field is thus systematically lower than the resources actually consumed and paid for.

---

### Finding Description

**Step 1 — RPC aggregation zeroes reverted execute resources.**

In `From<(ExecutionTransactionTrace, ThinStateDiff)> for TransactionTrace`, the Invoke arm matches on `execute_invocation`: [1](#0-0) 

When the execute phase reverted, `execute_execution_resources` is `ExecutionResources::default()` (all fields zero). The final `execution_resources` field is then: [2](#0-1) 

**Step 2 — Blockifier discards `execute_call_info` on revert.**

`ValidateExecuteCallInfo::new_reverted` sets `execute_call_info: None`: [3](#0-2) 

So the `TransactionExecutionInfo` reaching the RPC layer has no execute call info to extract resources from.

**Step 3 — Blockifier fee receipt *does* include reverted execute costs.**

In `run_revertible`, the revert receipt is built with `execution_steps_consumed` (steps consumed during the aborted execute phase) and `sierra_gas_revert_tracker.get_gas_consumed()`: [4](#0-3) 

These are stored in `TransactionResources.computation.n_reverted_steps` and `reverted_sierra_gas`: [5](#0-4) 

The gas vector (and therefore `overall_fee`) is derived from this receipt, so the fee charged to the user includes the reverted execute phase's costs.

**Step 4 — The upstream `InvokeTransactionTrace` (execution crate) also has no resources for the reverted case.**

The `TryFrom<TransactionExecutionInfo> for InvokeTransactionTrace` in `apollo_rpc_execution` converts `revert_error.is_some()` directly to `FunctionInvocationResult::Err(revert_reason)` with no resource extraction: [6](#0-5) 

There is no channel through which `n_reverted_steps` or `reverted_sierra_gas` from the receipt flows into the trace's `execution_resources`.

---

### Impact Explanation

Every reverted Invoke transaction (v1 or v3) served by `starknet_simulateTransactions` or `starknet_traceTransaction` returns an `InvokeTransactionTrace` whose `execution_resources` (steps, builtins, data_availability) is strictly less than the resources actually consumed and charged. The discrepancy equals the reverted execute phase's VM steps and sierra gas. Any client, explorer, or tool that reads `execution_resources` to reconcile fees, audit resource usage, or build receipts will see a wrong value — an authoritative-looking wrong value from the RPC layer.

**Impact category:** High — RPC tracing/simulation returns an authoritative-looking wrong value.

The fee itself is correctly charged by the blockifier; there is no direct economic harm to the protocol. The wrong value is confined to the RPC trace's `execution_resources` field.

---

### Likelihood Explanation

Triggered by any unprivileged user submitting an Invoke transaction whose `__execute__` entry point reverts (logic error, out-of-gas, panic). This is a common, everyday occurrence on mainnet. No special block state or privilege is required.

---

### Recommendation

The `n_reverted_steps` and `reverted_sierra_gas` values are present in `TransactionExecutionInfo.receipt.resources.computation` at the time the trace is built. The RPC layer should extract those values and add them to `execution_resources` when `execute_invocation` is `Err`. Concretely, in `apollo_rpc_execution/src/objects.rs`, the `TryFrom<TransactionExecutionInfo> for InvokeTransactionTrace` conversion should carry the receipt's `n_reverted_steps` / `reverted_sierra_gas` into the trace, and `execution.rs` should incorporate them into the `execution_resources` sum instead of using `ExecutionResources::default()`.

---

### Proof of Concept

```rust
// Pseudocode outline (not a compilable test — illustrates the invariant violation)
let sim_result = simulate_transactions(reverting_invoke_tx);
let TransactionTrace::Invoke(trace) = sim_result.transaction_trace;
let fee_estimation = sim_result.fee_estimation;

// Reported execution_resources = validate + 0 (reverted execute) + fee_transfer
let reported = trace.execution_resources;

// Fee was computed from receipt that includes n_reverted_steps
// Convert fee back to gas: fee / gas_price = gas_consumed
// gas_consumed > steps_implied_by(reported)

// The assertion that SHOULD hold but DOES NOT:
assert_eq!(
    reported,
    validate_resources + execute_resources + fee_transfer_resources
);
// Instead, execute_resources == ExecutionResources::default() in the trace,
// while the actual fee reflects non-zero reverted execute steps.
```

The existing blockifier test at `account_transactions_test.rs` already confirms `n_reverted_steps > 0` for a reverted invoke: [7](#0-6) 

This confirms the reverted steps are charged but are invisible in the RPC trace's `execution_resources`.

### Citations

**File:** crates/apollo_rpc/src/v0_8/execution.rs (L157-160)
```rust
                    ExecutionFunctionInvocationResult::Err(revert_reason) => (
                        FunctionInvocationResult::Err(revert_reason),
                        ExecutionResources::default(),
                    ),
```

**File:** crates/apollo_rpc/src/v0_8/execution.rs (L177-179)
```rust
                    execution_resources: validate_execution_resources.unwrap_or_default()
                        + execute_execution_resources
                        + fee_transfer_execution_resources.unwrap_or_default(),
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L748-764)
```rust
        // Pre-compute cost in case of revert.
        let execution_steps_consumed =
            n_allotted_execution_steps - execution_context.n_remaining_steps();
        // Get the receipt only in case of revert.
        let get_revert_receipt = || {
            TransactionReceipt::from_account_tx(
                self,
                &tx_context,
                &validate_state_cache.to_state_diff(),
                CallInfo::summarize_many(
                    validate_call_info.iter(),
                    &tx_context.block_context.versioned_constants,
                ),
                execution_steps_consumed,
                execution_context.sierra_gas_revert_tracker.get_gas_consumed(),
            )
        };
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L978-989)
```rust
    pub fn new_reverted(
        validate_call_info: Option<CallInfo>,
        revert_error: RevertError,
        final_cost: TransactionReceipt,
    ) -> Self {
        Self {
            validate_call_info,
            execute_call_info: None,
            revert_error: Some(revert_error),
            final_cost,
        }
    }
```

**File:** crates/blockifier/src/fee/receipt.rs (L92-103)
```rust
        let tx_resources = TransactionResources {
            starknet_resources,
            computation: ComputationResources {
                tx_extended_vm_resources: charged_resources
                    .extended_vm_resources
                    .filter_unused_cairo_primitives(),
                os_vm_resources,
                n_reverted_steps: reverted_steps,
                sierra_gas: charged_resources.gas_consumed,
                reverted_sierra_gas,
            },
        };
```

**File:** crates/apollo_rpc_execution/src/objects.rs (L123-156)
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
```

**File:** crates/blockifier/src/transaction/account_transactions_test.rs (L795-796)
```rust
    // Check that reverted steps are taken into account.
    assert!(tx_execution_info.receipt.resources.computation.n_reverted_steps > 0);
```
