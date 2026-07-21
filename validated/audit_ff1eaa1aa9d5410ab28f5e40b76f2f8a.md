Looking at the full execution path, I need to trace exactly what the bouncer sees for a reverted L1 handler vs. what the OS prover must prove.

The code evidence is conclusive. Here is the full analysis.

---

### Title
Reverted L1 Handler Transactions Report Zero Computation to the Bouncer, Enabling Block Overfill — (`crates/blockifier/src/transaction/l1_handler_transaction.rs`)

### Summary

When an L1 handler execution fails, `execute_raw` calls `TransactionReceipt::reverted_l1_handler`, which hardcodes all computation resources to zero. The bouncer then records near-zero `sierra_gas` and `proving_gas` weights for the transaction, while the Starknet OS still executes and must prove the full computation trace. An unprivileged attacker who can send L1→L2 messages can craft handlers that run maximum computation before reverting, filling a block with transactions whose true proving cost is invisible to the bouncer.

### Finding Description

**Execution path for a reverted L1 handler:**

In `execute_raw`, when `run_execute` returns `Err(execution_error)` (line 132), the code calls:

```rust
let receipt = TransactionReceipt::reverted_l1_handler(&tx_context, l1_handler_payload_size);
``` [1](#0-0) 

`reverted_l1_handler` delegates to `from_l1_handler` with `ExecutionSummary::default()` and `StateChanges::default()`:

```rust
pub fn reverted_l1_handler(...) -> Self {
    Self::from_l1_handler(tx_context, l1_handler_payload_size,
        ExecutionSummary::default(),   // ← all computation zeroed
        &StateChanges::default(),
    )
}
``` [2](#0-1) 

`from_l1_handler` then hardcodes both revert fields:

```rust
reverted_steps: 0,
reverted_sierra_gas: GasAmount(0),
``` [3](#0-2) 

Because `ExecutionSummary::default()` is passed, `charged_resources.gas_consumed` and `charged_resources.extended_vm_resources` are also zero. The resulting `ComputationResources` has every field at zero except the OS overhead computed from `get_additional_os_tx_resources`.

**What the bouncer sees:**

`transaction_executor.rs` feeds the receipt directly to `bouncer.try_update`:

```rust
lock_bouncer(&self.bouncer).try_update(
    &transactional_state,
    &tx_state_changes_keys,
    &tx_execution_info.summarize(&self.block_context.versioned_constants),  // empty
    &tx_execution_info.summarize_builtins(),                                 // empty
    &tx_execution_info.receipt.resources,                                    // zero computation
    &self.block_context.versioned_constants,
    tx_execution_info.receipt.gas.l2_gas,
)?;
``` [4](#0-3) 

Because `execute_call_info` is `None` for a reverted L1 handler, both `summarize()` and `summarize_builtins()` return empty structures. `get_tx_weights` then computes:

```rust
let vm_resources = &tx_resources.computation.total_extended_vm_resources() + &patricia_update_resources;
// total_extended_vm_resources() = tx_extended_vm_resources (0) + os_vm_resources (OS overhead only)

let sierra_gas = tx_resources.computation.sierra_gas;  // 0
``` [5](#0-4) [6](#0-5) 

The bouncer's `sierra_gas` and `proving_gas` weights for a reverted L1 handler are therefore only the OS overhead — regardless of how much computation the handler performed before reverting.

**What the OS actually proves:**

The Starknet OS Cairo code executes L1 handlers with `non_reverting_select_execute_entry_point_func`:

```cairo
let remaining_gas = L1_HANDLER_L2_GAS_MAX_AMOUNT;
non_reverting_select_execute_entry_point_func{remaining_gas=remaining_gas}(
    block_context=block_context, execution_context=tx_execution_context
);
``` [7](#0-6) 

The OS executes the full computation trace up to `L1_HANDLER_L2_GAS_MAX_AMOUNT` and must prove it. The bouncer's zero-weight accounting for reverted L1 handlers does not reflect this proving cost.

**Contrast with account transactions:**

For account transactions that revert, the actual consumed steps and sierra gas are captured and passed to `from_account_tx`:

```rust
let execution_steps_consumed = n_allotted_execution_steps - execution_context.n_remaining_steps();
let get_revert_receipt = || {
    TransactionReceipt::from_account_tx(
        self, &tx_context, ...,
        execution_steps_consumed,
        execution_context.sierra_gas_revert_tracker.get_gas_consumed(),
    )
};
``` [8](#0-7) 

L1 handlers have no equivalent mechanism; the revert path unconditionally discards all execution resources.

### Impact Explanation

The bouncer's `sierra_gas` and `proving_gas` block-capacity dimensions are the primary guards against block overfill. A block filled with reverted L1 handlers — each consuming up to `l1_handler_max_amount_bounds.l2_gas` of computation — will appear nearly empty to the bouncer while requiring the prover to prove the full computation for every handler. This can cause the prover to receive a block it cannot prove within its resource budget, breaking liveness.

### Likelihood Explanation

Sending L1→L2 messages requires only an L1 transaction to the Starknet core contract — no special privileges. A contract deployed on L2 can be written to consume maximum gas before reverting. The attacker pays only L1 gas for the messages; the L2 computation cost is borne by the sequencer/prover.

### Recommendation

1. Capture actual execution resources before aborting the transactional state in the revert path of `execute_raw`, analogously to how account transactions capture `execution_steps_consumed` and `sierra_gas_revert_tracker.get_gas_consumed()`.
2. Pass the captured resources to `from_l1_handler` (or a new `reverted_l1_handler_with_resources` variant) so the receipt and bouncer weights reflect the true computation cost.
3. Remove the hardcoded `reverted_steps: 0` / `reverted_sierra_gas: GasAmount(0)` in `from_l1_handler` for the revert path, or add an assertion that this path is only reached when no computation was performed.

### Proof of Concept

1. Deploy a Cairo 1 contract on L2 with an L1-handler entry point that loops until it exhausts `l1_handler_max_amount_bounds.l2_gas`, then reverts (e.g., via `assert(false, 'revert')`).
2. Send N L1→L2 messages targeting this handler, where N is chosen so that N × (OS overhead gas) < `block_max_capacity.sierra_gas` but N × `l1_handler_max_amount_bounds.l2_gas` >> `block_max_capacity.sierra_gas`.
3. Observe that the sequencer includes all N transactions in a single block (bouncer does not reject them).
4. Assert `receipt.resources.computation.n_reverted_steps == 0` and `receipt.resources.computation.reverted_sierra_gas == GasAmount(0)` for each reverted handler.
5. Observe that the prover fails or times out on the resulting block.

### Citations

**File:** crates/blockifier/src/transaction/l1_handler_transaction.rs (L132-141)
```rust
            Err(execution_error) => {
                execution_state.abort();
                let receipt =
                    TransactionReceipt::reverted_l1_handler(&tx_context, l1_handler_payload_size);
                Ok(l1_handler_tx_execution_info(
                    None,
                    receipt,
                    Some(gen_tx_execution_error_trace(&execution_error).into()),
                ))
            }
```

**File:** crates/blockifier/src/fee/receipt.rs (L148-152)
```rust
            tx_type: TransactionType::L1Handler,
            reverted_steps: 0,
            reverted_sierra_gas: GasAmount(0),
            has_client_side_proof: false,
        })
```

**File:** crates/blockifier/src/fee/receipt.rs (L155-166)
```rust
    /// Computes the receipt of a reverted L1 handler transaction.
    pub fn reverted_l1_handler(
        tx_context: &TransactionContext,
        l1_handler_payload_size: usize,
    ) -> Self {
        Self::from_l1_handler(
            tx_context,
            l1_handler_payload_size,
            ExecutionSummary::default(),
            &StateChanges::default(),
        )
    }
```

**File:** crates/blockifier/src/blockifier/transaction_executor.rs (L163-174)
```rust
            Ok(tx_execution_info) => {
                let state_diff = transactional_state.to_state_diff()?.state_maps;
                let tx_state_changes_keys = state_diff.keys();
                lock_bouncer(&self.bouncer).try_update(
                    &transactional_state,
                    &tx_state_changes_keys,
                    &tx_execution_info.summarize(&self.block_context.versioned_constants),
                    &tx_execution_info.summarize_builtins(),
                    &tx_execution_info.receipt.resources,
                    &self.block_context.versioned_constants,
                    tx_execution_info.receipt.gas.l2_gas,
                )?;
```

**File:** crates/blockifier/src/bouncer.rs (L856-860)
```rust
        versioned_constants,
    );
    let sierra_gas = tx_resources.computation.sierra_gas;

    vm_resources_sierra_gas = vm_resources_sierra_gas.checked_add_panic_on_overflow(sierra_gas);
```

**File:** crates/blockifier/src/bouncer.rs (L928-929)
```rust
    let vm_resources =
        &tx_resources.computation.total_extended_vm_resources() + &patricia_update_resources;
```

**File:** crates/apollo_starknet_os_program/src/cairo/starkware/starknet/core/os/execution/transaction_impls.cairo (L445-448)
```text
    let remaining_gas = L1_HANDLER_L2_GAS_MAX_AMOUNT;
    non_reverting_select_execute_entry_point_func{remaining_gas=remaining_gas}(
        block_context=block_context, execution_context=tx_execution_context
    );
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
