### Title
Unchecked `value` Against Sender Balance in L1→L2 Transaction Execution Causes Block-Halting Error - (File: `basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

In `execute_l1_transaction_and_notify_result`, the bootloader calls `run_single_interaction` with the transaction's user-supplied `value` field as `nominal_token_value` without first verifying that the sender's balance (after minting `to_transfer`) is sufficient to cover `value`. The `run_single_interaction` function explicitly documents this as a pre-condition callers must satisfy. When the pre-condition is violated, the resulting error is not treated as a graceful revert — it propagates as a fatal bootloader error that halts block processing.

---

### Finding Description

In `execute_l1_transaction_and_notify_result`, the execution sequence is:

1. Compute `max_fee_commitment = gas_price * gas_limit`
2. Compute `to_transfer = total_deposited - max_fee_commitment`
3. Mint `to_transfer` to `from` via `mint_base_token`
4. Call `run_single_interaction(…, &value, …)` — passing the raw transaction `value` as `nominal_token_value` [1](#0-0) [2](#0-1) [3](#0-2) 

The only balance-related check performed before this call is:

```rust
require_internal!(
    total_deposited >= tx_internal_cost,
    "Deposited amount too low",
    system
)?;
``` [4](#0-3) 

This verifies `total_deposited >= gas_price * gas_limit` only. It does **not** verify `total_deposited >= gas_price * gas_limit + value`. There is no check that `to_transfer >= value`.

`run_single_interaction` explicitly documents this as a required pre-condition:

```rust
/// Pre-condition: if [nominal_token_value] is not 0, this function
/// assumes the caller's balance has been validated. It returns an
/// internal error in case of balance underflow.
``` [5](#0-4) 

When the pre-condition is violated (i.e., `from.balance < value` after minting), `perform_transfer_if_required` returns `Err(interface_error!(BootloaderInterfaceError::TopLevelInsufficientBalance))` for the top-level `NoEE` caller: [6](#0-5) 

This error is **not** a `FatalRuntimeError`, so it is not caught by the out-of-native handler in `process_l1_transaction`. It falls through to the `_ =>` branch and propagates out of `process_l1_transaction`, halting block processing: [7](#0-6) 

---

### Impact Explanation

An L1→L2 transaction with `value > total_deposited - (gas_price * gas_limit)` — where the sender has no pre-existing L2 balance — causes `run_single_interaction` to return a `TopLevelInsufficientBalance` error. This error propagates out of `process_l1_transaction` as a `BootloaderSubsystemError`, halting block processing entirely. Since L1→L2 transactions cannot be invalidated (they are in the priority queue), a single such transaction can permanently stall the chain.

---

### Likelihood Explanation

The L1 bridge contracts are expected to enforce `total_deposited >= gas_price * gas_limit + value`. However, the ZKsync OS comment explicitly states it is supposed to double-check this invariant, yet the double-check is incomplete — it only validates the fee portion. If the L1 contracts are updated, have a bug, or if the ZKsync OS is deployed with a different L1 bridge that does not enforce this invariant, an unprivileged user submitting an L1→L2 transaction with `value > 0` and `total_deposited = gas_price * gas_limit` can trigger this path. The attacker-controlled inputs are `value` and `reserved[0]` (total deposited), both read directly from the transaction without further validation in the OS.

---

### Recommendation

Add an explicit check in `execute_l1_transaction_and_notify_result` (or in `process_l1_transaction` alongside the existing `total_deposited >= tx_internal_cost` check) that verifies:

```rust
require_internal!(
    to_transfer >= value,
    "Deposited amount insufficient to cover transaction value",
    system
)?;
```

This mirrors the comment's stated intent ("we double-check it here") and satisfies the documented pre-condition of `run_single_interaction`.

---

### Proof of Concept

1. Construct an L1→L2 priority transaction with:
   - `gas_price = 1000`, `gas_limit = 100_000` → `max_fee_commitment = 100_000_000`
   - `reserved[0]` (total_deposited) = `100_000_000` (exactly covers fees, nothing left for value)
   - `value = 1` (any non-zero value)
   - `from` = a fresh address with zero L2 balance
2. Submit this transaction to the L1 priority queue.
3. When the ZKsync OS processes the block:
   - `to_transfer = 100_000_000 - 100_000_000 = 0` → mints 0 to `from`
   - `run_single_interaction` is called with `nominal_token_value = 1`
   - `perform_transfer_if_required` finds `from.balance (0) < value (1)`
   - Returns `TopLevelInsufficientBalance` error
   - Error propagates through `execute_l1_transaction_and_notify_result` → `process_l1_transaction` → block processing halts

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L128-137)
```rust
    let tx_internal_cost = gas_price
        .checked_mul(U256::from(gas_limit))
        .ok_or(internal_error!("gp*gl"))?;
    let value = transaction.value.read();
    let total_deposited = transaction.reserved[0].read();
    require_internal!(
        total_deposited >= tx_internal_cost,
        "Deposited amount too low",
        system
    )?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L217-241)
```rust
                Err(e) => {
                    match e.root_cause() {
                        // Out of native / memory is converted to a top-level
                        // revert so post-execution L1 accounting can still run.
                        RootCause::Runtime(runtime @ RuntimeError::FatalRuntimeError(_)) => {
                            system_log!(
                                system,
                                "L1 transaction ran out of native resources or memory {runtime:?}\n"
                            );
                            resources.exhaust_ergs();
                            system.finish_global_frame(Some(&rollback_handle))?;
                            (
                                false,
                                Vec::new_in(system.get_allocator()),
                                None,
                                S::Resources::empty(),
                                memories,
                            )
                        }
                        _ => {
                            system.finish_global_frame(Some(&rollback_handle))?;
                            return Err(e);
                        }
                    }
                }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L607-613)
```rust
    let max_fee_commitment = gas_price
        .checked_mul(U256::from(transaction.gas_limit.read()))
        .ok_or(internal_error!("gp*gl"))?;
    let total_deposited = transaction.reserved[0].read();
    let to_transfer = total_deposited
        .checked_sub(max_fee_commitment)
        .ok_or(internal_error!("td-mfc"))?;
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L631-658)
```rust
    if to_transfer > U256::ZERO || Config::SIMULATION {
        resources
            .with_infinite_ergs(|inf_resources| {
                mint_base_token::<S, Config>(
                    system,
                    system_functions,
                    memories.reborrow(),
                    &to_transfer,
                    &from,
                    l1_chain_id,
                    inf_resources,
                    tracer,
                    validator,
                )
            })
            .map_err(|e| match e.root_cause() {
                RootCause::Runtime(RuntimeError::OutOfErgs(_)) => {
                    system_log!(
                        system,
                        "Out of ergs on infinite ergs: inner error was {e:?}"
                    );
                    BootloaderSubsystemError::LeafDefect(internal_error!(
                        "Out of ergs on infinite ergs"
                    ))
                }
                _ => e,
            })?;
    }
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L667-680)
```rust
    let (reverted, mut returndata) =
        match BasicBootloader::<S, ZkTransactionFlowOnlyEOA<S>>::run_single_interaction(
            system,
            system_functions,
            memories.reborrow(),
            calldata,
            &from,
            &to,
            resources_for_tx,
            &value,
            false,
            tracer,
            validator,
        ) {
```

**File:** basic_bootloader/src/bootloader/run_single_interaction.rs (L19-23)
```rust
    ///
    /// Pre-condition: if [nominal_token_value] is not 0, this function
    /// assumes the caller's balance has been validated. It returns an
    /// internal error in case of balance underflow.
    ///
```

**File:** basic_bootloader/src/bootloader/runner.rs (L374-383)
```rust
                        match caller_ee_type {
                            ExecutionEnvironmentType::NoEE => Err(interface_error!(
                                BootloaderInterfaceError::TopLevelInsufficientBalance
                            ))
                            .with_context(|| {
                                error_ctx! {
                                     "caller" => debug_format(call_request.caller),
                                     "target" => debug_format(target),
                                }
                            }),
```
