### Title
User-Controlled `executionEffort` Allows Scheduled Callback Bypass via Zero Computation Limit - (File: `fvm/blueprints/scheduled_callback.go`)

---

### Summary

The `callbackArgsFromEvent` function in `fvm/blueprints/scheduled_callback.go` reads the user-supplied `executionEffort` field from the `PendingExecution` event and uses it directly as the `ComputeLimit` for the execute-callback transaction, enforcing only an upper-bound cap with no lower-bound minimum. A user who schedules a transaction with `executionEffort = 0` (or a value too small to cover basic transaction overhead) will have their execute-callback transaction created with `SetComputeLimit(0)`, causing it to fail immediately without ever invoking `scheduler.executeTransaction(id: id)` — and therefore without ever calling the user's `TransactionHandler`.

---

### Finding Description

When a scheduled transaction's timestamp is reached, the `FlowTransactionScheduler` contract emits a `PendingExecution` event containing the `executionEffort` value that was specified by the user at scheduling time. The FVM reads this event and constructs an execute-callback transaction whose compute limit is set directly to that user-controlled value.

In `callbackArgsFromEvent`:

```go
effort := uint64(cadenceEffort)

if effort > flow.DefaultMaxTransactionGasLimit {
    log.Warn().Uint64("effort", effort).Msg("effort is greater than max transaction gas limit, setting to max")
    effort = flow.DefaultMaxTransactionGasLimit
}

return uint64(cadenceId), uint64(effort), nil
```

Only a maximum cap is enforced. There is no minimum. The returned `effort` is then passed to `generateExecuteCallbacksTransaction`:

```go
tx, err := flow.NewTransactionBodyBuilder().
    AddAuthorizer(sc.ScheduledTransactionExecutor.Address).
    SetScript(script).
    AddArgument(encID).
    SetComputeLimit(effort).   // ← directly user-controlled, no floor
    Build()
```

The execute-callback script is:

```cadence
transaction(id: UInt64) {
    prepare(serviceAccount: auth(BorrowValue) &Account) {
        let scheduler = serviceAccount.storage.borrow<...>(from: FlowTransactionScheduler.storagePath)
            ?? panic("Could not borrow FlowTransactionScheduler")
        scheduler.executeTransaction(id: id)
    }
}
```

When `SetComputeLimit(0)` is used, the FVM will exhaust the computation budget before `scheduler.executeTransaction(id: id)` is ever reached. The transaction is recorded as failed, and the user's `TransactionHandler.execute()` is never invoked. The `FlowTransactionScheduler` indexer then marks the scheduled transaction as failed (any `PendingExecution` event without a corresponding `Executed` event is treated as a failure).

This is the direct Flow analog of the EIP-150 gas manipulation: the party controlling the computation budget (here, the scheduler) can set it just low enough to guarantee the callback body never executes, while the outer system transaction (the process-callback transaction) completes successfully.

---

### Impact Explanation

**Impact: High**

Any protocol or user that relies on `FlowTransactionScheduler` for trustless deferred execution — e.g., a DeFi protocol that schedules a token payment to a counterparty — can have the callback silently bypassed by setting `executionEffort = 0` at scheduling time. The `TransactionHandler` is never called, so the payment or state mutation it was supposed to perform never occurs. The counterparty loses their expected on-chain asset transfer. Because the execute-callback transaction is a system-level transaction constructed entirely by the FVM from the event data, there is no opportunity for the counterparty to detect or prevent this at execution time.

---

### Likelihood Explanation

**Likelihood: Low**

Exploiting this requires the scheduler (the party who calls `FlowTransactionScheduler.schedule(...)`) to intentionally set `executionEffort = 0`. In a self-scheduling scenario this is self-harm; the attack surface is meaningful when a protocol or intermediary schedules on behalf of a user and has an incentive to ensure the callback fails (e.g., to avoid a payment obligation). The `FlowTransactionScheduler` contract in `flow-core-contracts` may impose its own minimum-effort validation, but no such floor is enforced in the Go-layer code that constructs the execute-callback transaction.

---

### Recommendation

Enforce a minimum `executionEffort` in `callbackArgsFromEvent` sufficient to cover at least the base overhead of the execute-callback transaction script. For example:

```go
const minCallbackEffort = uint64(1000) // tune to actual base overhead

if effort < minCallbackEffort {
    log.Warn().Uint64("effort", effort).Msg("effort is below minimum, setting to minimum")
    effort = minCallbackEffort
}
```

This mirrors the recommendation in the original EIP-150 report: check the available computation budget before executing the callback.

---

### Proof of Concept

1. Attacker calls `FlowTransactionScheduler.schedule(executionEffort: 0, fees: <-vault, ...)` from an unprivileged Cadence transaction.
2. When the block timestamp passes, `scheduler.process()` emits a `PendingExecution` event with `executionEffort = 0`.
3. `callbackArgsFromEvent` (line 118–123) returns `effort = 0` — the only check is the upper-bound cap at line 120, which is not triggered.
4. `generateExecuteCallbacksTransaction` (line 98) calls `SetComputeLimit(0)`.
5. The FVM executes the resulting transaction; the computation budget is exhausted before `scheduler.executeTransaction(id: id)` is reached.
6. The transaction output carries a computation-limit-exceeded error; the `TransactionHandler.execute()` is never called.
7. The indexer in `module/state_synchronization/indexer/extended/scheduled_transactions.go` (line 391–392) detects the `PendingExecution` event has no matching `Executed` event and marks the scheduled transaction as failed.
8. Any on-chain obligation encoded in the `TransactionHandler` (e.g., a token transfer to a counterparty) is silently skipped. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/blueprints/scheduled_callback.go (L94-99)
```go
	tx, err := flow.NewTransactionBodyBuilder().
		AddAuthorizer(sc.ScheduledTransactionExecutor.Address).
		SetScript(script).
		AddArgument(encID).
		SetComputeLimit(effort).
		Build()
```

**File:** fvm/blueprints/scheduled_callback.go (L112-126)
```go
func callbackArgsFromEvent(event flow.Event) (uint64, uint64, error) {
	cadenceId, cadenceEffort, err := ParsePendingExecutionEvent(event)
	if err != nil {
		return 0, 0, err
	}

	effort := uint64(cadenceEffort)

	if effort > flow.DefaultMaxTransactionGasLimit {
		log.Warn().Uint64("effort", effort).Msg("effort is greater than max transaction gas limit, setting to max")
		effort = flow.DefaultMaxTransactionGasLimit
	}

	return uint64(cadenceId), uint64(effort), nil
}
```

**File:** model/access/systemcollection/scripts/executeScheduledTransactionTemplateV0.cdc (L1-12)
```text
import "FlowTransactionScheduler"

// Execute a scheduled transaction by the FlowTransactionScheduler contract.
// This will be called by the FVM and the transaction will be executed by their ID.
transaction(id: UInt64) {
    prepare(serviceAccount: auth(BorrowValue) &Account) {
        let scheduler = serviceAccount.storage.borrow<auth(FlowTransactionScheduler.Execute) &FlowTransactionScheduler.SharedScheduler>(from: FlowTransactionScheduler.storagePath)
            ?? panic("Could not borrow FlowTransactionScheduler")

        scheduler.executeTransaction(id: id)
    }
}
```

**File:** model/access/systemcollection/system_collection_v0.go (L77-82)
```go
		tx, err := flow.NewTransactionBodyBuilder().
			AddAuthorizer(sc.FlowServiceAccount.Address).
			SetScript(script).
			AddArgument(id).
			SetComputeLimit(effort).
			Build()
```

**File:** engine/execution/computation/computer/computer.go (L665-668)
```go
	callbackTxs, err := blueprints.ExecuteCallbacksTransactions(e.vmCtx.Chain, txn.Output().Events)
	if err != nil {
		return nil, 0, err
	}
```
