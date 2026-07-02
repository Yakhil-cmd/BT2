### Title
Scheduled Transaction `executionEffort = 0` Bypasses Computation Limit via FVM Fallback - (File: `fvm/blueprints/scheduled_callback.go`)

### Summary
`callbackArgsFromEvent` in `fvm/blueprints/scheduled_callback.go` only enforces an upper bound on `executionEffort` (capping at `DefaultMaxTransactionGasLimit`) but applies no lower-bound check. When a user schedules a transaction with `executionEffort = 0`, the resulting execute-callback transaction is built with `GasLimit = 0`. The FVM's `TransactionProcedure.ComputationLimit()` in `fvm/transaction.go` treats `GasLimit = 0` as "unset" and silently falls back to the context's computation limit, granting the scheduled transaction full computation capacity despite the user declaring zero effort and paying minimal or zero fees.

### Finding Description
The Flow scheduled-transaction pipeline works as follows:

1. A user calls `FlowTransactionScheduler.schedule()` with an `executionEffort` value and pays upfront fees proportional to that effort.
2. When the scheduled timestamp is reached, the `process()` system transaction emits `PendingExecution` events containing `id` and `executionEffort`.
3. The FVM calls `callbackArgsFromEvent()` to decode the event and extract the effort value.
4. An execute-callback transaction is constructed with `SetComputeLimit(effort)`.
5. The FVM executes this transaction, which calls `scheduler.executeTransaction(id: id)`.

The vulnerability is in steps 3–4. In `fvm/blueprints/scheduled_callback.go`, `callbackArgsFromEvent` only checks the upper bound:

```go
effort := uint64(cadenceEffort)
if effort > flow.DefaultMaxTransactionGasLimit {
    effort = flow.DefaultMaxTransactionGasLimit
}
```

No lower-bound check exists. When `effort = 0`, `generateExecuteCallbacksTransaction` calls `SetComputeLimit(0)`, setting `GasLimit = 0` on the transaction body.

In `fvm/transaction.go`, `ComputationLimit()` treats `GasLimit = 0` as "unset" and falls back:

```go
computationLimit := proc.Transaction.GasLimit
if computationLimit == 0 {
    computationLimit = ctx.ComputationLimit
    if computationLimit == 0 {
        computationLimit = DefaultComputationLimit
    }
}
```

The execute-callback transaction therefore runs with the full context computation limit — not zero. The user paid fees based on `executionEffort = 0` (minimal or zero fees) but receives the full default computation budget for their scheduled transaction execution.

The same missing lower-bound check exists in the v0 system-collection path at `model/access/systemcollection/system_collection_v0.go` in `callbackArgsFromEvent`.

### Impact Explanation
A malicious user can schedule a transaction with `executionEffort = 0`, paying minimal or zero upfront fees, while the FVM executes the callback transaction with the full default computation limit. Concretely:

- **Fee bypass**: The user pays fees proportional to `executionEffort = 0` but consumes computation proportional to `DefaultComputationLimit` (or `ctx.ComputationLimit`).
- **Resource theft**: Computation consumed by the attacker's callback is charged to the system (service-account payer of the execute-callback transaction), not to the attacker.
- **Starvation risk**: If many such transactions are scheduled, they can consume the system collection's computation budget, causing legitimate scheduled transactions to fail or be delayed.

### Likelihood Explanation
The Go layer has no minimum-effort validation. The only remaining guard would be a minimum-effort check inside the `FlowTransactionScheduler` Cadence contract itself (not visible in this repository). If the contract permits `executionEffort = 0` — which is consistent with the absence of any Go-layer rejection — the vulnerability is directly exploitable by any unprivileged user who can call `FlowTransactionScheduler.schedule()`. No special privileges, staked nodes, or key compromise are required.

### Recommendation
Add a minimum-effort check in `callbackArgsFromEvent` in both `fvm/blueprints/scheduled_callback.go` and `model/access/systemcollection/system_collection_v0.go`:

```go
if effort == 0 {
    return 0, 0, fmt.Errorf("executionEffort must be greater than 0")
}
```

Alternatively, ensure `TransactionProcedure.ComputationLimit()` does not silently fall back to the default for system-collection execute-callback transactions when `GasLimit = 0`; instead, it should treat `GasLimit = 0` as an explicit zero limit and abort the transaction.

### Proof of Concept
1. Attacker calls `FlowTransactionScheduler.schedule()` with `executionEffort = 0` and `fees = 0` (or the minimum the contract accepts).
2. When the timestamp is reached, `process()` emits a `PendingExecution` event with `executionEffort = 0`.
3. `callbackArgsFromEvent` in `fvm/blueprints/scheduled_callback.go` returns `effort = 0` — no minimum check fires.
4. `generateExecuteCallbacksTransaction` calls `SetComputeLimit(0)`, producing a transaction body with `GasLimit = 0`.
5. `TransactionProcedure.ComputationLimit()` in `fvm/transaction.go` sees `GasLimit == 0` and falls back to `ctx.ComputationLimit` (e.g., `DefaultComputationLimit`).
6. The execute-callback transaction runs with the full default computation limit.
7. The attacker's `executeTransaction` callback executes with full computation despite paying zero fees.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/blueprints/scheduled_callback.go (L83-105)
```go
func generateExecuteCallbacksTransaction(
	sc *systemcontracts.SystemContracts,
	script []byte,
	id uint64,
	effort uint64,
) (*flow.TransactionBody, error) {
	encID, err := jsoncdc.Encode(cadence.UInt64(id))
	if err != nil {
		return nil, fmt.Errorf("failed to encode id: %w", err)
	}

	tx, err := flow.NewTransactionBodyBuilder().
		AddAuthorizer(sc.ScheduledTransactionExecutor.Address).
		SetScript(script).
		AddArgument(encID).
		SetComputeLimit(effort).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to construct execute callback transactions: %w", err)
	}

	return tx, nil
}
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

**File:** fvm/transaction.go (L41-56)
```go
func (proc *TransactionProcedure) ComputationLimit(ctx Context) uint64 {
	// TODO for BFT (enforce max computation limit, already checked by collection nodes)
	// TODO replace tx.Gas with individual limits for computation and memory

	// decide computation limit
	computationLimit := proc.Transaction.GasLimit
	// if the computation limit is set to zero by user, fallback to the gas limit set by the context
	if computationLimit == 0 {
		computationLimit = ctx.ComputationLimit
		// if the context computation limit is also zero, fallback to the default computation limit
		if computationLimit == 0 {
			computationLimit = DefaultComputationLimit
		}
	}
	return computationLimit
}
```

**File:** model/access/systemcollection/system_collection_v0.go (L121-140)
```go
func (b *builderV0) callbackArgsFromEvent(event flow.Event) ([]byte, uint64, error) {
	cadenceId, cadenceEffort, err := blueprints.ParsePendingExecutionEvent(event)
	if err != nil {
		return nil, 0, err
	}

	effort := uint64(cadenceEffort)

	if effort > flow.DefaultMaxTransactionGasLimit {
		log.Warn().Uint64("effort", effort).Msg("effort is greater than max transaction gas limit, setting to max")
		effort = flow.DefaultMaxTransactionGasLimit
	}

	encID, err := jsoncdc.Encode(cadenceId)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to encode id: %w", err)
	}

	return encID, uint64(effort), nil
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
