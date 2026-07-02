### Title
User-Controlled `executionEffort = 0` Bypasses Computation Fees in Scheduled Transaction Execution - (`fvm/blueprints/scheduled_callback.go`)

### Summary

The `callbackArgsFromEvent()` function in `fvm/blueprints/scheduled_callback.go` enforces only an upper bound on the `executionEffort` value read from the `PendingExecution` event, but no lower bound. When a user schedules a transaction with `executionEffort = 0`, the resulting execution transaction is built with `GasLimit = 0`. The FVM's `ComputationLimit()` method treats `GasLimit = 0` as a sentinel meaning "use the context default", so the scheduled transaction executes with the full default computation limit while the user paid fees calculated against zero effort.

### Finding Description

**Attacker-controlled entry path:**

Any unprivileged account can call `FlowTransactionScheduler.schedule()` and supply an arbitrary `executionEffort` value, including `0`. This value is stored in the scheduler contract and later emitted in a `PendingExecution` event when the scheduled timestamp is reached.

**Root cause in Go code:**

`callbackArgsFromEvent()` reads `executionEffort` from the event and applies only a ceiling check:

```go
// fvm/blueprints/scheduled_callback.go lines 112-126
func callbackArgsFromEvent(event flow.Event) (uint64, uint64, error) {
    cadenceId, cadenceEffort, err := ParsePendingExecutionEvent(event)
    ...
    effort := uint64(cadenceEffort)

    if effort > flow.DefaultMaxTransactionGasLimit {   // only upper bound
        effort = flow.DefaultMaxTransactionGasLimit
    }

    return uint64(cadenceId), uint64(effort), nil      // 0 passes through unchecked
}
``` [1](#0-0) 

The returned `effort` value (potentially `0`) is then passed directly to `generateExecuteCallbacksTransaction()`, which sets it as the transaction's `GasLimit`:

```go
// fvm/blueprints/scheduled_callback.go lines 94-99
tx, err := flow.NewTransactionBodyBuilder().
    AddAuthorizer(sc.ScheduledTransactionExecutor.Address).
    SetScript(script).
    AddArgument(encID).
    SetComputeLimit(effort).   // effort == 0 when user supplied 0
    Build()
``` [2](#0-1) 

**FVM behavior when `GasLimit = 0`:**

`TransactionProcedure.ComputationLimit()` explicitly treats `GasLimit = 0` as "no user-specified limit" and falls back to the context or global default:

```go
// fvm/transaction.go lines 41-56
func (proc *TransactionProcedure) ComputationLimit(ctx Context) uint64 {
    computationLimit := proc.Transaction.GasLimit
    if computationLimit == 0 {
        computationLimit = ctx.ComputationLimit
        if computationLimit == 0 {
            computationLimit = DefaultComputationLimit
        }
    }
    return computationLimit
}
``` [3](#0-2) 

This is confirmed by the existing test comment: `// gas limit of zero is ignored by runtime`. [4](#0-3) 

The same V0 builder path in `model/access/systemcollection/system_collection_v0.go` has the identical missing minimum check: [5](#0-4) 

### Impact Explanation

A user who schedules a transaction with `executionEffort = 0` pays fees calculated against zero effort (minimal or zero fees, depending on the `FlowTransactionScheduler` contract's fee formula). The execution transaction is then issued with `GasLimit = 0`, which the FVM silently upgrades to the full default computation limit. The user therefore obtains an unbounded computation budget for the cost of a zero-effort scheduling fee — a direct fee bypass that allows unauthorized consumption of protocol computation resources.

### Likelihood Explanation

Any account can call `FlowTransactionScheduler.schedule()` with `executionEffort = 0`. The Go-layer validation in `callbackArgsFromEvent()` is the only enforcement point between the on-chain event value and the execution transaction's `GasLimit`. No minimum is enforced there. The Cadence contract itself may impose a minimum, but that is not visible in this repository and cannot be relied upon as the sole guard; the Go layer must also validate.

### Recommendation

Add a minimum enforcement in `callbackArgsFromEvent()` (and the equivalent V0 path) before the value is used as a `GasLimit`. A value of `0` must never be forwarded because the FVM treats it as "unlimited":

```go
const minCallbackEffort = uint64(1)

if effort == 0 {
    return 0, 0, fmt.Errorf("effort must be greater than 0")
}
```

Additionally, consider enforcing a protocol-level minimum that is large enough to cover the overhead of the executor script itself, so that a trivially small effort cannot be used to cause guaranteed execution failures that waste block space while consuming pre-paid fees.

### Proof of Concept

1. Deploy a `TransactionHandler` contract and call `FlowTransactionScheduler.schedule()` with `executionEffort: UInt64(0)` and a non-zero fee vault.
2. Wait for the scheduled timestamp to be reached. The `process()` system transaction emits a `PendingExecution` event with `executionEffort = 0`.
3. `callbackArgsFromEvent()` returns `effort = 0` (no minimum check).
4. `generateExecuteCallbacksTransaction()` builds a transaction with `SetComputeLimit(0)`.
5. The FVM executes the transaction; `ComputationLimit()` returns `ctx.ComputationLimit` (or `DefaultComputationLimit`) because `GasLimit == 0`.
6. The handler's `execute()` function runs with the full default computation budget, despite the user having paid fees for zero effort.

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

**File:** fvm/fvm_blockcontext_test.go (L933-940)
```go
		{
			label:    "Zero",
			script:   gasLimitScript(100),
			gasLimit: 0,
			check: func(t *testing.T, output fvm.ProcedureOutput) {
				// gas limit of zero is ignored by runtime
				require.NoError(t, output.Err)
			},
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
