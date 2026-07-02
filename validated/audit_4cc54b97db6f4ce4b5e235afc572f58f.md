### Title
`ComputationRemaining` Returns Incorrect Value Due to uint64 Underflow and Dead Guard — (`fvm/meter/computation_meter.go`)

### Summary
`ComputationRemaining` in `fvm/meter/computation_meter.go` performs an unsigned integer subtraction `m.params.computationLimit - m.computationUsed` without first checking whether `computationUsed` exceeds `computationLimit`. Because both operands are `uint64`, the subtraction silently wraps around to a very large value when the limit is exceeded. The intended guard `if remainingComputationUsage <= 0` is dead code for `uint64` (a `uint64` is always ≥ 0), so it never fires. The function therefore returns a near-`MaxUint64` value instead of `0` whenever the computation budget is exhausted.

### Finding Description
In `fvm/meter/computation_meter.go`, `ComputationRemaining` is defined as:

```go
func (m *ComputationMeter) ComputationRemaining(kind common.ComputationKind) uint64 {
    w, ok := m.params.computationWeights[kind]
    if !ok || w == 0 {
        return math.MaxUint64
    }

    remainingComputationUsage := m.params.computationLimit - m.computationUsed  // ← underflows when used > limit
    if remainingComputationUsage <= 0 {                                          // ← dead code: uint64 ≥ 0 always
        return 0
    }

    return remainingComputationUsage / w
}
``` [1](#0-0) 

Both `computationLimit` and `computationUsed` are `uint64`: [2](#0-1) [3](#0-2) 

`MeterComputation` increments `computationUsed` **before** checking the limit, so `computationUsed` can legitimately exceed `computationLimit`:

```go
m.computationUsed += w * intensity
if m.computationUsed > m.params.computationLimit {
    return errors.NewComputationLimitExceededError(...)
}
``` [4](#0-3) 

After that point, `m.params.computationLimit - m.computationUsed` wraps to a value near `math.MaxUint64`. The guard `if remainingComputationUsage <= 0` is unreachable for `uint64`, so the function returns `math.MaxUint64 / w` — a huge positive number — instead of `0`.

`ComputationRemaining` is consumed in the EVM backend and handler to determine how much EVM gas to allocate to an operation: [5](#0-4) [6](#0-5) 

When the Flow computation budget is already exhausted, `ComputationRemaining` reports a near-infinite budget, which can be forwarded as the EVM gas limit for subsequent EVM calls within the same transaction context.

### Impact Explanation
Any transaction that has already exceeded its Flow computation limit will cause `ComputationRemaining` to return a near-`MaxUint64` value. If this value is used to set the EVM gas limit for a sub-call (as done in `fvm/evm/handler/handler.go` and `fvm/evm/backends/wrappedEnv.go`), the EVM sub-call may be granted far more gas than the remaining Flow budget permits. This breaks the intended computation-limit enforcement for EVM operations and can allow EVM execution to consume resources beyond the declared transaction gas limit.

### Likelihood Explanation
Any transaction that triggers a computation-limit-exceeded error — a routine occurrence for any transaction that runs out of gas — leaves `computationUsed > computationLimit` in the meter. If `ComputationRemaining` is subsequently queried (e.g., to gate an EVM call), the underflow fires unconditionally. No special privileges are required; any unprivileged transaction sender can trigger this path by submitting a transaction that exhausts its computation budget.

### Recommendation
Replace the subtraction-then-guard pattern with an explicit pre-check:

```go
func (m *ComputationMeter) ComputationRemaining(kind common.ComputationKind) uint64 {
    w, ok := m.params.computationWeights[kind]
    if !ok || w == 0 {
        return math.MaxUint64
    }
    if m.computationUsed >= m.params.computationLimit {
        return 0
    }
    return (m.params.computationLimit - m.computationUsed) / w
}
```

This eliminates the underflow and removes the dead `<= 0` guard.

### Proof of Concept
1. Submit a Flow transaction that performs enough Cadence statements to exceed its `GasLimit`.
2. `MeterComputation` increments `computationUsed` past `computationLimit` and returns `NewComputationLimitExceededError`.
3. Before the transaction is fully aborted, any call to `ComputationRemaining` (e.g., from the EVM handler to size an EVM sub-call's gas) executes `computationLimit - computationUsed` as `uint64`, wrapping to ~`MaxUint64`.
4. The guard `if remainingComputationUsage <= 0` never fires (uint64 ≥ 0 always).
5. The EVM sub-call receives a gas limit of `~MaxUint64 / w` instead of `0`, bypassing the intended computation cap. [7](#0-6)

### Citations

**File:** fvm/meter/computation_meter.go (L41-44)
```go
type ComputationMeterParameters struct {
	computationLimit   uint64
	computationWeights ExecutionEffortWeights
}
```

**File:** fvm/meter/computation_meter.go (L76-81)
```go
type ComputationMeter struct {
	params ComputationMeterParameters

	computationUsed        uint64
	computationIntensities MeteredComputationIntensities
}
```

**File:** fvm/meter/computation_meter.go (L100-104)
```go
	m.computationUsed += w * intensity
	if m.computationUsed > m.params.computationLimit {
		return errors.NewComputationLimitExceededError(
			uint64(m.params.TotalComputationLimit()))
	}
```

**File:** fvm/meter/computation_meter.go (L122-135)
```go
func (m *ComputationMeter) ComputationRemaining(kind common.ComputationKind) uint64 {
	w, ok := m.params.computationWeights[kind]
	// if the weight is 0 or not set return max uint64
	if !ok || w == 0 {
		return math.MaxUint64
	}

	remainingComputationUsage := m.params.computationLimit - m.computationUsed
	if remainingComputationUsage <= 0 {
		return 0
	}

	return remainingComputationUsage / w
}
```

**File:** fvm/evm/backends/wrappedEnv.go (L1-1)
```go
package backends
```

**File:** fvm/evm/handler/handler.go (L1-1)
```go
package handler
```
