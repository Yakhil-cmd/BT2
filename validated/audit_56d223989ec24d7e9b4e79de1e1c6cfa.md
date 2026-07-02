### Title
Uint64 Underflow in `ComputationRemaining` Bypasses EVM Batch Gas Pre-Check - (File: fvm/meter/computation_meter.go)

### Summary
`ComputationRemaining` in `fvm/meter/computation_meter.go` contains a dead guard `if remainingComputationUsage <= 0` on a `uint64` variable. When `computationUsed` exceeds `computationLimit` (which legitimately occurs after `Merge`), the subtraction wraps to a huge value and the guard never fires. The inflated return value is consumed directly by `batchRun` in `fvm/evm/handler/handler.go` as the available EVM gas budget, allowing an unprivileged transaction sender to run EVM batch transactions beyond their actual computation budget.

### Finding Description

`ComputationRemaining` computes remaining gas as:

```go
remainingComputationUsage := m.params.computationLimit - m.computationUsed
if remainingComputationUsage <= 0 {
    return 0
}
return remainingComputationUsage / w
```

`remainingComputationUsage` is `uint64`. The comparison `<= 0` is always `false` for any `uint64` value — Go does not allow a `uint64` to be negative. When `m.computationUsed > m.params.computationLimit`, the subtraction silently wraps around to a value near `math.MaxUint64`, and the intended guard is never taken. [1](#0-0) 

The state `computationUsed > computationLimit` is reachable without error through `Merge`:

```go
func (m *ComputationMeter) Merge(child ComputationMeter) {
    m.computationUsed = m.computationUsed + child.computationUsed
    ...
}
```

`Merge` performs no limit check and returns no error. The test suite explicitly documents and accepts this: *"merge hits limit, but is accepted."* [2](#0-1) 

The corrupted return value of `ComputationRemaining` flows directly into `batchRun`:

```go
remainingGasLimit := h.backend.ComputationRemaining(environment.ComputationKindEVMGasUsage)
...
if remainingGasLimit < txGasLimit {
    return nil, types.ErrInsufficientComputation
}
remainingGasLimit -= txGasLimit
``` [3](#0-2) 

When `remainingGasLimit` is `~MaxUint64` due to underflow, the check `remainingGasLimit < txGasLimit` passes for any realistic `txGasLimit`, and the batch proceeds. The EVM execution itself runs with metering disabled:

```go
h.backend.RunWithMeteringDisabled(func() {
    res, err = blk.BatchRunTransactions(txs)
})
``` [4](#0-3) 

This means the pre-check in `batchRun` is the **only** gate on EVM gas consumption. Bypassing it allows EVM transactions to execute with no effective computation budget.

### Impact Explanation

An unprivileged transaction sender can execute EVM batch transactions beyond their paid computation budget. Because `RunWithMeteringDisabled` suppresses all FVM metering during EVM execution, and the pre-check is the sole enforcement point, the attacker obtains free EVM computation. In a fee-based system this constitutes unauthorized resource consumption — the direct analog to the Mythos.sol refund theft where an unchecked arithmetic path allows an attacker to extract more value than entitled.

### Likelihood Explanation

The trigger condition (`computationUsed > computationLimit` after `Merge`) is a documented, tested, and accepted state in the FVM meter. Any Cadence transaction that creates nested execution contexts whose merged computation exceeds the parent limit reaches this state. A knowledgeable user can craft such a transaction and immediately follow it with an `EVM.batchRun` call. No privileged role, leaked key, or staked node is required — only the ability to submit a Cadence transaction, which is open to any network participant.

### Recommendation

Replace the dead `uint64` guard with an explicit signed comparison or a pre-subtraction check:

```go
// Before subtracting, check if already over limit
if m.computationUsed >= m.params.computationLimit {
    return 0
}
remainingComputationUsage := m.params.computationLimit - m.computationUsed
return remainingComputationUsage / w
```

Additionally, `Merge` should either enforce the limit and return an error, or `batchRun` should independently verify that `computationUsed <= computationLimit` before trusting the value returned by `ComputationRemaining`.

### Proof of Concept

1. Craft a Cadence transaction with a gas limit `L`.
2. Inside the transaction, execute nested Cadence code that consumes computation `C₁` in the parent context and `C₂` in a child context, where `C₁ + C₂ > L` (achievable because `Merge` does not enforce the limit).
3. After the merge, `computationUsed = C₁ + C₂ > computationLimit = L`.
4. Call `EVM.batchRun` with EVM transactions whose total `txGasLimit` is large (e.g., `math.MaxUint64 / 2`).
5. `ComputationRemaining` computes `L - (C₁+C₂)` as a `uint64`, wrapping to `~MaxUint64 - (C₁+C₂-L)`.
6. The check `remainingGasLimit < txGasLimit` evaluates to `false` (huge value is not less than the requested gas).
7. `batchRun` proceeds, executing the EVM transactions with `RunWithMeteringDisabled`, consuming EVM computation with no FVM budget enforcement. [5](#0-4) [6](#0-5)

### Citations

**File:** fvm/meter/computation_meter.go (L121-135)
```go
// ComputationRemaining returns the remaining computation (intensity) left in the transaction for the given type
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

**File:** fvm/meter/computation_meter.go (L147-153)
```go
func (m *ComputationMeter) Merge(child ComputationMeter) {
	m.computationUsed = m.computationUsed + child.computationUsed

	for key, intensity := range child.computationIntensities {
		m.computationIntensities[key] += intensity
	}
}
```

**File:** fvm/evm/handler/handler.go (L296-325)
```go
func (h *ContractHandler) batchRun(rlpEncodedTxs [][]byte) (_ []*types.Result, err error) {
	defer func() {
		if err == nil {
			// Invalidate drycall cache if EVM state is changed (batchRun is successful).
			h.invalidateDryCallCache()
		}
	}()

	// step 1 - transaction decoding and check that enough evm gas is available in the FVM transaction

	// remainingGasLimit is the remaining EVM gas available in hte FVM transaction
	remainingGasLimit := h.backend.ComputationRemaining(environment.ComputationKindEVMGasUsage)
	batchLen := len(rlpEncodedTxs)
	txs := make([]*gethTypes.Transaction, batchLen)
	for i, rlpEncodedTx := range rlpEncodedTxs {
		tx, err := h.decodeTransaction(rlpEncodedTx)
		// if any tx fails decoding revert the batch
		if err != nil {
			return nil, err
		}

		txs[i] = tx

		// step 2 - check if enough computation is available
		txGasLimit := tx.Gas()
		if remainingGasLimit < txGasLimit {
			return nil, types.ErrInsufficientComputation
		}
		remainingGasLimit -= txGasLimit
	}
```

**File:** fvm/evm/handler/handler.go (L346-350)
```go
	h.backend.RunWithMeteringDisabled(
		func() {
			res, err = blk.BatchRunTransactions(txs)
		},
	)
```
