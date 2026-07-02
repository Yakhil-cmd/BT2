### Title
EVM Execution Effort Truncates to Zero for Small Gas Amounts, Allowing Execution Fee Bypass — (File: `fvm/meter/computation_meter.go`)

---

### Summary

The `TotalComputationUsed()` function right-shifts accumulated computation by 16 bits. Because `ComputationKindEVMGasUsage` carries a weight of only `3` in `MainnetExecutionEffortWeights`, any EVM transaction consuming fewer than **21,846 gas** (including a standard ETH transfer at exactly 21,000 gas) contributes **0** to the reported execution effort. That zero is forwarded directly to `DeductTransactionFees`, so the execution-effort component of the fee is never charged for those transactions.

---

### Finding Description

**Root cause — truncation in `TotalComputationUsed()`**

`fvm/meter/computation_meter.go` accumulates computation in an internal fixed-point scale and exposes the public value by right-shifting 16 bits:

```go
const MeterExecutionInternalPrecisionBytes = 16

func (m *ComputationMeter) TotalComputationUsed() uint64 {
    return m.computationUsed >> MeterExecutionInternalPrecisionBytes   // ÷ 65536
}
``` [1](#0-0) [2](#0-1) 

**Extremely small weight for EVM gas**

`MainnetExecutionEffortWeights` in `fvm/environment/meter.go` assigns:

```go
ComputationKindEVMGasUsage: 3,
``` [3](#0-2) 

This weight is **not** pre-shifted by 16 bits (unlike the default weights such as `1 << MeterExecutionInternalPrecisionBytes = 65536`). Consequently, when `meterGasUsage` in `fvm/evm/handler/handler.go` meters EVM gas:

```go
func (h *ContractHandler) meterGasUsage(res *types.Result) error {
    usage := common.ComputationUsage{
        Kind:      environment.ComputationKindEVMGasUsage,
        Intensity: res.GasConsumed,
    }
    return h.backend.MeterComputation(usage)
}
``` [4](#0-3) 

the internal accumulation is `computationUsed += 3 × gasConsumed`. For a standard ETH transfer (21,000 gas):

```
3 × 21,000 = 63,000   <   65,536
TotalComputationUsed() = 63,000 >> 16 = 0
```

**Zero propagates to fee deduction**

`deductTransactionFees()` in `fvm/transactionInvoker.go` reads this value and passes it directly to `DeductTransactionFees`:

```go
computationUsed, err := executor.env.ComputationUsed()
...
_, err = executor.env.DeductTransactionFees(
    executor.proc.Transaction.Payer,
    executor.proc.Transaction.InclusionEffort(),
    computationUsed)   // ← 0 for small EVM txs
``` [5](#0-4) 

`DeductTransactionFees` in `fvm/environment/system_contracts.go` forwards this as `executionEffort` to the on-chain `FlowFees` contract:

```go
func (sys *SystemContracts) DeductTransactionFees(
    payer flow.Address,
    inclusionEffort uint64,
    executionEffort uint64,   // ← 0
) (cadence.Value, error) { ... }
``` [6](#0-5) 

When `executionEffortCost > 0` on-chain, the execution-effort component of the fee is `executionEffort × executionEffortCost = 0 × cost = 0`.

---

### Impact Explanation

Any unprivileged user can submit Cadence transactions that invoke `EVM.run()` or `EVM.batchRun()` with EVM transactions consuming fewer than 21,846 gas (e.g., simple ETH transfers at 21,000 gas). Each such FVM transaction pays only the fixed inclusion fee and **zero** execution-effort fee, regardless of how much EVM computation was actually performed. By submitting many such transactions the attacker consumes real EVM execution resources while bypassing the execution-effort fee component — a direct analog to the BarnBridge fee-rounding bypass.

---

### Likelihood Explanation

The `MainnetExecutionEffortWeights` map is explicitly labelled for mainnet use and is loaded by the FVM on every transaction. The fee system is designed to support a non-zero `executionEffortCost` (set via governance). When that cost is non-zero, the bypass is immediately reachable by any account holder who can submit a Cadence transaction containing an EVM call — no special privileges required. The minimum EVM transaction (21,000 gas for an ETH transfer) falls below the truncation threshold, making the attack trivially constructible.

---

### Recommendation

1. **Pre-shift the EVM gas weight** so it is expressed in the same internal precision as other weights:
   ```go
   ComputationKindEVMGasUsage: 3 << MeterExecutionInternalPrecisionBytes,
   ```
   This ensures `3 × 21,000 × 65,536 >> 16 = 63,000` computation units rather than 0.

2. **Alternatively, round up** in `TotalComputationUsed()` when any EVM gas was consumed, ensuring at least 1 computation unit is reported.

3. **Audit all weights** in `MainnetExecutionEffortWeights` to confirm none are so small that typical intensities truncate to zero.

---

### Proof of Concept

1. Obtain any Flow account with sufficient FLOW to pay the inclusion fee.
2. Submit a Cadence transaction that calls `EVM.run()` with a signed EVM transaction performing a simple ETH transfer (gas limit = 21,000, gas price = 1 wei).
3. Observe the emitted `FlowFees.FeesDeducted` event: the `executionEffort` field is `0` and the `amount` equals only the inclusion fee.
4. Repeat the transaction N times; each iteration consumes 21,000 EVM gas but pays zero execution-effort fee.
5. Contrast with a Cadence-only transaction of equivalent computational cost, which correctly charges a non-zero execution-effort fee.

The attacker-controlled entry path is: unprivileged Cadence transaction → `EVM.run()` → `ContractHandler.run()` → `meterGasUsage(res)` → `MeterComputation({Kind: ComputationKindEVMGasUsage, Intensity: 21000})` → `computationUsed += 3×21000 = 63000` → `TotalComputationUsed() = 0` → `DeductTransactionFees(..., executionEffort=0)` → zero execution-effort fee charged. [7](#0-6) [4](#0-3) [5](#0-4) [8](#0-7)

### Citations

**File:** fvm/meter/computation_meter.go (L28-38)
```go
const MeterExecutionInternalPrecisionBytes = 16

type ExecutionEffortWeights map[common.ComputationKind]uint64

func (weights ExecutionEffortWeights) ComputationFromIntensities(intensities MeteredComputationIntensities) uint64 {
	var result uint64
	for kind, weight := range weights {
		intensity := uint64(intensities[kind])
		result += weight * intensity
	}
	return result >> MeterExecutionInternalPrecisionBytes
```

**File:** fvm/meter/computation_meter.go (L90-106)
```go
// MeterComputation captures computation usage and returns an error if it goes beyond the limit
func (m *ComputationMeter) MeterComputation(usage common.ComputationUsage) error {
	kind := usage.Kind
	intensity := usage.Intensity

	m.computationIntensities[kind] += intensity
	w, ok := m.params.computationWeights[kind]
	if !ok {
		return nil
	}
	m.computationUsed += w * intensity
	if m.computationUsed > m.params.computationLimit {
		return errors.NewComputationLimitExceededError(
			uint64(m.params.TotalComputationLimit()))
	}
	return nil
}
```

**File:** fvm/meter/computation_meter.go (L142-145)
```go
// TotalComputationUsed returns the total computation used
func (m *ComputationMeter) TotalComputationUsed() uint64 {
	return m.computationUsed >> MeterExecutionInternalPrecisionBytes
}
```

**File:** fvm/environment/meter.go (L60-105)
```go
// MainnetExecutionEffortWeights are the execution effort weights as they are on mainnet
var MainnetExecutionEffortWeights = meter.ExecutionEffortWeights{
	ComputationKindCreateAccount:                      2143437,
	ComputationKindBLSVerifyPOP:                       1538600,
	ComputationKindGetAccountBalance:                  485476,
	ComputationKindBLSAggregatePublicKeys:             402728,
	ComputationKindGetStorageCapacity:                 397087,
	ComputationKindGetAccountAvailableBalance:         375235,
	ComputationKindUpdateAccountContractCode:          369407,
	ComputationKindBLSAggregateSignatures:             325309,
	ComputationKindGenerateAccountLocalID:             75507,
	ComputationKindGetAccountContractNames:            32771,
	ComputationKindGetStorageUsed:                     25416,
	ComputationKindAccountKeysCount:                   24709,
	ComputationKindAllocateSlabIndex:                  15372,
	common.ComputationKindAtreeMapGet:                 8837,
	common.ComputationKindAtreeMapRemove:              7373,
	common.ComputationKindCreateArrayValue:            4364,
	common.ComputationKindCreateDictionaryValue:       3818,
	common.ComputationKindAtreeMapSet:                 3656,
	common.ComputationKindAtreeArrayInsert:            3652,
	common.ComputationKindAtreeMapReadIteration:       3325,
	ComputationKindEncodeEvent:                        2911,
	common.ComputationKindTransferCompositeValue:      2358,
	common.ComputationKindAtreeArrayAppend:            1907,
	common.ComputationKindStatement:                   1770,
	common.ComputationKindAtreeArraySet:               1737,
	common.ComputationKindFunctionInvocation:          1399,
	common.ComputationKindAtreeMapPopIteration:        1210,
	common.ComputationKindAtreeArrayPopIteration:      736,
	ComputationKindRLPDecoding:                        516,
	common.ComputationKindGraphemesIteration:          278,
	common.ComputationKindUfixParse:                   257,
	common.ComputationKindFixParse:                    223,
	common.ComputationKindLoop:                        179,
	common.ComputationKindAtreeArrayBatchConstruction: 177,
	common.ComputationKindTransferDictionaryValue:     125,
	common.ComputationKindBigIntParse:                 69,
	common.ComputationKindTransferArrayValue:          48,
	ComputationKindSetValue:                           48,
	common.ComputationKindUintParse:                   31,
	common.ComputationKindIntParse:                    28,
	ComputationKindGetValue:                           23,
	common.ComputationKindStringToLower:               5,
	ComputationKindEVMGasUsage:                        3,
}
```

**File:** fvm/evm/handler/handler.go (L714-720)
```go
func (h *ContractHandler) meterGasUsage(res *types.Result) error {
	usage := common.ComputationUsage{
		Kind:      environment.ComputationKindEVMGasUsage,
		Intensity: res.GasConsumed,
	}
	return h.backend.MeterComputation(usage)
}
```

**File:** fvm/transactionInvoker.go (L269-300)
```go
func (executor *transactionExecutor) deductTransactionFees() (err error) {
	if !executor.env.TransactionFeesEnabled() {
		return nil
	}

	computationLimit := executor.txnState.TotalComputationLimit()

	computationUsed, err := executor.env.ComputationUsed()
	if err != nil {
		return errors.NewTransactionFeeDeductionFailedError(
			executor.proc.Transaction.Payer,
			computationLimit,
			err)
	}

	if computationUsed > computationLimit {
		computationUsed = computationLimit
	}

	_, err = executor.env.DeductTransactionFees(
		executor.proc.Transaction.Payer,
		executor.proc.Transaction.InclusionEffort(),
		computationUsed)

	if err != nil {
		return errors.NewTransactionFeeDeductionFailedError(
			executor.proc.Transaction.Payer,
			computationUsed,
			err)
	}
	return nil
}
```

**File:** fvm/environment/system_contracts.go (L150-165)
```go
// DeductTransactionFees executes the fee deduction function
// on the FlowFees account.
func (sys *SystemContracts) DeductTransactionFees(
	payer flow.Address,
	inclusionEffort uint64,
	executionEffort uint64,
) (cadence.Value, error) {
	return sys.Invoke(
		deductTransactionFeeSpec,
		[]cadence.Value{
			cadence.BytesToAddress(payer.Bytes()),
			cadence.UFix64(inclusionEffort),
			cadence.UFix64(executionEffort),
		},
	)
}
```
