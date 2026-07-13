### Title
Missing Input Length Guard in `BankContract.RequiredGas` and `BankContract.Run` Enables Free DoS via Panic - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
`BankContract.RequiredGas` and `BankContract.Run` both perform an unchecked 4-byte slice on the caller-supplied input before any length validation. Sending fewer than 4 bytes to the bank precompile address triggers a Go runtime panic (index out of range). Ethermint's EVM runtime silently recovers all panics inside precompile execution and does not charge gas for the failed call, giving an unprivileged attacker a free, infinitely repeatable denial-of-service primitive.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, both entry points into the bank precompile slice the input at offset `[:4]` without a prior length check:

```go
// RequiredGas — line 84
func (bc *BankContract) RequiredGas(input []byte) uint64 {
    baseCost := uint64(len(input)) * bc.kvGasConfig.WriteCostPerByte
    var methodID [4]byte
    copy(methodID[:], input[:4])   // ← panics if len(input) < 4
    ...
}

// Run — line 105
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
    methodID := contract.Input[:4]  // ← panics if len(contract.Input) < 4
    ...
}
``` [1](#0-0) [2](#0-1) 

Every other Cronos precompile already has the guard. `IcaContract.RequiredGas` and `IcaContract.Run` both check `len(input) < 4` before slicing: [3](#0-2) [4](#0-3) 

`RelayerContract.RequiredGas` and `RelayerContract.Run` do the same: [5](#0-4) [6](#0-5) 

`BankContract` is the sole precompile that omits this guard in both methods. [1](#0-0) 

The bank precompile is registered at address `0x0000000000000000000000000000000000000064` and is reachable by any EVM caller. [7](#0-6) 

### Impact Explanation

**High — Permanent or long-lived inability for honest users or validators to process valid transactions under normal network assumptions.**

Ethermint's EVM runtime wraps precompile execution in a deferred panic recovery. A panic inside `RequiredGas` or `Run` is silently caught; the transaction is marked as failed and **no gas is charged to the sender**. An attacker can therefore submit an unbounded stream of zero-cost transactions to the bank precompile, saturating the mempool and block-processing pipeline without paying any fees. Because the cost to the attacker is zero and the cost to the network is non-zero (panic recovery, mempool churn, block space consumed), this is a sustainable, unprivileged DoS.

### Likelihood Explanation

The bank precompile address is a well-known, publicly documented constant. Any EVM-capable wallet or script can craft a transaction with 0–3 bytes of calldata to that address. No special privilege, key, or prior state is required. The attack is trivially automatable.

### Recommendation

Add the same length guard that `IcaContract` and `RelayerContract` already use, in both `RequiredGas` and `Run`:

```go
func (bc *BankContract) RequiredGas(input []byte) uint64 {
    baseCost := uint64(len(input)) * bc.kvGasConfig.WriteCostPerByte
    if len(input) < 4 {
        return baseCost
    }
    var methodID [4]byte
    copy(methodID[:], input[:4])
    ...
}

func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
    if len(contract.Input) < 4 {
        return nil, errors.New("input too short")
    }
    methodID := contract.Input[:4]
    ...
}
```

### Proof of Concept

```go
// Attacker sends an EVM transaction with the following parameters:
// To:    0x0000000000000000000000000000000000000064  (bank precompile)
// Data:  0x01  (1 byte — fewer than the 4 required for a method selector)
// Gas:   any value
//
// Execution trace:
// 1. EVM calls BankContract.RequiredGas([]byte{0x01})
// 2. Line 84: copy(methodID[:], input[:4])
//    → runtime panic: runtime error: slice bounds out of range [:4] with length 1
// 3. Ethermint's deferred recover catches the panic; tx is marked failed.
// 4. No gas is deducted from the attacker's account.
// 5. Attacker repeats indefinitely at zero cost.
```

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-32)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
```

**File:** x/cronos/keeper/precompiles/bank.go (L80-90)
```go
func (bc *BankContract) RequiredGas(input []byte) uint64 {
	// base cost to prevent large input size
	baseCost := uint64(len(input)) * bc.kvGasConfig.WriteCostPerByte
	var methodID [4]byte
	copy(methodID[:], input[:4])
	requiredGas, ok := bankGasRequiredByMethod[methodID]
	if ok {
		return requiredGas + baseCost
	}
	return baseCost
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-109)
```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	// parse input
	methodID := contract.Input[:4]
	method, err := bankABI.MethodById(methodID)
	if err != nil {
		return nil, err
	}
```

**File:** x/cronos/keeper/precompiles/ica.go (L109-111)
```go
	if len(input) < 4 {
		return baseCost
	}
```

**File:** x/cronos/keeper/precompiles/ica.go (L125-127)
```go
	if len(contract.Input) < 4 {
		return nil, errors.New("input too short")
	}
```

**File:** x/cronos/keeper/precompiles/relayer.go (L145-148)
```go
	if inputLen < 4 {
		bc.logger.Error("invalid input length", "input", input)
		return getRequiredGas(DefaultGasRequired, baseCost, intrinsicGas)
	}
```

**File:** x/cronos/keeper/precompiles/relayer.go (L203-205)
```go
	if len(contract.Input) < 4 {
		return nil, errors.New("input too short")
	}
```
