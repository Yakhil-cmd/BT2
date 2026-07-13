### Title
Missing Input Length Guard in `BankContract.RequiredGas` Causes Panic on Short Calldata - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
`BankContract.RequiredGas` unconditionally slices `input[:4]` without first checking `len(input) >= 4`. Any unprivileged EVM call to the bank precompile with fewer than 4 bytes of calldata triggers a Go runtime panic (`slice bounds out of range`). The identical class of bug was already patched for `RelayerContract` and `IcaContract` (CHANGELOG #1941), but `BankContract` was not updated.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, `RequiredGas` executes:

```go
func (bc *BankContract) RequiredGas(input []byte) uint64 {
    baseCost := uint64(len(input)) * bc.kvGasConfig.WriteCostPerByte
    var methodID [4]byte
    copy(methodID[:], input[:4])   // ← panics when len(input) < 4
    ...
}
``` [1](#0-0) 

The expression `input[:4]` is a slice-bounds operation in Go. When `len(input) < 4` it raises a runtime panic, not a recoverable error. `BankContract.Run` has the same defect at line 105:

```go
methodID := contract.Input[:4]   // ← also panics when len < 4
``` [2](#0-1) 

By contrast, both sibling precompiles guard this path explicitly:

- `IcaContract.RequiredGas`: `if len(input) < 4 { return baseCost }`
- `RelayerContract.RequiredGas`: `if inputLen < 4 { ... return ... }`
- `RelayerContract.Run` / `IcaContract.Run`: `if len(contract.Input) < 4 { return nil, errors.New("input too short") }` [3](#0-2) [4](#0-3) [5](#0-4) 

The CHANGELOG explicitly records that the panic-on-short-input class was fixed for `RelayerContract` and `IcaContract` in PR #1941, confirming the team treats such panics as consensus-impacting bugs — but `BankContract` was not included in that fix. [6](#0-5) 

### Impact Explanation
`RequiredGas` is invoked by the EVM engine before gas deduction and before `Run`. A Go runtime panic at this point propagates outside the normal EVM error-return path. If the panic is not caught by a `recover()` at the ABCI/consensus boundary, every validator that processes the transaction will crash, causing a **chain halt**. Even if a top-level recover exists, the panic surfaces as a non-deterministic abort rather than a clean EVM revert, which can produce **consensus divergence** between nodes running different Go runtime versions or with different panic-recovery wrappers.

The bank precompile controls `mint`, `burn`, and `transfer` of EVM-native tokens (CRC20/CRC21 assets), making it a high-value target. The impact maps directly to the allowed scope: *chain halt triggered by an unprivileged precompile call*.

### Likelihood Explanation
The bank precompile is deployed at the fixed address `common.BytesToAddress([]byte{100})` (`0x0000000000000000000000000000000000000064`). [7](#0-6) 

Any unprivileged user can send an EVM transaction to this address with 0–3 bytes of calldata. No special permissions, keys, or prior state are required. The attack is a single transaction.

### Recommendation
Add the same guard that was applied to `IcaContract` and `RelayerContract`:

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
    ...
}
```

### Proof of Concept
1. Obtain any funded EOA on Cronos.
2. Send an EVM transaction to `0x0000000000000000000000000000000000000064` with `data = 0x01` (1 byte).
3. The EVM calls `BankContract.RequiredGas([]byte{0x01})`.
4. `input[:4]` panics: `runtime error: slice bounds out of range [:4] with length 1`.
5. The panic propagates through the Ethermint EVM execution stack; if not recovered at the ABCI boundary, the node crashes and the chain halts.

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

**File:** x/cronos/keeper/precompiles/bank.go (L103-106)
```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	// parse input
	methodID := contract.Input[:4]
	method, err := bankABI.MethodById(methodID)
```

**File:** x/cronos/keeper/precompiles/ica.go (L105-121)
```go
func (ic *IcaContract) RequiredGas(input []byte) uint64 {
	// base cost to prevent large input size
	baseCost := uint64(len(input)) * ic.kvGasConfig.WriteCostPerByte
	var methodID [4]byte
	if len(input) < 4 {
		return baseCost
	}
	copy(methodID[:], input[:4])
	requiredGas, ok := icaGasRequiredByMethod[methodID]
	if !ok {
		return baseCost
	}
	if icaMethodNamesByID[methodID] == SubmitMsgsMethodName {
		requiredGas += ic.cronosKeeper.GetParams(ic.ctx).MaxCallbackGas
	}
	return requiredGas + baseCost
}
```

**File:** x/cronos/keeper/precompiles/relayer.go (L139-148)
```go
func (bc *RelayerContract) RequiredGas(input []byte) (gas uint64) {
	intrinsicGas, _ := core.IntrinsicGas(input, nil, nil, false, bc.isHomestead, bc.isIstanbul, bc.isShanghai)
	// base cost to prevent large input size
	inputLen := len(input)
	baseCost := uint64(inputLen) * authtypes.DefaultTxSizeCostPerByte
	var methodID [4]byte
	if inputLen < 4 {
		bc.logger.Error("invalid input length", "input", input)
		return getRequiredGas(DefaultGasRequired, baseCost, intrinsicGas)
	}
```

**File:** x/cronos/keeper/precompiles/relayer.go (L199-205)
```go
func (bc *RelayerContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	if readonly {
		return nil, errors.New("the method is not readonly")
	}
	if len(contract.Input) < 4 {
		return nil, errors.New("input too short")
	}
```

**File:** CHANGELOG.md (L62-62)
```markdown
* [#1941](https://github.com/crypto-org-chain/cronos/pull/1941) fix: return calculated gas instead of panic for RelayerContract, add guards for ica precompile and ibc getSourceChannelId
```
