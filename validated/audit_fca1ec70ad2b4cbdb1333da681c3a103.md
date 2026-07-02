### Title
Caller-Controlled `coinbase` in `EVM.run()` / `EVM.batchRun()` Allows Permanent Locking of EVM Gas Fees - (File: `fvm/evm/handler/handler.go`)

---

### Summary

Any unprivileged Cadence transaction sender can call `EVM.run()` or `EVM.batchRun()` and supply an arbitrary, unclaimable EVM address as the `coinbase` (gas fee collector). Because no validation is performed on this address, EVM gas fees are permanently transferred to an address with no owner — such as the zero address, a precompile address, or the internal `CoinbaseAddress` itself — making those fees permanently inaccessible.

---

### Finding Description

Flow EVM exposes two public Cadence functions for running EVM transactions:

```cadence
// fvm/evm/stdlib/contract.cdc:828
access(all)
fun run(tx: [UInt8], coinbase: EVMAddress): Result { ... }

// fvm/evm/stdlib/contract.cdc:918
access(all)
fun batchRun(txs: [[UInt8]], coinbase: EVMAddress): [Result] { ... }
```

Both accept a fully caller-controlled `coinbase: EVMAddress` parameter with no pre-condition checks beyond the `isPaused()` guard. [1](#0-0) 

These functions route through `ContractHandler.Run()` / `ContractHandler.BatchRun()` in Go, both of which call `runWithGasFeeRefund(gasFeeCollector, ...)`:

```go
// fvm/evm/handler/handler.go:252-266
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
    cb := h.AccountByAddress(types.CoinbaseAddress, true)
    initCoinbaseBalance := cb.Balance()
    f()
    afterBalance := cb.Balance()
    diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
    if diff.Sign() > 0 {
        cb.Transfer(gasFeeCollector, diff)  // ← no validation of gasFeeCollector
    }
    ...
}
``` [2](#0-1) 

The EVM emulator accumulates gas fees at the internal `types.CoinbaseAddress` (`{0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0}`), then `runWithGasFeeRefund` transfers the balance delta to the caller-supplied `gasFeeCollector`. There is no check that `gasFeeCollector` is:
- Not the zero address
- Not a precompile address (prefix `{0,0,...,0,0}` or `{0,0,...,0,1}`)
- Not `CoinbaseAddress` itself (prefix `{0,0,...,0,3}`)
- Not any other address with no owner

`CoinbaseAddress` is defined as a protocol-internal special address: [3](#0-2) 

There is no mechanism to withdraw funds from `CoinbaseAddress`, the zero address, or any precompile address. Funds sent there are permanently locked.

---

### Impact Explanation

An attacker calls:

```cadence
import EVM from <EVMContractAddress>

transaction(tx: [UInt8]) {
    prepare(account: &Account) {
        // coinbase = zero address (or CoinbaseAddress, or any precompile address)
        let deadCoinbase = EVM.EVMAddress(bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
        EVM.run(tx: tx, coinbase: deadCoinbase)
    }
}
```

The EVM gas fees paid by the EVM transaction sender (FLOW tokens held in EVM form) are transferred to the zero address and are permanently inaccessible. The legitimate fee collector (e.g., the EVM gateway relayer) receives nothing. The locked FLOW tokens cannot be recovered by any protocol mechanism.

This is a direct analog to the external report: a user-controlled parameter (referral/coinbase address) redirects protocol fees to an unclaimable address, permanently destroying those assets.

---

### Likelihood Explanation

- `EVM.run()` and `EVM.batchRun()` are `access(all)` — callable by any Cadence transaction sender with no role or stake requirement.
- The `coinbase` parameter is a raw `[UInt8; 20]` byte array with no type-level restriction.
- The attack requires only a valid signed EVM transaction (which the attacker can construct) and a Cadence transaction to wrap it.
- No admin keys, staked nodes, or special privileges are needed.

---

### Recommendation

In `runWithGasFeeRefund`, validate that `gasFeeCollector` is not a reserved or unclaimable address before transferring fees. At minimum, reject:
- The zero address (`EmptyAddress`)
- `CoinbaseAddress` itself (self-transfer, fees remain permanently locked)
- Addresses matching the native precompile prefix (`FlowEVMNativePrecompileAddressPrefix`)
- Addresses matching the extended precompile prefix (`FlowEVMExtendedPrecompileAddressPrefix`)

Alternatively, restrict the `coinbase` parameter at the Cadence layer in `EVM.run()` / `EVM.batchRun()` to only accept addresses that are known to be claimable (e.g., COA addresses or externally-owned EVM accounts with a non-special prefix).

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker constructs a valid RLP-encoded EVM transaction `evmTx` signed by an EVM EOA with `gasPrice > 0` and `gasLimit > 0`.
2. Attacker submits a Cadence transaction:

```cadence
import EVM from 0xEVMAddress

transaction(evmTxBytes: [UInt8]) {
    prepare(account: &Account) {
        // Supply CoinbaseAddress as coinbase — self-transfer, fees permanently locked
        let lockedCoinbase = EVM.EVMAddress(bytes: [0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0])
        let res = EVM.run(tx: evmTxBytes, coinbase: lockedCoinbase)
        // res.status == successful, but gas fees are now permanently at CoinbaseAddress
    }
}
```

3. `runWithGasFeeRefund` computes `diff = afterBalance - initBalance > 0` and calls `cb.Transfer(lockedCoinbase, diff)`.
4. Since `lockedCoinbase == CoinbaseAddress`, this is a self-transfer — the balance stays at `CoinbaseAddress`.
5. `CoinbaseAddress` has no private key and no withdrawal mechanism; the fees are permanently inaccessible.

**Relevant code path:**
- `EVM.run()` → `InternalEVM.run()` → `ContractHandler.Run()` → `runWithGasFeeRefund(gasFeeCollector, ...)` → `cb.Transfer(gasFeeCollector, diff)` [4](#0-3) [1](#0-0) [5](#0-4)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L827-836)
```text
    access(all)
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.run(
            tx: tx,
            coinbase: coinbase.bytes
        ) as! Result
    }
```

**File:** fvm/evm/handler/handler.go (L232-266)
```go
// Run tries to run an rlp-encoded evm transaction
// collects the gas fees and pay it to the gasFeeCollector address provided.
func (h *ContractHandler) Run(rlpEncodedTx []byte, gasFeeCollector types.Address) *types.ResultSummary {
	// capture open tracing span
	defer h.backend.StartChildSpan(trace.FVMEVMRun).End()

	var res *types.Result
	var err error
	h.runWithGasFeeRefund(gasFeeCollector, func() {
		// run transaction
		res, err = h.run(rlpEncodedTx)
		panicOnError(err)

	})
	// return the result summary
	return res.ResultSummary()
}

// runWithGasFeeRefund runs a method and transfers the balance changes of the
// coinbase address to the provided gas fee collector
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
	// capture coinbase init balance
	cb := h.AccountByAddress(types.CoinbaseAddress, true)
	initCoinbaseBalance := cb.Balance()
	f()
	// transfer the gas fees collected to the gas fee collector address
	afterBalance := cb.Balance()
	diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
	if diff.Sign() > 0 {
		cb.Transfer(gasFeeCollector, diff)
	}
	if diff.Sign() < 0 { // this should never happen but in case
		panic(fvmErrors.NewEVMError(fmt.Errorf("negative balance change on coinbase")))
	}
}
```

**File:** fvm/evm/types/address.go (L31-42)
```go
var (
	// Using leading zeros for prefix helps with the storage compactness.
	//
	// Prefix for the built-in EVM precompiles
	FlowEVMNativePrecompileAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	// Prefix for the extended precompiles
	FlowEVMExtendedPrecompileAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	// Prefix for the COA addresses
	FlowEVMCOAAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	// Coinbase address
	CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
)
```
