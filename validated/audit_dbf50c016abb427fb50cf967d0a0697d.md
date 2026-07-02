### Title
Gas Fees Permanently Burned via Zero-Address Coinbase in `EVM.run` / `EVM.batchRun` — (`fvm/evm/stdlib/contract.cdc`, `fvm/evm/handler/handler.go`)

---

### Summary

`EVM.run` and `EVM.batchRun` in the Flow EVM Cadence contract are `access(all)` functions that accept a caller-controlled `coinbase: EVMAddress` parameter with no zero-address guard. When the zero EVM address is supplied as coinbase, the gas fees collected from the EVM transaction sender are permanently transferred to the zero EVM address via `runWithGasFeeRefund`, causing irreversible cross-VM asset loss of bridged FLOW tokens.

---

### Finding Description

`EVM.run` and `EVM.batchRun` in `fvm/evm/stdlib/contract.cdc` are publicly callable by any unprivileged Cadence transaction sender:

```cadence
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
``` [1](#0-0) 

The `EVMAddress` struct constructor performs no zero-address validation:

```cadence
view init(bytes: [UInt8; 20]) {
    self.bytes = bytes
}
``` [2](#0-1) 

After the EVM transaction executes, `runWithGasFeeRefund` in `handler.go` computes the gas fee delta on the internal `CoinbaseAddress` and unconditionally transfers it to the caller-supplied `gasFeeCollector`:

```go
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
    cb := h.AccountByAddress(types.CoinbaseAddress, true)
    initCoinbaseBalance := cb.Balance()
    f()
    afterBalance := cb.Balance()
    diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
    if diff.Sign() > 0 {
        cb.Transfer(gasFeeCollector, diff)   // ← no zero-address guard
    }
    ...
}
``` [3](#0-2) 

`CoinbaseAddress` is a distinct internal address (`{0,0,0,0,0,0,0,0,0,0,0,3,...}`), not the zero address:

```go
CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
var EmptyAddress = Address(gethCommon.Address{})
``` [4](#0-3) 

When `gasFeeCollector` is the zero EVM address, `cb.Transfer` executes a valid EVM transfer to `0x0000000000000000000000000000000000000000`. No private key controls that address; the FLOW tokens bridged into EVM as gas fees are permanently locked there and can never be withdrawn back to Cadence.

The same path exists for `BatchRun`:

```go
func (h *ContractHandler) BatchRun(rlpEncodedTxs [][]byte, gasFeeCollector types.Address) []*types.ResultSummary {
    ...
    h.runWithGasFeeRefund(gasFeeCollector, func() { ... })
    ...
}
``` [5](#0-4) 

---

### Impact Explanation

FLOW tokens bridged into the EVM environment are permanently burned. The gas fees are deducted from the EVM transaction sender's EVM balance and transferred to the zero address, from which they can never be withdrawn. Because `EVM.run` is `access(all)`, any Cadence transaction can act as a relayer and supply a zero coinbase, causing the EVM transaction sender's gas fees to be irrecoverably lost. This is a direct cross-VM asset loss.

---

### Likelihood Explanation

`EVM.run` and `EVM.batchRun` are publicly accessible to any Cadence transaction sender. A malicious relayer submitting EVM transactions on behalf of EOA users can trivially pass `EVM.EVMAddress(bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])` as the coinbase. No special privilege, staked node, or key compromise is required. The only precondition is that the EVM transaction has a non-zero gas price (so that `diff.Sign() > 0` and the transfer fires).

---

### Recommendation

Add a zero-address pre-condition to `EVM.run`, `EVM.mustRun`, and `EVM.batchRun` in `contract.cdc`:

```cadence
pre {
    !self.isPaused(): "EVM operations are temporarily paused"
    coinbase.bytes != [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
        "EVM.run(): coinbase must not be the zero address"
}
```

Equivalently, add a guard in `runWithGasFeeRefund` in `handler.go`:

```go
if gasFeeCollector == (types.Address{}) {
    panic(fvmErrors.NewEVMError(fmt.Errorf("gas fee collector must not be the zero address")))
}
```

---

### Proof of Concept

Any unprivileged Cadence transaction:

```cadence
import EVM from <EVMContractAddress>

transaction(rlpTx: [UInt8]) {
    prepare(signer: &Account) {
        // Zero address as coinbase — gas fees are permanently burned
        let zeroCoinbase = EVM.EVMAddress(
            bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        )
        let result = EVM.run(tx: rlpTx, coinbase: zeroCoinbase)
        // result.status == successful, but gas fees are now in 0x000...000
        // and can never be recovered
    }
}
```

1. The EVM transaction executes normally.
2. `runWithGasFeeRefund` computes `diff = afterCoinbaseBalance - initCoinbaseBalance > 0`.
3. `cb.Transfer(zeroAddress, diff)` fires — gas fees move from `CoinbaseAddress` to `0x000...000`.
4. The FLOW tokens are permanently locked; no withdrawal path exists from the zero EVM address back to Cadence.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L163-165)
```text
        view init(bytes: [UInt8; 20]) {
            self.bytes = bytes
        }
```

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

**File:** fvm/evm/handler/handler.go (L252-266)
```go
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

**File:** fvm/evm/handler/handler.go (L272-294)
```go
func (h *ContractHandler) BatchRun(rlpEncodedTxs [][]byte, gasFeeCollector types.Address) []*types.ResultSummary {
	// capture open tracing
	span := h.backend.StartChildSpan(trace.FVMEVMBatchRun)
	if span.Tracer != nil {
		span.SetAttributes(attribute.Int("tx_counts", len(rlpEncodedTxs)))
	}
	defer span.End()

	var results []*types.Result
	var err error
	h.runWithGasFeeRefund(gasFeeCollector, func() {
		// batch run transactions and panic if any error
		results, err = h.batchRun(rlpEncodedTxs)
		panicOnError(err)
	})

	// convert results into result summaries
	resSummaries := make([]*types.ResultSummary, len(results))
	for i, r := range results {
		resSummaries[i] = r.ResultSummary()
	}
	return resSummaries
}
```

**File:** fvm/evm/types/address.go (L41-56)
```go
	CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
)

// Address is an EVM-compatible address
type Address gethCommon.Address

// AddressLength holds the number of bytes used for each EVM address
const AddressLength = gethCommon.AddressLength

// NewAddress constructs a new Address
func NewAddress(addr gethCommon.Address) Address {
	return Address(addr)
}

// EmptyAddress is an empty evm address
var EmptyAddress = Address(gethCommon.Address{})
```
