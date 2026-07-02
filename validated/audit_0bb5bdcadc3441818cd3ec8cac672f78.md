### Title
Caller-Controlled `coinbase` in `EVM.run` / `EVM.batchRun` Enables EVM Gas Fee Self-Redirection — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.run` and `EVM.batchRun` are `access(all)` functions that accept a fully caller-controlled `coinbase` EVM address. This address receives all EVM gas fees collected during execution. Because there is no validation that the `coinbase` is a legitimate, protocol-controlled recipient, any unprivileged Cadence transaction sender can set their own EVM address as the `coinbase`, routing gas fees back to themselves and executing EVM transactions at zero net EVM gas cost.

---

### Finding Description

`EVM.run` is declared `access(all)` in the EVM system contract, accepting a caller-supplied `coinbase: EVMAddress` with no restrictions:

```cadence
access(all)
fun run(tx: [UInt8], coinbase: EVMAddress): Result {
    ...
    return InternalEVM.run(tx: tx, coinbase: coinbase.bytes) as! Result
}
``` [1](#0-0) 

This `coinbase` value flows through the Go host function `newInternalEVMTypeRunFunction` without any validation:

```go
result := handler.Run(transaction, types.NewAddressFromBytes(gasFeeCollector))
``` [2](#0-1) 

Inside `ContractHandler.Run`, the `gasFeeCollector` is passed directly to `runWithGasFeeRefund`:

```go
h.runWithGasFeeRefund(gasFeeCollector, func() {
    res, err = h.run(rlpEncodedTx)
    panicOnError(err)
})
``` [3](#0-2) 

`runWithGasFeeRefund` computes the coinbase balance delta after execution and transfers it unconditionally to the caller-supplied address:

```go
diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
if diff.Sign() > 0 {
    cb.Transfer(gasFeeCollector, diff)
}
``` [4](#0-3) 

The same pattern applies to `EVM.batchRun` via `newInternalEVMTypeBatchRunFunction` → `handler.BatchRun` → `runWithGasFeeRefund`. [5](#0-4) [6](#0-5) 

At no point in this call chain is the `coinbase`/`gasFeeCollector` address validated against any protocol-controlled address or checked to be distinct from the EVM transaction sender.

---

### Impact Explanation

An attacker who controls an EVM EOA can:

1. Fund their EVM EOA with FLOW (attoflow) to cover gas.
2. Craft a signed EVM transaction from that EOA.
3. Submit a Cadence transaction calling `EVM.run(tx: myTx, coinbase: myEVMAddress)` where `myEVMAddress` is the same EOA (or any address they control).
4. The EVM transaction executes; gas fees are deducted from the EOA and transferred to `myEVMAddress` (the attacker-controlled coinbase).
5. Net result: the attacker recovers all EVM gas fees, executing arbitrary EVM computation at zero net EVM gas cost (paying only the much cheaper Cadence-level inclusion fee).

This is a direct analog to the `BatchTrade.sol` bug: just as the attacker there set the `taker` to their own address to bypass fee collection, here the attacker sets the `coinbase` to their own address to redirect gas fees back to themselves. The EVM fee market — which is the primary economic mechanism preventing spam and resource exhaustion in Flow EVM — is undermined for any caller who uses `EVM.run` directly.

---

### Likelihood Explanation

**High.** `EVM.run` is `access(all)` — callable by any Cadence transaction with no authorization requirement. The attack requires only a standard Flow account, an EVM EOA, and a single Cadence transaction. No special privileges, staked nodes, or compromised keys are needed. The attack is cheap to execute repeatedly.

---

### Recommendation

1. **Restrict the `coinbase` to a protocol-controlled address.** The `coinbase` should be set by the protocol (e.g., the Flow fees contract address or the service account's EVM address), not supplied by the caller. Remove the `coinbase` parameter from the public `EVM.run` / `EVM.batchRun` API and hardcode it internally.

2. **If relayer use cases require a configurable coinbase**, add an entitlement check (e.g., `access(FlowFees)` or a dedicated `Relay` entitlement) so only authorized relayer contracts can specify a custom fee recipient.

3. **Validate that `coinbase != tx.from`** at minimum, to prevent trivial self-dealing.

---

### Proof of Concept

```cadence
import EVM from <EVMContractAddress>

transaction(myEVMTxBytes: [UInt8], myEVMAddress: [UInt8; 20]) {
    execute {
        // Attacker sets their own EVM address as coinbase.
        // Gas fees paid by the EVM tx are returned to the attacker.
        let coinbase = EVM.EVMAddress(bytes: myEVMAddress)
        let result = EVM.run(tx: myEVMTxBytes, coinbase: coinbase)
        // result.status == EVM.Status.successful
        // Attacker's EVM balance is unchanged (gas paid == gas received as coinbase)
    }
}
```

The attacker prepares `myEVMTxBytes` as a signed EVM transaction from the EOA at `myEVMAddress`. After `EVM.run` completes, `runWithGasFeeRefund` transfers the gas fee delta from `types.CoinbaseAddress` to `myEVMAddress`, netting the attacker zero EVM gas cost. [7](#0-6) [8](#0-7)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L819-836)
```text
    /// Runs an a RLP-encoded EVM transaction, deducts the gas fees,
    /// and deposits the gas fees into the provided coinbase address.
    ///
    /// @param tx: The rlp-encoded transaction to run
    /// @param coinbase: The address of entity to receive the transaction fees
    /// for relaying the transaction
    ///
    /// @return: The transaction result
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

**File:** fvm/evm/impl/impl.go (L1074-1075)
```go
			// run transaction
			result := handler.Run(transaction, types.NewAddressFromBytes(gasFeeCollector))
```

**File:** fvm/evm/impl/impl.go (L1134-1182)
```go
func newInternalEVMTypeBatchRunFunction(
	gauge common.MemoryGauge,
	handler types.ContractHandler,
) *interpreter.HostFunctionValue {
	return interpreter.NewStaticHostFunctionValue(
		gauge,
		stdlib.InternalEVMTypeBatchRunFunctionType,
		func(invocation interpreter.Invocation) interpreter.Value {
			context := invocation.InvocationContext

			// Get transactions batch argument
			transactionsBatchValue, ok := invocation.Arguments[0].(*interpreter.ArrayValue)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			batchCount := transactionsBatchValue.Count()
			var transactionBatch [][]byte
			if batchCount > 0 {
				transactionBatch = make([][]byte, batchCount)
				i := 0
				transactionsBatchValue.Iterate(
					context,
					func(transactionValue interpreter.Value) (resume bool) {
						t, err := interpreter.ByteArrayValueToByteSlice(context, transactionValue)
						if err != nil {
							panic(err)
						}
						transactionBatch[i] = t
						i++
						return true
					},
					false,
				)
			}

			// Get gas fee collector argument
			gasFeeCollectorValue, ok := invocation.Arguments[1].(*interpreter.ArrayValue)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			gasFeeCollector, err := interpreter.ByteArrayValueToByteSlice(context, gasFeeCollectorValue)
			if err != nil {
				panic(err)
			}

			// Batch run
			batchResults := handler.BatchRun(transactionBatch, types.NewAddressFromBytes(gasFeeCollector))
```

**File:** fvm/evm/handler/handler.go (L240-245)
```go
	h.runWithGasFeeRefund(gasFeeCollector, func() {
		// run transaction
		res, err = h.run(rlpEncodedTx)
		panicOnError(err)

	})
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
