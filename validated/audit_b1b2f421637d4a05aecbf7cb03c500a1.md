### Title
Caller-Controlled `coinbase` in `EVM.run` / `EVM.batchRun` Allows Any Flow Transaction Sender to Redirect EVM Gas Fees - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.run()` and `EVM.batchRun()` are declared `access(all)` in the EVM system contract and accept a caller-supplied `coinbase` (gas fee collector) address that is never part of the signed EVM transaction payload. Any unprivileged Flow transaction sender who obtains a valid signed EVM transaction can call these functions with an arbitrary `coinbase`, redirecting all gas fees away from the legitimate relayer to an attacker-controlled EVM address.

---

### Finding Description

`EVM.run(tx: [UInt8], coinbase: EVMAddress)` and `EVM.batchRun(txs: [[UInt8]], coinbase: EVMAddress)` are both declared `access(all)` in the EVM system contract: [1](#0-0) [2](#0-1) 

The `coinbase` argument is passed directly through `InternalEVM.run` / `InternalEVM.batchRun` to the Go-layer `ContractHandler.Run` / `ContractHandler.BatchRun`: [3](#0-2) [4](#0-3) 

In `runWithGasFeeRefund`, the entire balance increase at the EVM coinbase address (i.e., all gas fees paid by the EVM transaction) is transferred to the caller-supplied `gasFeeCollector`: [5](#0-4) 

The signed EVM transaction (RLP-encoded, ECDSA-signed by the EVM user) commits to `gasPrice` and `gasLimit`, but **not** to the `coinbase` address. The EVM transaction's signature does not cover who receives the gas fees. Because `EVM.run()` is `access(all)`, any Flow transaction sender — not just the intended relayer — can supply any `coinbase` value.

---

### Impact Explanation

An attacker who obtains a valid signed EVM transaction (e.g., from a public broadcast channel, a relayer API, or a mempool observer) can call `EVM.run(tx: victimTx, coinbase: attackerEVMAddress)` before the legitimate relayer does. All gas fees from the EVM transaction execution are transferred to the attacker's EVM address. The legitimate relayer receives nothing. The EVM user's transaction still executes correctly and they pay exactly the gas fees they signed for, but the fee revenue is stolen from the relayer.

For `batchRun`, the same applies to an entire batch: all accumulated gas fees for the batch are transferred to the attacker-supplied `coinbase`. [6](#0-5) [7](#0-6) 

---

### Likelihood Explanation

Signed EVM transactions are broadcast publicly (e.g., via the Flow Access API or EVM-compatible RPC endpoints). Any Flow account holder — an unprivileged transaction sender — can call `EVM.run()` with no special capability or entitlement. The only requirement is obtaining the RLP-encoded signed EVM transaction bytes, which are public by design. No staked node, admin key, or social engineering is required. [1](#0-0) 

---

### Recommendation

Restrict `EVM.run()` and `EVM.batchRun()` so that the `coinbase` address cannot be freely specified by an arbitrary caller. Options include:

1. **Remove the `coinbase` parameter** and derive the fee recipient from the Flow transaction's payer or a fixed protocol address, so the fee destination is determined by the protocol rather than the caller.
2. **Require an entitlement** (e.g., `access(EVMRelayer)`) on `run` and `batchRun` so only authorized relayer accounts can call these functions and set the `coinbase`.
3. **Bind `coinbase` to the Flow transaction's payer address** inside the FVM layer, removing it as a user-supplied argument entirely.

---

### Proof of Concept

Any unprivileged Flow account can submit the following transaction to redirect gas fees from a legitimate relayer to an attacker-controlled EVM address:

```cadence
import EVM from <EVMContractAddress>

// Attacker submits this transaction with:
//   - victimSignedTx: RLP-encoded EVM transaction signed by Alice (obtained from broadcast)
//   - attackerCoinbase: attacker's own EVM address
transaction(victimSignedTx: [UInt8], attackerCoinbaseBytes: [UInt8; 20]) {
    prepare(account: &Account) {
        let attackerCoinbase = EVM.EVMAddress(bytes: attackerCoinbaseBytes)
        // coinbase is not part of Alice's EVM signature — attacker freely sets it
        let res = EVM.run(tx: victimSignedTx, coinbase: attackerCoinbase)
        // Alice's EVM transaction executes; gas fees go to attacker, not the legitimate relayer
    }
}
```

The root cause is confirmed at: [1](#0-0) [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L917-926)
```text
    access(all)
    fun batchRun(txs: [[UInt8]], coinbase: EVMAddress): [Result] {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.batchRun(
            txs: txs,
            coinbase: coinbase.bytes,
        ) as! [Result]
    }
```

**File:** fvm/evm/impl/impl.go (L1062-1075)
```go
			// Get gas fee collector argument

			gasFeeCollectorValue, ok := invocation.Arguments[1].(*interpreter.ArrayValue)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			gasFeeCollector, err := interpreter.ByteArrayValueToByteSlice(context, gasFeeCollectorValue)
			if err != nil {
				panic(err)
			}

			// run transaction
			result := handler.Run(transaction, types.NewAddressFromBytes(gasFeeCollector))
```

**File:** fvm/evm/impl/impl.go (L1170-1182)
```go
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

**File:** fvm/evm/handler/handler.go (L234-248)
```go
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
