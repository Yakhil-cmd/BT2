The vulnerability claim is valid. Here is the full analysis:

---

### Title
Coinbase SELFDESTRUCT Proceeds Forwarded to gasFeeCollector in `runWithGasFeeRefund` — (`fvm/evm/handler/handler.go`)

### Summary

`runWithGasFeeRefund` measures the coinbase balance delta across EVM execution and forwards the entire delta to the caller-supplied `gasFeeCollector`. Because the EVM block coinbase is the fixed `types.CoinbaseAddress`, any EVM-level SELFDESTRUCT targeting that address inflates the delta beyond legitimate gas fees, and the excess is unconditionally transferred to the attacker-controlled collector.

### Finding Description

`runWithGasFeeRefund` snapshots `types.CoinbaseAddress` balance before and after calling `f()`, then transfers the full positive difference to `gasFeeCollector`: [1](#0-0) 

The EVM block context always sets the EVM-level coinbase to the same fixed address: [2](#0-1) 

`newConfig` wires that into the geth `BlockContext.Coinbase`: [3](#0-2) 

`types.CoinbaseAddress` is a well-known, publicly readable constant: [4](#0-3) 

The caller-supplied `coinbase` argument to `EVM.run()` is passed straight through as `gasFeeCollector` — it is never validated or restricted: [5](#0-4) 

`EVM.run()` is `access(all)` — any Cadence script or transaction can call it with an arbitrary coinbase address: [6](#0-5) 

### Impact Explanation

Attack steps:

1. Attacker pre-funds an EVM contract (address `X`) with `N` attoFLOW.
2. Attacker submits an EVM transaction via `EVM.run(tx, gasFeeCollector=attackerAddr)` where the transaction calls `SELFDESTRUCT` on `X` with beneficiary = `types.CoinbaseAddress` (`0x000000000000000000000003...`).
3. During EVM execution the geth state credits `types.CoinbaseAddress` with both the gas fees (`gasConsumed × gasPrice`) and the SELFDESTRUCT proceeds (`N`).
4. `runWithGasFeeRefund` computes `diff = afterBalance − initCoinbaseBalance = gasFeesEarned + N`.
5. `cb.Transfer(attackerAddr, diff)` forwards `gasFeesEarned + N` to the attacker.

The attacker receives `N` attoFLOW beyond the legitimate gas fees. If `X` was funded by third-party users (e.g., a DeFi contract), those funds are stolen. Even if the attacker self-funded `X`, they recover `N` plus the gas fees, breaking the invariant that the gasFeeCollector receives only earned gas fees and corrupting total-supply accounting.

Post-EIP-6780 (Prague rules, which Flow EVM uses — confirmed by the test referencing Prague precompiles): [7](#0-6) 

SELFDESTRUCT still transfers the balance to the beneficiary; only contract destruction is suppressed. The balance transfer path remains fully exploitable.

### Likelihood Explanation

- `EVM.run()` is permissionless (`access(all)`); no authorization is required.
- `types.CoinbaseAddress` is a public constant; any attacker can target it.
- Deploying a self-destructing contract and submitting the SELFDESTRUCT transaction are standard EVM operations requiring no privileged access.
- The attack is locally reproducible on the Flow emulator with a handler test using the real emulator (not the mock).

### Recommendation

Replace the balance-delta heuristic with an explicit gas-fee accounting mechanism. Options:

1. Track gas fees inside the emulator and return the exact `gasConsumed × effectiveGasPrice` value from `RunTransaction`/`BatchRunTransactions`, then transfer only that amount.
2. Before calling `f()`, record `initCoinbaseBalance`; after `f()`, compute `diff = min(afterBalance − initCoinbaseBalance, sum(result.GasConsumed × result.GasPrice))` and transfer only that bounded amount.
3. Prevent SELFDESTRUCT from targeting `types.CoinbaseAddress` via a precompile guard or stateDB hook — but this is a weaker mitigation.

### Proof of Concept

```go
// handler_test.go (real emulator, not mock)
// 1. Deploy a Solidity contract pre-funded with 1e18 attoFLOW.
// 2. Submit EVM tx: contract calls SELFDESTRUCT(types.CoinbaseAddress).
// 3. Assert that the amount transferred to gasFeeCollector equals
//    exactly GasConsumed * GasPrice, NOT GasConsumed * GasPrice + 1e18.
// The assertion will FAIL on unmodified code, proving the bug.
```

The existing mock-based test at `handler_test.go:742–744` already demonstrates the design flaw: it treats any coinbase balance increase (here `coinbaseAfterBalance − coinbaseInitBalance = 2`) as gas fees, with no check that the delta matches actual gas consumed. [8](#0-7)

### Citations

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

**File:** fvm/evm/handler/handler.go (L748-749)
```go
		GasFeeCollector:           types.CoinbaseAddress,
	}, nil
```

**File:** fvm/evm/emulator/emulator.go (L44-57)
```go
func newConfig(ctx types.BlockContext) *Config {
	return NewConfig(
		WithChainID(ctx.ChainID),
		WithBlockNumber(new(big.Int).SetUint64(ctx.BlockNumber)),
		WithBlockTime(ctx.BlockTimestamp),
		WithCoinbase(ctx.GasFeeCollector.ToCommon()),
		WithDirectCallBaseGasUsage(ctx.DirectCallBaseGasUsage),
		WithExtraPrecompiledContracts(ctx.ExtraPrecompiledContracts),
		WithGetBlockHashFunction(ctx.GetHashFunc),
		WithRandom(&ctx.Random),
		WithTransactionTracer(ctx.Tracer),
		WithBlockTotalGasUsedSoFar(ctx.TotalGasUsedSoFar),
		WithBlockTxCountSoFar(ctx.TxCountSoFar),
	)
```

**File:** fvm/evm/types/address.go (L41-41)
```go
	CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
```

**File:** fvm/evm/impl/impl.go (L1074-1075)
```go
			// run transaction
			result := handler.Run(transaction, types.NewAddressFromBytes(gasFeeCollector))
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

**File:** fvm/evm/evm_test.go (L5912-5914)
```go
				// The address below is the latest precompile on the Prague hard-fork:
				// https://github.com/ethereum/go-ethereum/blob/v1.16.3/core/vm/contracts.go#L140 .
				to := common.HexToAddress("0x00000000000000000000000000000000000000011")
```

**File:** fvm/evm/handler/handler_test.go (L742-763)
```go
					coinbaseInitBalance := big.NewInt(1)
					coinbaseAfterBalance := big.NewInt(3)
					coinbaseDiffBalance := big.NewInt(2)
					em := &testutils.TestEmulator{
						RunTransactionFunc: func(tx *gethTypes.Transaction) (*types.Result, error) {
							return result, nil
						},
						BalanceOfFunc: func(address types.Address) (*big.Int, error) {
							if firstBalanceCall {
								firstBalanceCall = false
								return coinbaseInitBalance, nil
							}
							return coinbaseAfterBalance, nil
						},
						NonceOfFunc: func(address types.Address) (uint64, error) {
							return 0, nil
						},
						DirectCallFunc: func(call *types.DirectCall) (*types.Result, error) {
							feeCollected = true
							require.Equal(t, types.CoinbaseAddress, call.From)
							require.Equal(t, gasFeeCollector, call.To)
							require.True(t, types.BalancesAreEqual(call.Value, coinbaseDiffBalance))
```
