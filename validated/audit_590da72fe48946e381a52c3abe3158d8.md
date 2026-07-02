### Title
Unchecked `uint64` Arithmetic in EVM Cumulative Gas Accumulation Corrupts Block Accounting - (File: `fvm/evm/emulator/emulator.go`)

---

### Summary
Two unchecked `uint64` additions in `fvm/evm/emulator/emulator.go` compute `CumulativeGasUsed` without overflow protection. If the sum wraps around, the corrupted value is written back into `BlockTotalGasUsedSoFar`, propagated into the EVM block proposal's `TotalGasUsed`, and ultimately embedded in the EVM block hash — corrupting the on-chain EVM ledger and breaking off-chain replay validation.

---

### Finding Description

In `fvm/evm/emulator/emulator.go`, `CumulativeGasUsed` is computed via bare `uint64` addition in two code paths with no overflow guard:

**Path 1 — `run()` (regular and batch EVM transactions):** [1](#0-0) 

```go
res.CumulativeGasUsed = execResult.UsedGas + proc.config.BlockTotalGasUsedSoFar
// ...
proc.config.BlockTotalGasUsedSoFar = res.CumulativeGasUsed   // line 716
```

**Path 2 — `deployAt()` (direct-call contract deployments):** [2](#0-1) 

```go
res.CumulativeGasUsed = proc.config.BlockTotalGasUsedSoFar + res.GasConsumed
```

Both fields are `uint64`: [3](#0-2) 

The corrupted `CumulativeGasUsed` is then consumed by `AppendTransaction` on the block proposal, which sets `bp.TotalGasUsed = res.CumulativeGasUsed`: [4](#0-3) 

`TotalGasUsed` is a field in the `Block` struct that participates in the EVM block hash computation. The block context is initialized from `bp.TotalGasUsed` for each subsequent Cadence transaction in the same Flow block: [5](#0-4) 

Additionally, there is a silent `uint` → `uint16` truncation for the transaction index: [6](#0-5) 

```go
txIndex := proc.config.BlockTxCountSoFar   // type: uint
res.Index = uint16(txIndex)                // silent truncation if txIndex > 65535
```

If `BlockTxCountSoFar` exceeds 65535, two distinct transactions receive the same `Index`, corrupting the `TransactionHashRoot` in the block event.

The off-chain replay engine explicitly validates `TotalGasUsed` against the re-accumulated sum: [7](#0-6) 

A wrapped-around value will never match, permanently breaking replay for that block.

---

### Impact Explanation

If overflow is triggered:

1. **Corrupted `CumulativeGasUsed`** is emitted in every subsequent `TransactionExecuted` event within the same Flow block.
2. **Corrupted `TotalGasUsed`** is stored in the committed EVM block and emitted in the `BlockExecuted` event.
3. **EVM block hash is wrong** — `TotalGasUsed` is an input to the block hash; all downstream block hashes in the EVM chain are invalidated.
4. **Off-chain replay permanently fails** — `ReplayBlockExecution` at `replay.go:79` compares `blockEvent.TotalGasUsed` against the re-accumulated sum and returns an error, breaking all indexers and verifiers that rely on replay.
5. **`uint16` index collision** — if `BlockTxCountSoFar > 65535`, two transactions share the same `Index`, corrupting `TransactionHashRoot` and the block hash.

---

### Likelihood Explanation

The `batchRun` pre-check in `handler.go` (lines 307–325) guards against the sum of declared gas *limits* exceeding the FVM computation budget: [8](#0-7) 

However, this guard operates on gas *limits* (declared upper bounds), not actual gas *consumed*. The `BlockTotalGasUsedSoFar` accumulates across all Cadence transactions within a single Flow block; each Cadence transaction has its own independent computation budget. A sequence of Cadence transactions each consuming near-maximum EVM gas could push the accumulated total toward `uint64` max across the block. The `deployAt` path (line 621) is called for direct calls (COA deployments, deposits) and has no analogous pre-check at all. The block-level EVM gas pool is set to `math.MaxUint64`: [9](#0-8) 

The existing test `"Batch run evm gas overflow"` confirms the team is aware of gas overflow risks but relies solely on the FVM computation limit as the guard, with no arithmetic-level protection: [10](#0-9) 

---

### Recommendation

1. Add explicit overflow checks before both unchecked additions in `emulator.go`:

```go
// In run():
if execResult.UsedGas > math.MaxUint64 - proc.config.BlockTotalGasUsedSoFar {
    return nil, fmt.Errorf("cumulative gas overflow")
}
res.CumulativeGasUsed = execResult.UsedGas + proc.config.BlockTotalGasUsedSoFar

// In deployAt():
if res.GasConsumed > math.MaxUint64 - proc.config.BlockTotalGasUsedSoFar {
    return nil, fmt.Errorf("cumulative gas overflow")
}
res.CumulativeGasUsed = proc.config.BlockTotalGasUsedSoFar + res.GasConsumed
```

2. Guard the `uint16` cast for `Index`:

```go
if txIndex > math.MaxUint16 {
    return nil, fmt.Errorf("transaction index overflow: %d", txIndex)
}
res.Index = uint16(txIndex)
```

3. Consider adding a block-level cap on `TotalGasUsed` in `AppendTransaction` to prevent the corrupted value from being committed to the block proposal.

---

### Proof of Concept

**Entry path (unprivileged sender):**

1. Attacker submits a series of Cadence transactions each calling `EVM.batchRun()` with EVM transactions that consume the maximum allowed gas per Cadence transaction.
2. Each Cadence transaction passes the per-transaction `remainingGasLimit` check independently.
3. Across the Flow block, `bp.TotalGasUsed` (read back as `TotalGasUsedSoFar` for each new Cadence transaction via `getBlockContext`) accumulates without bound.
4. When `TotalGasUsedSoFar + execResult.UsedGas > math.MaxUint64`, line 705 wraps around silently.
5. The wrapped value is written to `bp.TotalGasUsed` via `AppendTransaction`, committed to the EVM block, and emitted in `BlockExecuted`.
6. Any call to `ReplayBlockExecution` for that block returns `"total gas used doesn't match"` at `replay.go:79`, permanently breaking off-chain verification.

### Citations

**File:** fvm/evm/emulator/emulator.go (L621-621)
```go
	res.CumulativeGasUsed = proc.config.BlockTotalGasUsedSoFar + res.GasConsumed
```

**File:** fvm/evm/emulator/emulator.go (L679-679)
```go
	gasPool := (*gethCore.GasPool)(&proc.config.BlockContext.GasLimit)
```

**File:** fvm/evm/emulator/emulator.go (L699-704)
```go
	txIndex := proc.config.BlockTxCountSoFar
	// if pre-checks are passed, the exec result won't be nil
	if execResult != nil {
		res.GasConsumed = execResult.UsedGas
		res.MaxGasConsumed = execResult.MaxUsedGas
		res.Index = uint16(txIndex)
```

**File:** fvm/evm/emulator/emulator.go (L705-716)
```go
		res.CumulativeGasUsed = execResult.UsedGas + proc.config.BlockTotalGasUsedSoFar
		res.PrecompiledCalls, err = proc.config.PCTracker.CapturedCalls()
		if err != nil {
			return nil, err
		}

		// we need to capture the returned value no matter the status
		// if the tx is reverted the error message is returned as returned value
		res.ReturnedData = execResult.ReturnData

		// Update proc context
		proc.config.BlockTotalGasUsedSoFar = res.CumulativeGasUsed
```

**File:** fvm/evm/emulator/config.go (L47-51)
```go
	BlockTxCountSoFar uint
	// BlockTotalGasSoFar captures the total
	// amount of gas used so far
	BlockTotalGasUsedSoFar uint64
	// PrecompiledContracts holds the applicable precompiled contracts
```

**File:** fvm/evm/types/block_test.go (L70-73)
```go
	bp.AppendTransaction(res)
	require.Equal(t, res.TxHash, bp.TxHashes[0])
	require.Equal(t, res.CumulativeGasUsed, bp.TotalGasUsed)
	require.Equal(t, *res.LightReceipt(), bp.Receipts[0])
```

**File:** fvm/evm/handler/handler.go (L304-325)
```go
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

**File:** fvm/evm/handler/handler.go (L746-748)
```go
		TxCountSoFar:              uint(len(bp.TxHashes)),
		TotalGasUsedSoFar:         bp.TotalGasUsed,
		GasFeeCollector:           types.CoinbaseAddress,
```

**File:** fvm/evm/offchain/sync/replay.go (L49-81)
```go
	gasConsumedSoFar := uint64(0)
	txHashes := make(types.TransactionHashes, len(transactionEvents))
	results := make([]*types.Result, 0, len(transactionEvents))
	for idx, tx := range transactionEvents {
		result, err := replayTransactionExecution(
			rootAddr,
			ctx,
			uint(idx),
			gasConsumedSoFar,
			storage,
			&tx,
			validateResults,
		)
		if err != nil {
			return nil, fmt.Errorf("transaction execution failed, txIndex: %d, err: %w", idx, err)
		}
		gasConsumedSoFar += tx.GasConsumed
		txHashes[idx] = tx.Hash

		results = append(results, result)
	}

	if validateResults {
		// check transaction inclusion
		txHashRoot := gethTypes.DeriveSha(txHashes, gethTrie.NewStackTrie(nil))
		if txHashRoot != blockEvent.TransactionHashRoot {
			return nil, fmt.Errorf("transaction root hash doesn't match [%x] != [%x]", txHashRoot, blockEvent.TransactionHashRoot)
		}

		// check total gas used
		if blockEvent.TotalGasUsed != gasConsumedSoFar {
			return nil, fmt.Errorf("total gas used doesn't match [%d] != [%d]", gasConsumedSoFar, blockEvent.TotalGasUsed)
		}
```

**File:** fvm/evm/evm_test.go (L1926-2007)
```go
	// run a batch of two transactions. The sum of their gas usage would overflow an uint46
	// so the batch run should fail with an overflow error.
	t.Run("Batch run evm gas overflow", func(t *testing.T) {
		t.Parallel()
		RunWithNewEnvironment(t,
			chain, func(
				ctx fvm.Context,
				vm fvm.VM,
				snapshot snapshot.SnapshotTree,
				testContract *TestContract,
				testAccount *EOATestAccount,
			) {
				sc := systemcontracts.SystemContractsForChain(chain.ChainID())
				batchRunCode := fmt.Appendf(nil,
					`
					import EVM from %s

					transaction(txs: [[UInt8]], coinbaseBytes: [UInt8; 20]) {
						execute {
							let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)
							let batchResults = EVM.batchRun(txs: txs, coinbase: coinbase)
						}
					}
					`,
					sc.EVMContract.Address.HexWithPrefix(),
				)

				coinbaseAddr := types.Address{1, 2, 3}
				coinbaseBalance := getEVMAccountBalance(t, ctx, vm, snapshot, coinbaseAddr)
				require.Zero(t, types.BalanceToBigInt(coinbaseBalance).Uint64())

				batchCount := 2
				txBytes := make([]cadence.Value, batchCount)

				tx := testAccount.PrepareSignAndEncodeTx(t,
					testContract.DeployedAt.ToCommon(),
					testContract.MakeCallData(t, "storeWithLog", big.NewInt(0)),
					big.NewInt(0),
					uint64(200_000),
					big.NewInt(1),
				)

				txBytes[0] = cadence.NewArray(
					unittest.BytesToCdcUInt8(tx),
				).WithType(stdlib.EVMTransactionBytesCadenceType)

				tx = testAccount.PrepareSignAndEncodeTx(t,
					testContract.DeployedAt.ToCommon(),
					testContract.MakeCallData(t, "storeWithLog", big.NewInt(1)),
					big.NewInt(0),
					math.MaxUint64-uint64(100_000),
					big.NewInt(1),
				)

				txBytes[1] = cadence.NewArray(
					unittest.BytesToCdcUInt8(tx),
				).WithType(stdlib.EVMTransactionBytesCadenceType)

				coinbase := cadence.NewArray(
					unittest.BytesToCdcUInt8(coinbaseAddr.Bytes()),
				).WithType(stdlib.EVMAddressBytesCadenceType)

				txs := cadence.NewArray(txBytes).
					WithType(cadence.NewVariableSizedArrayType(
						stdlib.EVMTransactionBytesCadenceType,
					))

				txBody, err := flow.NewTransactionBodyBuilder().
					SetScript(batchRunCode).
					SetPayer(sc.FlowServiceAccount.Address).
					AddArgument(json.MustEncode(txs)).
					AddArgument(json.MustEncode(coinbase)).
					Build()
				require.NoError(t, err)

				state, output, err := vm.Run(ctx, fvm.Transaction(txBody, 0), snapshot)
				require.NoError(t, err)
				require.Error(t, output.Err)
				require.ErrorContains(t, output.Err, "insufficient computation")
				require.Empty(t, state.WriteSet)
			})
	})
```
