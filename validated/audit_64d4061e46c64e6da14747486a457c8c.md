### Title
Unprotected Narrowing Cast of EVM Transaction Index from `uint` to `uint16` - (File: `fvm/evm/emulator/emulator.go`)

### Summary
The EVM emulator's `run` function performs an unguarded narrowing cast of `BlockTxCountSoFar` (type `uint`, 64-bit on 64-bit platforms) to `uint16` when assigning `res.Index`. If a Flow EVM block accumulates more than 65,535 EVM transactions, the index silently wraps around, causing multiple distinct EVM transactions to share the same `Index` value in their on-chain event payloads.

### Finding Description
In `fvm/evm/emulator/emulator.go`, the `run` function reads the current block transaction count and casts it directly to `uint16` without any bounds check:

```go
txIndex := proc.config.BlockTxCountSoFar   // type: uint (64-bit)
...
res.Index = uint16(txIndex)                 // silent truncation if txIndex > 65535
``` [1](#0-0) 

`BlockTxCountSoFar` is declared as `uint` in `Config`: [2](#0-1) 

It is populated from `BlockContext.TxCountSoFar` (also `uint`): [3](#0-2) 

And set at block-execution time from the length of already-included transaction hashes: [4](#0-3) 

The `Result.Index` field is typed `uint16`: [5](#0-4) 

This `Index` is serialised into the on-chain `TransactionEventPayload` (also `uint16`) that is emitted for every EVM transaction and consumed by bridges, block explorers, and off-chain replay: [6](#0-5) 

By contrast, the codebase already demonstrates the correct pattern for a similar narrowing cast in `engine/execution/block_result.go`, where a bounds check and explicit panic are used before casting `serviceEventCount` to `uint16`: [7](#0-6) 

No equivalent guard exists for the EVM transaction index cast.

### Impact Explanation
When `BlockTxCountSoFar` exceeds 65,535, the cast `uint16(txIndex)` silently wraps (e.g., transaction 65,536 gets index 0, colliding with the first transaction). The corrupted `Index` is written into the immutable on-chain EVM transaction event. Any consumer that relies on the `Index` field for deduplication or ordering — including cross-VM bridges that match EVM receipts to Flow events — may process a transaction twice or skip it entirely, leading to bridge escrow mis-accounting and potential cross-VM asset loss.

### Likelihood Explanation
The Flow EVM block gas limit is set to `math.MaxUint64` (`DefaultBlockLevelGasLimit`), and the minimum gas per EVM transaction is 21,000. The practical ceiling is the Flow block computation limit, which currently makes accumulating >65,535 EVM transactions in a single block very difficult under normal conditions. However, the absence of any guard means the truncation is a latent defect that would silently activate if block capacity parameters are ever relaxed, or if a future protocol change increases throughput. No privileged access is required; any unprivileged sender can submit EVM transactions via `EVM.run` or `EVM.batchRun`.

### Recommendation
Add an explicit bounds check before the cast, mirroring the pattern already used for `ServiceEventCountForChunk`:

```go
txIndex := proc.config.BlockTxCountSoFar
if txIndex > math.MaxUint16 {
    panic(fmt.Sprintf("EVM tx index (%d) exceeds uint16 maximum", txIndex))
}
res.Index = uint16(txIndex)
```

Alternatively, widen `Result.Index` and `TransactionEventPayload.Index` to `uint32` to match the Flow transaction index type used elsewhere in the protocol.

### Proof of Concept
1. Construct a Flow block that includes more than 65,535 EVM transactions (e.g., via repeated `EVM.batchRun` calls within a single Flow block, each batch containing many zero-value transfers at 21,000 gas each).
2. Observe that `BlockTxCountSoFar` reaches 65,536 inside `run`.
3. The cast `uint16(65536)` evaluates to `0`, so transaction 65,537 is assigned `Index = 0` — identical to the first transaction in the block.
4. Both transactions emit on-chain events with `Index = 0`; a bridge or indexer treating `(blockHeight, Index)` as a unique key will mis-account one of them. [8](#0-7)

### Citations

**File:** fvm/evm/emulator/emulator.go (L699-717)
```go
	txIndex := proc.config.BlockTxCountSoFar
	// if pre-checks are passed, the exec result won't be nil
	if execResult != nil {
		res.GasConsumed = execResult.UsedGas
		res.MaxGasConsumed = execResult.MaxUsedGas
		res.Index = uint16(txIndex)
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
		proc.config.BlockTxCountSoFar += 1
```

**File:** fvm/evm/emulator/config.go (L46-48)
```go
	// transactions included in this block so far
	BlockTxCountSoFar uint
	// BlockTotalGasSoFar captures the total
```

**File:** fvm/evm/types/emulator.go (L44-44)
```go
	TxCountSoFar           uint
```

**File:** fvm/evm/handler/handler.go (L746-746)
```go
		TxCountSoFar:              uint(len(bp.TxHashes)),
```

**File:** fvm/evm/types/result.go (L95-96)
```go
	// transaction block inclusion index
	Index uint16
```

**File:** fvm/evm/events/events.go (L189-191)
```go
	Hash             gethCommon.Hash `cadence:"hash"`
	Index            uint16          `cadence:"index"`
	TransactionType  uint8           `cadence:"type"`
```

**File:** engine/execution/block_result.go (L55-63)
```go
func (er *BlockExecutionResult) ServiceEventCountForChunk(chunkIndex int) uint16 {
	serviceEventCount := len(er.collectionExecutionResults[chunkIndex].serviceEvents)
	if serviceEventCount > math.MaxUint16 {
		// The current protocol demands that the ServiceEventCount does not exceed 65535.
		// For defensive programming, we explicitly enforce this limit as 65k could be produced by a bug.
		// Execution nodes would be first to realize that this bound is violated, and crash (fail early).
		panic(fmt.Sprintf("service event count (%d) exceeds maximum value of 65535", serviceEventCount))
	}
	return uint16(serviceEventCount)
```
