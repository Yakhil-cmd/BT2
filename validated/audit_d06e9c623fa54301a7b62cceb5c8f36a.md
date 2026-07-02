### Title
Unchecked EVM Execution Result in `EVM.run()` / `mustRun()` Allows Silent Cross-VM Asset Loss - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
`EVM.run()` and `EVM.mustRun()` both return an `EVM.Result` struct whose `status` field can be `failed` (EVM execution reverted or ran out of gas) without causing the enclosing Cadence transaction to revert. This is the direct Flow analog of unchecked ERC20 `transfer()` return values: a Cadence transaction that submits an EVM token transfer via `EVM.run()` or `coa.call()` and does not explicitly assert `result.status == EVM.Status.successful` will silently proceed even though the EVM-side transfer never occurred, producing cross-VM asset mis-accounting.

### Finding Description
`EVM.run()` is a public, permissionless function defined in the EVM system contract:

```cadence
access(all)
fun run(tx: [UInt8], coinbase: EVMAddress): Result {
    pre {
        !self.isPaused(): "EVM operations are temporarily paused"
    }
    return InternalEVM.run(tx: tx, coinbase: coinbase.bytes) as! Result
}
```

It returns a `Result` struct whose `status` field is one of `unknown`, `invalid`, `failed`, or `successful`. A `failed` result means the EVM transaction was included in a block but the VM reported an error (e.g., ERC20 `transfer()` reverted, out-of-gas). The Cadence runtime does **not** automatically revert the outer Cadence transaction in this case.

`mustRun()` was introduced as a safer wrapper, but its assert only excludes `unknown`/`invalid`:

```cadence
fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
    let runResult = self.run(tx: tx, coinbase: coinbase)
    assert(
        runResult.status == Status.failed || runResult.status == Status.successful,
        message: "EVM.mustRun(): The provided transaction is not valid for execution"
    )
    return runResult
}
```

The inline comment explicitly states: *"Note that this method does not rollback if transaction is executed but an vm error is reported as the outcome of the execution (status: failed)."* A `failed` EVM transaction — including a reverted ERC20 `transfer` — passes through `mustRun()` without reverting the Cadence transaction.

`CadenceOwnedAccount.call()` has the same property:

```cadence
access(Owner | Call)
fun call(to: EVMAddress, data: [UInt8], gasLimit: UInt64, value: Balance): Result {
    pre { !EVM.isPaused(): "EVM operations are temporarily paused" }
    return InternalEVM.call(
        from: self.addressBytes, to: to.bytes,
        data: data, gasLimit: gasLimit, value: value.attoflow
    ) as! Result
}
```

The returned `Result` is discarded or unchecked by any caller that does not explicitly assert `result.status == EVM.Status.successful`.

### Impact Explanation
Any Cadence transaction that:
1. Calls `EVM.run()`, `mustRun()`, or `coa.call()` to perform an EVM-side token transfer (e.g., ERC20 `transfer`, native FLOW send), and
2. Does not assert `result.status == EVM.Status.successful` before updating Cadence-side state (e.g., recording a payment, releasing escrowed Cadence tokens, minting a Cadence NFT),

will silently proceed with a failed EVM transfer. The Cadence state is mutated as if the transfer succeeded, but the EVM-side tokens were never moved. This constitutes **cross-VM asset mis-accounting / loss**: the sender retains their EVM tokens while the Cadence side records the transfer as complete.

### Likelihood Explanation
The entry path requires only an unprivileged Cadence transaction sender. `EVM.run()` and `coa.call()` are `access(all)` / `access(Owner | Call)` — reachable by any account. The failure condition (EVM `status: failed`) is a normal, documented outcome (out-of-gas, contract revert, insufficient ERC20 balance). The protocol itself documents that `mustRun()` does not revert on `failed`, making it easy for contract authors to miss the check. The pattern is directly analogous to the well-known unchecked-ERC20-transfer class.

### Recommendation
1. **`mustRun()` should assert `successful`**, not merely `failed || successful`. The current assert is weaker than its name implies:
   ```cadence
   assert(
       runResult.status == Status.successful,
       message: "EVM.mustRun(): EVM transaction failed"
   )
   ```
2. Alternatively, introduce a `runOrRevert()` variant that panics on any non-`successful` status.
3. All Cadence code that calls `EVM.run()` or `coa.call()` for asset-moving operations must explicitly check `result.status == EVM.Status.successful` before updating Cadence state.

### Proof of Concept
The `mustRun()` function explicitly allows `status: failed` to pass through: [1](#0-0) 

`EVM.run()` returns a `Result` without any success enforcement: [2](#0-1) 

`CadenceOwnedAccount.call()` similarly returns an unchecked `Result`: [3](#0-2) 

The `Status` enum confirms `failed` is a distinct, non-reverting outcome: [4](#0-3) 

The Go-level `Result` type confirms `Failed()` is a normal, non-fatal condition: [5](#0-4)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L341-365)
```text
    /// reports the status of evm execution.
    access(all) enum Status: UInt8 {
        /// Returned (rarely) when status is unknown
        /// and something has gone very wrong.
        access(all) case unknown

        /// Returned when execution of an evm transaction/call
        /// has failed at the validation step (e.g. nonce mismatch).
        /// An invalid transaction/call is rejected to be executed
        /// or be included in a block.
        access(all) case invalid

        /// Returned when execution of an evm transaction/call
        /// has been successful but the vm has reported an error in
        /// the outcome of execution (e.g. running out of gas).
        /// A failed tx/call is included in a block.
        /// Note that resubmission of a failed transaction would
        /// result in invalid status in the second attempt, given
        /// the nonce would become invalid.
        access(all) case failed

        /// Returned when execution of an evm transaction/call
        /// has been successful and no error is reported by the vm.
        access(all) case successful
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L636-653)
```text
        access(Owner | Call)
        fun call(
            to: EVMAddress,
            data: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.call(
                from: self.addressBytes,
                to: to.bytes,
                data: data,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
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

**File:** fvm/evm/stdlib/contract.cdc (L838-851)
```text
    /// mustRun runs the transaction using EVM.run
    /// It will rollback if the tx execution status is unknown or invalid.
    /// Note that this method does not rollback if transaction
    /// is executed but an vm error is reported as the outcome
    /// of the execution (status: failed).
    access(all)
    fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
        let runResult = self.run(tx: tx, coinbase: coinbase)
        assert(
            runResult.status == Status.failed || runResult.status == Status.successful,
            message: "EVM.mustRun(): The provided transaction is not valid for execution"
        )
        return runResult
    }
```

**File:** fvm/evm/types/result.go (L109-117)
```go
// Failed returns true if transaction has been executed but VM has returned some error
func (res *Result) Failed() bool {
	return res.VMError != nil
}

// Successful returns true if transaction has been executed without any errors
func (res *Result) Successful() bool {
	return !res.Failed() && !res.Invalid()
}
```
