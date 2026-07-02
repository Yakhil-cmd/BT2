### Title
`EVM.mustRun()` Does Not Revert on Failed EVM Execution, Enabling Silent Cross-VM Transfer Failures - (File: fvm/evm/stdlib/contract.cdc)

### Summary
The `EVM.mustRun()` function in the EVM system contract only asserts that the EVM transaction is not `invalid` (validation failure), but does **not** assert that it is `successful`. A `failed` EVM transaction — such as a reverted ERC20 transfer — passes the `mustRun` assertion silently. Any Cadence transaction or contract that uses `mustRun` to execute an EVM token transfer and then proceeds to update Cadence state based on the assumption that the transfer succeeded is vulnerable to cross-VM asset loss.

### Finding Description
`EVM.mustRun()` is defined in `fvm/evm/stdlib/contract.cdc` as:

```cadence
fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
    let runResult = self.run(tx: tx, coinbase: coinbase)
    assert(
        runResult.status == Status.failed || runResult.status == Status.successful,
        message: "EVM.mustRun(): The provided transaction is not valid for execution"
    )
    return runResult
}
``` [1](#0-0) 

The assertion `runResult.status == Status.failed || runResult.status == Status.successful` only rejects `Status.invalid` (pre-execution validation failures such as nonce mismatch). It explicitly allows `Status.failed` — which covers all EVM execution errors including out-of-gas, `REVERT`, and failed ERC20 transfers — to pass through without reverting the enclosing Cadence transaction.

The three EVM statuses are:

- `invalid`: transaction rejected before execution (nonce mismatch, gas limit exceeded, etc.) — NOT included in a block
- `failed`: transaction executed but the EVM reported an error (revert, out-of-gas) — **included in a block**
- `successful`: transaction executed without error [2](#0-1) 

The `TransactionExecuted` event is emitted for both `failed` and `successful` transactions (only skipped for `invalid`), as confirmed in the handler: [3](#0-2) 

This means a Cadence transaction that calls `EVM.mustRun()` to execute an EVM ERC20 transfer, then proceeds to update Cadence state (e.g., minting Cadence-side tokens, recording a bridge deposit), will continue executing even when the EVM transfer reverted. The `TransactionExecuted` event is emitted with `errorCode != 0`, but the Cadence transaction is not rolled back.

The name `mustRun` strongly implies "must succeed," directly analogous to the unchecked `transfer()` return value in the original report: the operation appears to have been performed, but the actual asset movement failed silently.

### Impact Explanation
A Cadence bridge contract or user transaction that uses `EVM.mustRun()` to:
1. Burn ERC20 tokens on the EVM side, then
2. Mint equivalent Cadence fungible tokens

...would mint Cadence tokens even if the EVM burn reverted. This constitutes **cross-VM asset loss / bridge escrow mis-accounting**: Cadence-side supply increases without a corresponding EVM-side decrease, allowing an attacker to obtain Cadence tokens for free.

### Likelihood Explanation
Medium. The function name `mustRun` strongly implies guaranteed execution success, making it likely that Cadence contract authors will use it without additionally asserting `result.status == EVM.Status.successful`. The behavior is documented in a comment, but the misleading name overrides the documentation in practice. Any bridge or settlement contract using `mustRun` for token transfers without an explicit success check is vulnerable. The entry path requires only an unprivileged Cadence transaction sender — no privileged access is needed.

### Recommendation
Either:
1. Add a `mustRunSuccessful` variant that asserts `runResult.status == Status.successful`, or
2. Change the existing assertion in `mustRun` to `runResult.status == Status.successful`, and document the current behavior under a different name (e.g., `runIfValid`), or
3. At minimum, update the function name and documentation to make clear that `mustRun` does **not** guarantee the EVM operation succeeded.

### Proof of Concept
An unprivileged user submits the following Cadence transaction, where `tx` encodes an ERC20 `transfer()` call that will revert (e.g., insufficient balance):

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>

transaction(tx: [UInt8], coinbaseBytes: [UInt8; 20]) {
    prepare(account: &Account) {
        let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)

        // EVM ERC20 transfer that reverts → status == EVM.Status.failed
        let res = EVM.mustRun(tx: tx, coinbase: coinbase)

        // mustRun does NOT revert here — assertion passes because
        // (Status.failed || Status.successful) is satisfied.
        // res.status == EVM.Status.failed, res.errorCode != 0

        // Any subsequent Cadence state mutation proceeds as if the
        // EVM transfer succeeded:
        // e.g., emit a "transfer confirmed" event, mint Cadence tokens, etc.
    }
}
``` [4](#0-3) 

The `TransactionExecuted` event is emitted with a non-zero `errorCode` confirming the EVM failure, but the Cadence transaction is not reverted, directly mirroring the original unchecked ERC20 `transfer()` pattern where a failed transfer emits a success event.

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

**File:** fvm/evm/handler/handler.go (L522-534)
```go
	// step 7 - skip the rest if is invalid tx
	if res.Invalid() {
		return res, nil
	}

	// step 8 - update the block proposal
	bp.AppendTransaction(res)
	h.backend.StageBlockProposal(bp)

	// step 9 - emit transaction event
	err = h.emitEvent(
		events.NewTransactionEvent(res, rlpEncodedTx, bp.Height),
	)
```
