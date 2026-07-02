### Title
`EVM.mustRun()` Does Not Revert on `Status.failed`, Enabling Silent Cross-VM Transfer Failures - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.mustRun()` in `fvm/evm/stdlib/contract.cdc` is explicitly documented to **not** revert when an EVM transaction executes but the VM reports an error (`Status.failed`). Its name implies a success guarantee, but it only guards against `Status.invalid`. Any Cadence transaction that uses `mustRun` to perform an EVM token transfer (e.g., an ERC20 `transfer()`) and then takes action on the Cadence side based on an assumed success will silently proceed with a failed EVM transfer — a direct analog to the unchecked ERC20 return-value pattern.

---

### Finding Description

`EVM.mustRun()` is defined as:

```cadence
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
``` [1](#0-0) 

The `Status` enum has four values: `unknown`, `invalid`, `failed`, and `successful`. [2](#0-1) 

`mustRun` asserts only that the status is **not** `unknown` or `invalid`. It explicitly passes through `Status.failed` — meaning a reverted EVM call (e.g., an ERC20 `transfer()` that reverts due to insufficient balance, a paused token, or any other EVM-level error) returns to the Cadence caller **without reverting the Cadence transaction**.

At the Go layer, `Account.Call()` uses only `panicOnError(err)` — not `panicOnErrorOrInvalidOrFailedState` — so a failed EVM call result propagates back to the Cadence layer as a `ResultSummary` with `Status: StatusFailed` without triggering a panic: [3](#0-2) 

Compare this with internal protocol operations like `Deposit`, `Withdraw`, and `Transfer`, which correctly use `panicOnErrorOrInvalidOrFailedState`: [4](#0-3) 

The `panicOnErrorOrInvalidOrFailedState` helper panics on both `Invalid()` and `Failed()` states: [5](#0-4) 

The `Result.Failed()` method returns `true` when `VMError != nil`: [6](#0-5) 

---

### Impact Explanation

A Cadence transaction that:
1. Calls `EVM.mustRun()` to execute an ERC20 `transfer()` or `transferFrom()` on behalf of a user
2. Interprets the non-revert of `mustRun` as a success guarantee
3. Proceeds to release Cadence-side assets (e.g., unlocking escrowed NFTs, minting Cadence tokens, or crediting a balance)

…will silently release those assets even though the EVM-side token transfer failed. This constitutes **cross-VM asset loss**: Cadence assets are released without the corresponding EVM token payment being received.

The `coa.call()` function has the same surface — it returns a `Result` struct that callers must explicitly check: [7](#0-6) 

If a caller omits the `result.status == EVM.Status.successful` check, the failure is invisible.

---

### Likelihood Explanation

**Medium.** The name `mustRun` strongly implies a success guarantee — analogous to how `safeTransfer` implies safety. A Cadence transaction author integrating EVM token payments into a Cadence-side workflow is likely to use `mustRun` precisely because they want assurance the transaction ran, and may not read the fine-print that `Status.failed` is silently passed through. The `coa.call()` path has the same risk for any author who omits the status check. ERC20 tokens that revert on failure (the common case) would surface this as a `Status.failed` result.

---

### Recommendation

1. **Rename or redesign `mustRun`**: Either rename it to `runOrFail` / `runChecked` and have it assert `status == Status.successful`, or add a separate `mustRunSuccessful` variant that panics on `Status.failed`. The current name creates a false sense of safety.

2. **Add a `mustSucceed` assertion helper in the Cadence contract**: Provide a utility that Cadence transaction authors can call on any `Result` to assert `status == Status.successful`, analogous to OpenZeppelin's `SafeERC20.safeTransfer`.

3. **Document the risk prominently**: At minimum, add a warning in the `mustRun` docstring and in the `coa.call()` docstring that callers **must** check `result.status` before taking any Cadence-side action.

---

### Proof of Concept

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>

// Attacker scenario:
// 1. Attacker has an EVM address with 0 ERC20 balance.
// 2. A Cadence contract uses mustRun to collect ERC20 payment before releasing an NFT.
// 3. The ERC20 transfer() reverts (insufficient balance) → Status.failed.
// 4. mustRun does NOT revert the Cadence transaction.
// 5. The Cadence contract proceeds to release the NFT without receiving payment.

transaction(erc20TransferTx: [UInt8], coinbaseBytes: [UInt8; 20]) {
    prepare(account: &Account) {
        let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)

        // mustRun does NOT revert even if the ERC20 transfer() reverts inside EVM
        let result = EVM.mustRun(tx: erc20TransferTx, coinbase: coinbase)

        // result.status may be EVM.Status.failed here — no panic, no revert
        // A naive caller assumes success and proceeds:
        assert(result.status == EVM.Status.failed, message: "confirmed: failed tx passes mustRun")

        // Any subsequent Cadence asset release here executes without EVM payment
    }
}
```

The `mustRun` assert at line 846–849 passes for `Status.failed`: [8](#0-7) 

The `StatusFailed` value at the Go layer confirms this is a real, reachable state: [9](#0-8)

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

**File:** fvm/evm/handler/handler.go (L1041-1059)
```go
func (a *Account) Call(to types.Address, data types.Data, gaslimit types.GasLimit, balance types.Balance) *types.ResultSummary {
	// capture open tracing span
	defer a.fch.backend.StartChildSpan(trace.FVMEVMCall).End()

	res, err := a.executeAndHandleAuthorizedCall(
		types.NewContractCall(
			a.address,
			to,
			data,
			uint64(gaslimit),
			balance,
			a.Nonce(),
		),
		nil,
		false,
	)
	panicOnError(err)

	return res.ResultSummary()
```

**File:** fvm/evm/handler/handler.go (L1073-1089)
```go
func panicOnErrorOrInvalidOrFailedState(res *types.Result, err error) {

	if res != nil && res.Invalid() {
		panic(fvmErrors.NewEVMError(res.ValidationError))
	}

	if res != nil && res.Failed() {
		panic(fvmErrors.NewEVMError(res.VMError))
	}

	// this should never happen
	if err == nil && res == nil {
		panic(fvmErrors.NewEVMError(types.ErrUnexpectedEmptyResult))
	}

	panicOnError(err)
}
```

**File:** fvm/evm/types/result.go (L36-41)
```go
	// but the output of the execution was an error
	// for this case a block is formed and receipts are available
	StatusFailed Status = 2
	// StatusSuccessful shows that the transaction has been executed and the execution has returned success
	// for this case a block is formed and receipts are available
	StatusSuccessful Status = 3
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
