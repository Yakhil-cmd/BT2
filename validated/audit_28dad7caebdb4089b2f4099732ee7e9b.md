### Title
Silent EVM Execution Failure via `EVM.mustRun()` Non-Revert on `Status.failed` — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The Flow EVM system contract exposes a result-code error propagation pattern that is the direct analog of the Compound Finance vulnerability described in the external report. `EVM.run()`, `EVM.mustRun()`, `coa.call()`, and `coa.deploy()` all return a `Result` struct carrying a `status` enum and `errorCode` integer instead of reverting on EVM execution failure. Critically, `EVM.mustRun()` — whose name implies a hard guarantee of successful execution — explicitly permits `Status.failed` results to pass through without reverting. Any Cadence transaction or contract author who calls these functions without inspecting the returned `Result.status` will silently proceed after an EVM execution failure, with the outer Cadence transaction committing successfully.

---

### Finding Description

The `EVM.Status` enum and `EVM.Result` struct in `fvm/evm/stdlib/contract.cdc` implement a result-code pattern:

```cadence
access(all) enum Status: UInt8 {
    access(all) case unknown
    access(all) case invalid
    access(all) case failed
    access(all) case successful
}

access(all) struct Result {
    access(all) let status: Status
    access(all) let errorCode: UInt64
    access(all) let errorMessage: String
    ...
}
``` [1](#0-0) 

`EVM.run()` returns this struct unconditionally — it never reverts on EVM failure:

```cadence
access(all)
fun run(tx: [UInt8], coinbase: EVMAddress): Result {
    pre { !self.isPaused(): "EVM operations are temporarily paused" }
    return InternalEVM.run(tx: tx, coinbase: coinbase.bytes) as! Result
}
``` [2](#0-1) 

`EVM.mustRun()` — the function whose name implies a hard execution guarantee — only asserts that the status is not `unknown` or `invalid`. It explicitly allows `Status.failed` to pass through without reverting:

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
``` [3](#0-2) 

The same pattern applies to `coa.call()` and `coa.deploy()`, which return `Result` without any assertion:

```cadence
access(Owner | Call)
fun call(to: EVMAddress, data: [UInt8], gasLimit: UInt64, value: Balance): Result {
    pre { !EVM.isPaused(): "EVM operations are temporarily paused" }
    return InternalEVM.call(...) as! Result
}
``` [4](#0-3) 

```cadence
access(Owner | Deploy)
fun deploy(code: [UInt8], gasLimit: UInt64, value: Balance): Result {
    pre { !EVM.isPaused(): "EVM operations are temporarily paused" }
    return InternalEVM.deploy(...) as! Result
}
``` [5](#0-4) 

At the Go layer, `ResultSummary()` defaults `Status` to `StatusSuccessful` and only overrides it if `Invalid()` or `Failed()` is true — meaning an unexamined result carries an implicit "success" assumption:

```go
func (res *Result) ResultSummary() *ResultSummary {
    rs := &ResultSummary{
        ...
        Status: StatusSuccessful,  // default assumption: success
    }
    if res.Invalid() { rs.Status = StatusInvalid; return rs }
    if res.Failed()  { rs.Status = StatusFailed;  return rs }
    return rs
}
``` [6](#0-5) 

This mirrors the Compound Finance pattern exactly: the default assumption is "no error" unless the caller explicitly checks.

---

### Impact Explanation

Any Cadence transaction or contract author who calls `EVM.mustRun()`, `EVM.run()`, `coa.call()`, or `coa.deploy()` and does not inspect `res.status` will silently continue execution after an EVM failure. The outer Cadence transaction commits successfully. Concrete consequences include:

- **Cross-VM asset loss**: A Cadence contract that calls `coa.call()` to execute an EVM token transfer, then releases escrowed Cadence-side assets assuming success, will release assets even when the EVM transfer reverted.
- **Bridge escrow mis-accounting**: A bridge contract that calls `EVM.run()` to mint EVM-side tokens and does not check the result will record a successful bridge while no EVM tokens were minted.
- **State inconsistency**: Cadence-side state (balances, ownership records) diverges from EVM-side state, permanently.

The `mustRun()` naming is particularly dangerous: a contract author reading the name reasonably concludes it will revert on any failure. The documented behavior — that it does not revert on `Status.failed` — is counter-intuitive and easy to miss.

---

### Likelihood Explanation

The entry path requires only an unprivileged Cadence transaction sender. Any user can:

1. Deploy a Cadence contract that uses `EVM.mustRun()` or `coa.call()` without checking `res.status`.
2. Submit a Cadence transaction that calls into that contract with an EVM payload crafted to fail (e.g., insufficient gas, execution revert, nonce mismatch).
3. The EVM operation fails silently; the Cadence transaction commits.

The misleading `mustRun` name increases the probability that contract authors will not add a secondary status check. The pattern is also inconsistent: `EVM.mustRun()` reverts on `unknown`/`invalid` but not on `failed`, while `coa.withdraw()` panics directly on failure — creating the same inconsistency noted in the external report between `CEther.mint` (reverts) and `CErc20.mint` (returns error code). [7](#0-6) 

---

### Recommendation

1. **`EVM.mustRun()` should revert on `Status.failed`** as well, or be renamed to `EVM.runIfValid()` to accurately reflect that it only guards against `unknown`/`invalid` status.
2. Introduce a `EVM.runOrPanic()` / `EVM.runOrRevert()` variant that asserts `status == Status.successful` and panics otherwise, giving callers a safe default.
3. Audit all Cadence contracts (including bridge contracts) that call `EVM.run()`, `coa.call()`, or `coa.deploy()` to verify they check `res.status` before proceeding.
4. Consider aligning the API with the `coa.withdraw()` pattern, which panics directly on failure rather than returning a result code.

---

### Proof of Concept

A Cadence transaction that demonstrates the silent failure:

```cadence
import EVM from <EVM_ADDRESS>

transaction(tx: [UInt8], coinbaseBytes: [UInt8; 20]) {
    prepare(account: &Account) {
        let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)

        // mustRun sounds like it will revert on failure.
        // It does NOT revert when status == Status.failed.
        let res = EVM.mustRun(tx: tx, coinbase: coinbase)

        // Caller omits: assert(res.status == EVM.Status.successful, ...)
        // Execution continues here even if the EVM tx reverted.
        // The Cadence transaction commits successfully.
    }
}
```

Submit this with an EVM transaction that reverts (e.g., calls a Solidity function that executes `revert()`). The Flow transaction will succeed with `output.Err == nil`, the EVM state will be unchanged, but any Cadence-side state mutations after the `mustRun` call will be committed. [3](#0-2) [8](#0-7)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L341-415)
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

    /// Reports the outcome of an evm transaction/call execution attempt
    access(all) struct Result {
        /// status of the execution
        access(all) let status: Status

        /// error code (error code zero means no error)
        access(all) let errorCode: UInt64

        /// error message
        access(all) let errorMessage: String

        /// returns the amount of gas metered during
        /// evm execution
        access(all) let gasUsed: UInt64

        /// returns the data that is returned from
        /// the evm for the call. For coa.deploy
        /// calls it returns the code deployed to
        /// the address provided in the contractAddress field.
        /// in case of revert, the smart contract custom error message
        /// is also returned here (see EIP-140 for more details).
        access(all) let data: [UInt8]

        /// returns the newly deployed contract address
        /// if the transaction caused such a deployment
        /// otherwise the value is nil.
        access(all) let deployedContract: EVMAddress?

        init(
            status: Status,
            errorCode: UInt64,
            errorMessage: String,
            gasUsed: UInt64,
            data: [UInt8],
            contractAddress: [UInt8; 20]?
        ) {
            self.status = status
            self.errorCode = errorCode
            self.errorMessage = errorMessage
            self.gasUsed = gasUsed
            self.data = data

            if let addressBytes = contractAddress {
                self.deployedContract = EVMAddress(bytes: addressBytes)
            } else {
                self.deployedContract = nil
            }
        }
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L586-606)
```text
        access(Owner | Withdraw)
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            if balance.isZero() {
                return <-FlowToken.createEmptyVault(vaultType: Type<@FlowToken.Vault>())
            }
            let vault <- InternalEVM.withdraw(
                from: self.addressBytes,
                amount: balance.attoflow
            ) as! @FlowToken.Vault
            emit FLOWTokensWithdrawn(
                address: self.address().toString(),
                amount: balance.inFLOW(),
                withdrawnUUID: vault.uuid,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
            return <-vault
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L617-632)
```text
        access(Owner | Deploy)
        fun deploy(
            code: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.deploy(
                from: self.addressBytes,
                code: code,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
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

**File:** fvm/evm/types/result.go (L30-42)
```go
var (
	StatusUnknown Status = 0
	// StatusInvalid shows that the transaction was not a valid
	// transaction and rejected to be executed and included in any block.
	StatusInvalid Status = 1
	// StatusFailed shows that the transaction has been executed,
	// but the output of the execution was an error
	// for this case a block is formed and receipts are available
	StatusFailed Status = 2
	// StatusSuccessful shows that the transaction has been executed and the execution has returned success
	// for this case a block is formed and receipts are available
	StatusSuccessful Status = 3
)
```

**File:** fvm/evm/types/result.go (L279-304)
```go
// ResultSummary constructs a result summary
func (res *Result) ResultSummary() *ResultSummary {
	rs := &ResultSummary{
		GasConsumed:             res.GasConsumed,
		MaxGasConsumed:          res.MaxGasConsumed,
		DeployedContractAddress: res.DeployedContractAddress,
		ReturnedData:            res.ReturnedData,
		Status:                  StatusSuccessful,
	}

	if res.Invalid() {
		rs.ErrorCode = ValidationErrorCode(res.ValidationError)
		rs.ErrorMessage = res.ValidationError.Error()
		rs.Status = StatusInvalid
		return rs
	}

	if res.Failed() {
		rs.ErrorCode = ExecutionErrorCode(res.VMError)
		rs.ErrorMessage = res.VMError.Error()
		rs.Status = StatusFailed
		return rs
	}

	return rs
}
```
