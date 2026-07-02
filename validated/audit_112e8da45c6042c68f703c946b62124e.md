### Title
Unchecked EVM Call Result Status in `EVM.run()` / `COA.call()` Enables Silent Cross-VM Transfer Failures — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.run()` and `COA.call()` in the Flow EVM Cadence contract return a `Result` struct whose `status` field (`unknown`, `invalid`, `failed`, `successful`) is never enforced to be checked by the caller. A Cadence transaction or contract that performs EVM token transfers via these functions without asserting `res.status == EVM.Status.successful` will silently succeed even when the underlying EVM execution reverts or runs out of gas — directly mirroring the unchecked `transfer()` return value pattern in the external report.

---

### Finding Description

`EVM.run()` is defined in `fvm/evm/stdlib/contract.cdc` as:

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

The returned `Result` struct carries a `status` field of enum type `Status`:

```cadence
access(all) enum Status: UInt8 {
    access(all) case unknown
    access(all) case invalid
    access(all) case failed      // EVM executed but reverted / out-of-gas
    access(all) case successful
}
``` [2](#0-1) 

`Status.failed` means the EVM transaction was included in a block but its execution produced a VM error (e.g., revert, out-of-gas). The Cadence runtime does **not** automatically revert the outer Cadence transaction when this status is returned — the caller must explicitly check it.

The safer variant `EVM.mustRun()` only asserts that the status is not `unknown`/`invalid`; it explicitly **does not** revert on `Status.failed`:

```cadence
fun mustRun(tx: [UInt8], coinbase: EVMAddress): Result {
    let runResult = self.run(tx: tx, coinbase: coinbase)
    assert(
        runResult.status == Status.failed || runResult.status == Status.successful,
        message: "EVM.mustRun(): The provided transaction is not valid for execution"
    )
    return runResult
}
``` [3](#0-2) 

The comment explicitly states: *"Note that this method does not rollback if transaction is executed but an vm error is reported as the outcome of the execution (status: failed)."*

The same pattern applies to `COA.call()`, which is backed by `Account.Call()` in Go:

```go
func (a *Account) Call(...) *types.ResultSummary {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnError(err)   // only checks Go-level errors
    return res.ResultSummary()
}
``` [4](#0-3) 

Contrast this with `Account.Deposit()`, `Account.Withdraw()`, and `Account.Transfer()`, which all call `panicOnErrorOrInvalidOrFailedState(res, err)` — explicitly panicking (reverting the Cadence transaction) on `Status.failed`:

```go
func (a *Account) Deposit(v *types.FLOWTokenVault) {
    ...
    panicOnErrorOrInvalidOrFailedState(res, err)
}

func (a *Account) Withdraw(b types.Balance) *types.FLOWTokenVault {
    ...
    panicOnErrorOrInvalidOrFailedState(res, err)
}
``` [5](#0-4) 

`Account.Call()` deliberately omits this check and returns the result to the Cadence caller, placing the entire burden of status validation on the Cadence transaction author.

---

### Impact Explanation

A Cadence transaction or contract that calls `EVM.run()` or `COA.call()` to perform an EVM-side token transfer (e.g., ERC-20 `transfer`, bridge mint/burn) without asserting `res.status == EVM.Status.successful` will:

1. Succeed at the Cadence level (no panic, no revert).
2. Emit a `TransactionExecuted` event with `errorCode != 0` and `status == failed`.
3. Leave the EVM-side state unchanged (the token transfer did not happen).
4. Potentially advance Cadence-side accounting (e.g., marking a bridge transfer as complete, releasing escrowed assets) based on a transfer that never occurred.

This constitutes **cross-VM asset loss** and **bridge escrow mis-accounting** — the exact impact class targeted by the external report.

---

### Likelihood Explanation

Any Cadence contract author who uses `EVM.run()` or `COA.call()` to perform EVM token transfers is exposed. The API design actively encourages this pattern: `EVM.run()` is the primary public entry point for submitting EVM transactions from Cadence, and its documentation does not require callers to check the result. `EVM.mustRun()` provides a false sense of safety because its name implies "must succeed" but it explicitly allows `Status.failed` through. An unprivileged transaction sender can trigger the failure condition by, for example, ensuring the EVM account has insufficient gas or that the target ERC-20 contract reverts.

---

### Recommendation

**Short term:** Every call to `EVM.run()` or `COA.call()` that performs an asset transfer must be followed by an explicit status assertion:

```cadence
let res = EVM.run(tx: tx, coinbase: coinbase)
assert(res.status == EVM.Status.successful,
    message: "EVM transfer failed: ".concat(res.errorMessage))
```

**Long term:** Introduce a `EVM.safeRun()` function (analogous to Solidity's `safeTransfer`) that automatically reverts the Cadence transaction if the EVM result status is not `successful`. Update `EVM.mustRun()` to also assert on `Status.failed`, or rename it to avoid the misleading implication of guaranteed success.

---

### Proof of Concept

The following Cadence transaction silently succeeds even when the EVM ERC-20 transfer reverts:

```cadence
import EVM from <EVM_ADDRESS>

transaction(encodedERC20Transfer: [UInt8], coinbaseBytes: [UInt8; 20]) {
    prepare(signer: auth(Storage) &Account) {
        let coinbase = EVM.EVMAddress(bytes: coinbaseBytes)

        // EVM.run returns Result with status == Status.failed if the
        // ERC-20 transfer reverts (e.g., insufficient balance, paused token).
        // No status check → Cadence transaction succeeds silently.
        let res = EVM.run(tx: encodedERC20Transfer, coinbase: coinbase)

        // res.status may be EVM.Status.failed here.
        // The Cadence transaction commits successfully.
        // Any Cadence-side state updates (e.g., bridge accounting) are persisted
        // even though the EVM transfer never occurred.
    }
}
```

The `Status` enum and `Result` struct confirm that `failed` is a valid non-reverting outcome returned to callers: [6](#0-5) [7](#0-6)

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

**File:** fvm/evm/stdlib/contract.cdc (L367-415)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L843-851)
```text
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

**File:** fvm/evm/handler/handler.go (L957-995)
```go
// Deposit deposits the token from the given vault into the flow evm main vault
// and update the account balance with the new amount
func (a *Account) Deposit(v *types.FLOWTokenVault) {
	defer a.fch.backend.StartChildSpan(trace.FVMEVMDeposit).End()

	bridge := a.fch.addressAllocator.NativeTokenBridgeAddress()
	bridgeAccount := a.fch.AccountByAddress(bridge, false)
	// Note: its not an authorized call
	res, err := a.fch.executeAndHandleCall(
		types.NewDepositCall(
			bridge,
			a.address,
			v.Balance(),
			bridgeAccount.Nonce(),
		),
		v.Balance(),
		false,
	)
	panicOnErrorOrInvalidOrFailedState(res, err)
}

// Withdraw deducts the balance from the account and
// withdraw and return flow token from the Flex main vault.
func (a *Account) Withdraw(b types.Balance) *types.FLOWTokenVault {
	defer a.fch.backend.StartChildSpan(trace.FVMEVMWithdraw).End()

	res, err := a.executeAndHandleAuthorizedCall(
		types.NewWithdrawCall(
			a.fch.addressAllocator.NativeTokenBridgeAddress(),
			a.address,
			b,
			a.Nonce(),
		),
		b,
		true,
	)
	panicOnErrorOrInvalidOrFailedState(res, err)

	return types.NewFlowTokenVault(b)
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
