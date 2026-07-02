### Title
Unchecked EVM Call Result Enables Silent Cross-VM Value Transfer Failure in `CadenceOwnedAccount.call()` — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.CadenceOwnedAccount.call()` and `EVM.mustRun()` return an `EVM.Result` struct without enforcing that the EVM execution succeeded. When a non-zero `value` (FLOW tokens) is included in a `coa.call()` invocation and the EVM call reverts or fails, the Cadence transaction continues executing without error. The caller receives a `Result` with `status == failed` but is not required to inspect it. This is the direct Flow analog to the deprecated Solidity `.send()` / `.transfer()` pattern: a value-bearing call whose failure is silently swallowed.

---

### Finding Description

`EVM.CadenceOwnedAccount.call()` is defined in `fvm/evm/stdlib/contract.cdc` as:

```cadence
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

The returned `EVM.Result` carries a `status` field that can be `successful`, `failed`, or `invalid`. There is no `post` condition, no `assert`, and no panic enforcing that `status == successful`. The Cadence runtime does not revert the enclosing transaction when the EVM call fails.

At the Go layer, `Account.Call()` in `fvm/evm/handler/handler.go` only calls `panicOnError(err)` — it deliberately does **not** call `panicOnErrorOrInvalidOrFailedState(res, err)`, which is the guard used by `Deposit()` and `Withdraw()`:

```go
func (a *Account) Call(...) *types.ResultSummary {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnError(err)          // only panics on Go-level errors
    return res.ResultSummary() // failed/invalid EVM result returned silently
}
```

Compare with `Withdraw()`:
```go
func (a *Account) Withdraw(b types.Balance) *types.FLOWTokenVault {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnErrorOrInvalidOrFailedState(res, err) // panics on failed/invalid
    return types.NewFlowTokenVault(b)
}
```

Additionally, `EVM.mustRun()` is misleadingly named: it only asserts that the status is not `unknown` or `invalid`, explicitly allowing `failed` to pass through:

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

A `failed` EVM transaction means the EVM state was reverted — no FLOW was transferred — yet the Cadence transaction proceeds.

---

### Impact Explanation

When a Cadence transaction or contract uses `coa.call(to: target, data: ..., gasLimit: ..., value: nonZeroBalance)` to transfer FLOW tokens to an EVM address and does not check `res.status`:

1. The EVM call executes and reverts (e.g., the target contract's `receive()` or `fallback()` reverts, or gas runs out).
2. The EVM state is rolled back — no FLOW is credited to the target.
3. The Cadence transaction does **not** revert; it continues and commits.
4. Any Cadence-side state changes that assumed the transfer succeeded (e.g., marking a payment as complete, releasing an escrowed resource, updating an accounting ledger) are committed with incorrect state.

This constitutes **cross-VM asset accounting error**: the Cadence side records a transfer that never occurred on the EVM side. In bridge or escrow contexts this directly maps to **bridge escrow mis-accounting** — the class of impact in scope.

---

### Likelihood Explanation

The entry path is reachable by any unprivileged transaction sender:

1. An attacker deploys a malicious EVM contract whose `receive()` or `fallback()` unconditionally reverts.
2. The attacker interacts with any Cadence contract that uses `coa.call()` with a non-zero `value` to pay that EVM address (e.g., a Cadence-side marketplace, bridge, or payment contract that does not assert `res.status == EVM.Status.successful`).
3. The Cadence contract's payment step silently fails; the contract proceeds as if payment was made.

The `EVM.run()` / `EVM.mustRun()` surface is similarly reachable: any Cadence transaction relaying an EVM transaction that transfers value can observe a `failed` result without the outer Cadence transaction reverting.

---

### Recommendation

1. **For `CadenceOwnedAccount.call()` with non-zero value**: Add a `post` condition or an explicit `assert` enforcing `result.status == EVM.Status.successful` when `value.attoflow > 0`, or document clearly that callers **must** check the result and add a companion `callOrPanic()` variant that enforces success.

2. **For `EVM.mustRun()`**: Rename to `mustRunOrFail()` to reflect that it permits `failed` outcomes, or change the assertion to require `status == successful` to match the semantic implied by "must".

3. **At the Go layer**: Consider aligning `Account.Call()` with `Account.Withdraw()` / `Account.Deposit()` by calling `panicOnErrorOrInvalidOrFailedState` when a non-zero balance is involved, so that a failed value-bearing call panics and reverts the Cadence transaction.

---

### Proof of Concept

A Cadence transaction that silently loses a value transfer:

```cadence
import EVM from <EVMContractAddress>

transaction {
    prepare(signer: auth(Storage) &Account) {
        let coa = signer.storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(
            from: /storage/evmCOA
        ) ?? panic("no COA")

        let target = EVM.EVMAddress(bytes: /* malicious reverting contract address */)
        let bal = EVM.Balance(attoflow: 1_000_000_000_000_000_000) // 1 FLOW

        // Result is returned but never checked.
        // If target reverts, status == failed, FLOW is NOT transferred,
        // but this transaction commits successfully.
        let res = coa.call(to: target, data: [], gasLimit: 100_000, value: bal)

        // Cadence-side accounting proceeds as if payment succeeded:
        // e.g., markOrderFulfilled(), releaseEscrow(), etc.
    }
}
```

The root cause is confirmed at: [1](#0-0) 

The Go-layer asymmetry between `Call()` (no result enforcement) and `Withdraw()` / `Deposit()` (full result enforcement): [2](#0-1) [3](#0-2) 

The `panicOnErrorOrInvalidOrFailedState` guard that `Call()` omits: [4](#0-3) 

The misleading `mustRun()` that permits `failed` outcomes: [5](#0-4) 

The `EVM.Status` enum confirming `failed` means EVM state was reverted but the call was included: [6](#0-5)

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

**File:** fvm/evm/handler/handler.go (L978-996)
```go
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
