### Title
Unchecked EVM Call Result in `CadenceOwnedAccount.call()` and `CadenceOwnedAccount.deploy()` Enables Silent Cross-VM Asset Transfer Failures - (File: fvm/evm/stdlib/contract.cdc)

---

### Summary

`CadenceOwnedAccount.call()` and `CadenceOwnedAccount.deploy()` in `fvm/evm/stdlib/contract.cdc` return a `Result` struct whose `status` field is never enforced by the protocol. At the Go layer (`fvm/evm/handler/handler.go`), `Account.Call()` and `Account.Deploy()` only call `panicOnError(err)` — not `panicOnErrorOrInvalidOrFailedState(res, err)` — so a failed EVM execution (out-of-gas, revert, `StatusFailed`) does **not** cause the enclosing Cadence transaction to revert. This is the direct Flow analog of unchecked ERC-20 `transfer()`/`transferFrom()` return values.

---

### Finding Description

**Root cause in Go handler:**

`Account.Call()` and `Account.Deploy()` in `fvm/evm/handler/handler.go` only guard against backend/fatal errors:

```go
// handler.go ~L1041-1059
func (a *Account) Call(...) *types.ResultSummary {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnError(err)          // ← only fatal/backend errors
    return res.ResultSummary() // ← StatusFailed silently returned
}

func (a *Account) Deploy(...) *types.ResultSummary {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnError(err)          // ← same: no check for StatusFailed
    return res.ResultSummary()
}
```

In contrast, the asset-critical operations `Deposit()`, `Withdraw()`, and `Transfer()` all call `panicOnErrorOrInvalidOrFailedState(res, err)`, which panics on `StatusFailed` or `StatusInvalid`:

```go
// handler.go ~L959-1010
func (a *Account) Deposit(v *types.FLOWTokenVault) {
    res, err := a.fch.executeAndHandleCall(...)
    panicOnErrorOrInvalidOrFailedState(res, err) // ← enforced
}
func (a *Account) Withdraw(b types.Balance) *types.FLOWTokenVault {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnErrorOrInvalidOrFailedState(res, err) // ← enforced
}
func (a *Account) Transfer(to types.Address, balance types.Balance) {
    res, err := a.executeAndHandleAuthorizedCall(...)
    panicOnErrorOrInvalidOrFailedState(res, err) // ← enforced
}
```

**Cadence surface:**

`CadenceOwnedAccount.call()` and `CadenceOwnedAccount.deploy()` in `contract.cdc` simply return the `Result` to the caller with no post-condition:

```cadence
// contract.cdc ~L636-653
access(Owner | Call)
fun call(to: EVMAddress, data: [UInt8], gasLimit: UInt64, value: Balance): Result {
    pre { !EVM.isPaused(): "EVM operations are temporarily paused" }
    return InternalEVM.call(
        from: self.addressBytes, to: to.bytes,
        data: data, gasLimit: gasLimit, value: value.attoflow
    ) as! Result
    // ← no post { result.status == Status.successful }
}

// contract.cdc ~L617-632
access(Owner | Deploy)
fun deploy(code: [UInt8], gasLimit: UInt64, value: Balance): Result {
    pre { !EVM.isPaused(): "EVM operations are temporarily paused" }
    return InternalEVM.deploy(...) as! Result
    // ← no post { result.status == Status.successful }
}
```

The `EVM.Status` enum explicitly defines three non-success states (`unknown`, `invalid`, `failed`) that a caller can silently ignore:

```cadence
// contract.cdc ~L342-365
access(all) enum Status: UInt8 {
    access(all) case unknown
    access(all) case invalid
    access(all) case failed
    access(all) case successful
}
```

---

### Impact Explanation

A Cadence contract acting as a cross-VM bridge or DEX that calls `coa.call()` to pull EVM-side tokens into escrow before releasing Cadence-side assets — without checking `res.status` — will proceed to release Cadence assets even when the EVM call reverted (e.g., because the user never approved the EVM token spend). The EVM state is rolled back (tokens stay with the user), but the Cadence transaction is not rolled back, so the contract releases Cadence-side assets for free. This constitutes unauthorized access to on-chain assets via cross-VM asset mis-accounting.

---

### Likelihood Explanation

Medium. The asymmetry between `call()`/`deploy()` (no enforcement) and `deposit()`/`withdraw()`/`transfer()` (enforced) is subtle and undocumented at the Cadence interface level. Any Cadence contract author building a cross-VM bridge or DEX who follows the pattern of calling `coa.call()` for token ingress without inspecting `res.status` introduces this vulnerability. The entry path requires only an unprivileged Cadence transaction sender interacting with such a contract.

---

### Recommendation

Apply the same enforcement pattern used by `Deposit()`, `Withdraw()`, and `Transfer()` to `call()` and `deploy()`. Either:

1. Add a Cadence `post`-condition to `CadenceOwnedAccount.call()` and `CadenceOwnedAccount.deploy()` in `contract.cdc`:
   ```cadence
   post { result.status == Status.successful: "EVM call failed" }
   ```
2. Or, at the Go layer in `handler.go`, change `Account.Call()` and `Account.Deploy()` to use `panicOnErrorOrInvalidOrFailedState(res, err)` instead of `panicOnError(err)`, consistent with `Deposit()`, `Withdraw()`, and `Transfer()`.
3. At minimum, add a "safe" variant (analogous to `SafeERC20.safeTransfer()`) that enforces success, and document clearly that the base `call()`/`deploy()` variants require explicit result checking.

---

### Proof of Concept

```cadence
import EVM from 0x...

// Vulnerable Cadence bridge contract pattern
transaction {
    prepare(signer: auth(Storage) &Account) {
        let coa = signer.storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(
            from: /storage/evmCOA
        )!

        // Attempt to pull EVM tokens from user into COA escrow.
        // If the EVM contract reverts (e.g., user never approved),
        // res.status == EVM.Status.failed — but NO panic occurs.
        let res = coa.call(
            to: EVM.EVMAddress(bytes: [/* EVM token contract */]),
            data: [/* transferFrom(user, coa, amount) calldata */],
            gasLimit: 100_000,
            value: EVM.Balance(attoflow: 0)
        )

        // res.status is EVM.Status.failed here — EVM state reverted,
        // tokens NOT transferred — but Cadence execution continues.

        // Bridge contract now incorrectly releases Cadence-side assets:
        // releaseCadenceAssets(to: signer.address, amount: X)
        // → attacker receives Cadence assets without paying EVM tokens.
    }
}
```

**Key code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** fvm/evm/handler/handler.go (L959-1011)
```go
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
}

// Transfer transfers tokens between accounts
func (a *Account) Transfer(to types.Address, balance types.Balance) {
	res, err := a.executeAndHandleAuthorizedCall(
		types.NewTransferCall(
			a.address,
			to,
			balance,
			a.Nonce(),
		),
		nil,
		false,
	)
	panicOnErrorOrInvalidOrFailedState(res, err)
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
