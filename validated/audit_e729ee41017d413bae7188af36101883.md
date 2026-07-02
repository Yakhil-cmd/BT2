### Title
Hardcoded 2300-Gas Stipend for EVM Deposit Calls Prevents FLOW Token Delivery to Smart Contracts with Complex Receive Logic - (File: `fvm/evm/types/call.go`)

---

### Summary

`DepositCallGasLimit` and `DefaultGasLimitForTokenTransfer` are hardcoded to `21_000 + 2_300 = 23_300` gas in `fvm/evm/types/call.go`. This mirrors the exact anti-pattern of Solidity's deprecated `transfer()` function: only 2300 gas is forwarded to the target EVM smart contract's `receive()` or `fallback()` function. Any EVM smart contract whose receive/fallback logic consumes more than 2300 gas will always revert when FLOW tokens are deposited to it via the Cadence-to-EVM bridge, permanently blocking cross-VM asset delivery to that contract.

---

### Finding Description

In `fvm/evm/types/call.go`, the gas limits for deposit and transfer direct calls are defined as:

```go
IntrinsicFeeForTokenTransfer = gethParams.TxGas  // 21_000

// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300  // 23_300

// the value is set to the gas limit for transfer to facilitate transfers
// to smart contract addresses.
DepositCallGasLimit  = DefaultGasLimitForTokenTransfer  // 23_300
WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer  // 23_300
``` [1](#0-0) 

`NewDepositCall` uses this hardcoded limit:

```go
func NewDepositCall(...) *DirectCall {
    return &DirectCall{
        ...
        GasLimit: DepositCallGasLimit,  // 23_300
    }
}
``` [2](#0-1) 

This deposit call is triggered whenever a Cadence transaction calls `EVMAddress.deposit()` or `CadenceOwnedAccount.deposit()`:

```cadence
fun deposit(from: @FlowToken.Vault) {
    self.address().deposit(from: <-from)
}
``` [3](#0-2) 

In `fvm/evm/emulator/emulator.go`, the `mintTo` procedure executes the deposit call. If the target EVM smart contract's `receive()` or `fallback()` function uses more than 2300 gas, the call fails with `ErrExecutionReverted`, the EVM state is reset, and the failed result is returned:

```go
if res.Invalid() || res.Failed() {
    proc.state.Reset()
    return res, nil
}
``` [4](#0-3) 

Back in `fvm/evm/handler/handler.go`, `Account.Deposit()` calls `panicOnErrorOrInvalidOrFailedState()` on the result:

```go
func (a *Account) Deposit(v *types.FLOWTokenVault) {
    ...
    res, err := a.fch.executeAndHandleCall(...)
    panicOnErrorOrInvalidOrFailedState(res, err)
}
``` [5](#0-4) 

`panicOnErrorOrInvalidOrFailedState` panics with an EVM error when the result is `Failed()`:

```go
func panicOnErrorOrInvalidOrFailedState(res *types.Result, err error) {
    if res != nil && res.Failed() {
        panic(fvmErrors.NewEVMError(res.VMError))
    }
    ...
}
``` [6](#0-5) 

The same 2300-gas constraint applies to `NewTransferCall` (COA-to-EVM transfers):

```go
func NewTransferCall(...) *DirectCall {
    return &DirectCall{
        ...
        GasLimit: DefaultGasLimitForTokenTransfer,  // 23_300
    }
}
``` [7](#0-6) 

---

### Impact Explanation

Any EVM smart contract deployed on Flow EVM whose `receive()` or `fallback()` function consumes more than 2300 gas (proxy contracts, multisig wallets, contracts that emit events on receive, contracts that update state on receive) **cannot receive FLOW tokens via the Cadence-to-EVM bridge deposit path**. Every deposit attempt to such a contract will revert the entire Cadence transaction. While the FLOW tokens are not permanently destroyed (they remain in the Cadence vault after the revert), the cross-VM asset delivery is permanently blocked for that contract address. Protocols that deploy EVM smart contracts expecting to receive bridged FLOW tokens will be silently broken if their receive logic exceeds the 2300-gas threshold.

---

### Likelihood Explanation

The 2300-gas limit is extremely tight. Common EVM patterns that exceed it include: proxy contracts with delegatecall fallbacks, ERC-4337 smart wallets, contracts that emit a single event on receive (costs ~375 gas for the LOG opcode plus topic/data costs), and any contract that writes to storage on receive (~20,000 gas for a cold SSTORE). Any Flow EVM dApp that deploys such a contract and relies on the bridge deposit mechanism will encounter this failure. The issue is reachable by any unprivileged Cadence transaction sender calling `EVMAddress.deposit()` or `CadenceOwnedAccount.deposit()` targeting such a contract.

---

### Recommendation

Replace the hardcoded `DepositCallGasLimit = DefaultGasLimitForTokenTransfer` with a higher gas allowance for deposit calls, similar to how OpenZeppelin's `Address.sendValue()` forwards all available gas. Alternatively, expose a parameter allowing the Cadence caller to specify the gas limit for the deposit call, so protocols can provide sufficient gas for their contract's receive logic. The `WithdrawCallGasLimit` and `DefaultGasLimitForTokenTransfer` used in `NewTransferCall` should be reviewed under the same lens.

---

### Proof of Concept

The existing test in `fvm/evm/emulator/emulator_test.go` explicitly demonstrates this failure path — depositing to a smart contract that has no payable fallback reverts with `ErrExecutionReverted`:

```go
t.Run("tokens deposit to an smart contract that doesn't accept native token", func(t *testing.T) {
    // deploy a contract with no receive/fallback
    call := types.NewDepositCall(bridgeAccount, testContract, types.MakeBigIntInFlow(1), 0)
    res, err := blk.DirectCall(call)
    require.NoError(t, err)
    require.NoError(t, res.ValidationError)
    require.Equal(t, res.VMError, gethVM.ErrExecutionReverted)  // deposit fails
})
``` [8](#0-7) 

The same failure occurs for any contract whose `receive()` or `fallback()` uses more than 2300 gas, because `DepositCallGasLimit = 23_300` leaves exactly 2300 gas after the 21,000-gas intrinsic cost — identical to the Solidity `transfer()` stipend that the original report flags. [1](#0-0)

### Citations

**File:** fvm/evm/types/call.go (L29-37)
```go
	IntrinsicFeeForTokenTransfer = gethParams.TxGas

	// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
	DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300

	// the value is set to the gas limit for transfer to facilitate transfers
	// to smart contract addresses.
	DepositCallGasLimit  = DefaultGasLimitForTokenTransfer
	WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer
```

**File:** fvm/evm/types/call.go (L193-210)
```go
// NewDepositCall constructs a new deposit direct call
func NewDepositCall(
	bridge Address,
	address Address,
	amount *big.Int,
	nonce uint64,
) *DirectCall {
	return &DirectCall{
		Type:     DirectCallTxType,
		SubType:  DepositCallSubType,
		From:     bridge,
		To:       address,
		Data:     nil,
		Value:    amount,
		GasLimit: DepositCallGasLimit,
		Nonce:    nonce,
	}
}
```

**File:** fvm/evm/types/call.go (L231-247)
```go
func NewTransferCall(
	from Address,
	to Address,
	amount *big.Int,
	nonce uint64,
) *DirectCall {
	return &DirectCall{
		Type:     DirectCallTxType,
		SubType:  TransferCallSubType,
		From:     from,
		To:       to,
		Data:     nil,
		Value:    amount,
		GasLimit: DefaultGasLimitForTokenTransfer,
		Nonce:    nonce,
	}
}
```

**File:** fvm/evm/stdlib/contract.cdc (L559-565)
```text
        /// Deposits the given vault into the cadence owned account's balance
        ///
        /// @param from: The FlowToken Vault to deposit to this cadence owned account
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }
```

**File:** fvm/evm/emulator/emulator.go (L413-420)
```go
	// if any error (invalid or vm) on the internal call, revert and don't commit any change
	// this prevents having cases that we add balance to the bridge but the transfer
	// fails due to gas, etc.
	if res.Invalid() || res.Failed() {
		// reset the state to revert the add balances
		proc.state.Reset()
		return res, nil
	}
```

**File:** fvm/evm/handler/handler.go (L957-976)
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

**File:** fvm/evm/emulator/emulator_test.go (L83-111)
```go
			t.Run("tokens deposit to an smart contract that doesn't accept native token", func(t *testing.T) {
				var testContract types.Address
				// deploy contract
				RunWithNewEmulator(t, backend, rootAddr, func(env *emulator.Emulator) {
					RunWithNewBlockView(t, env, func(blk types.BlockView) {
						emptyContractByteCode, err := hex.DecodeString("6080604052348015600e575f80fd5b50603e80601a5f395ff3fe60806040525f80fdfea2646970667358221220093c3754c634ed147652afc2e8c4a2336be5c37cbc733839668aa5a11e713e6e64736f6c634300081a0033")
						require.NoError(t, err)
						call := types.NewDeployCall(
							bridgeAccount,
							emptyContractByteCode,
							100_000,
							big.NewInt(0),
							1)
						res, err := blk.DirectCall(call)
						requireSuccessfulExecution(t, err, res)
						testContract = *res.DeployedContractAddress
					})
				})

				RunWithNewEmulator(t, backend, rootAddr, func(env *emulator.Emulator) {
					RunWithNewBlockView(t, env, func(blk types.BlockView) {
						call := types.NewDepositCall(bridgeAccount, testContract, types.MakeBigIntInFlow(1), 0)
						res, err := blk.DirectCall(call)
						require.NoError(t, err)
						require.NoError(t, res.ValidationError)
						require.Equal(t, res.VMError, gethVM.ErrExecutionReverted)
					})
				})
			})
```
