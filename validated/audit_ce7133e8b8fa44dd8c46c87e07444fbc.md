### Title
Fixed Gas Limit (21,000 + 2,300) for EVM Deposit and Transfer Direct Calls Causes Permanent Failure for Smart Contract Recipients - (File: `fvm/evm/types/call.go`)

### Summary

`DepositCallGasLimit`, `WithdrawCallGasLimit`, and `DefaultGasLimitForTokenTransfer` are all hardcoded to `21,000 + 2,300 = 23,300` gas in `fvm/evm/types/call.go`. This is the direct analog of Solidity's `.transfer` anti-pattern: after the 21,000 intrinsic gas is consumed, only 2,300 gas remains for the recipient's `receive`/`fallback` function. Any EVM smart contract whose `receive`/`fallback` requires more than 2,300 gas will permanently fail to receive FLOW tokens via `EVMAddress.deposit()` or `CadenceOwnedAccount.Transfer()`.

### Finding Description

In `fvm/evm/types/call.go`, the gas limits for all three bridge-level direct call types are defined as:

```go
IntrinsicFeeForTokenTransfer    = gethParams.TxGas          // 21,000
DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300  // 23,300

DepositCallGasLimit  = DefaultGasLimitForTokenTransfer  // 23,300
WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer  // 23,300
```

`NewDepositCall` (used when bridging FLOW into EVM via `EVMAddress.deposit()`) hardcodes `GasLimit: DepositCallGasLimit`:

```go
func NewDepositCall(...) *DirectCall {
    return &DirectCall{
        ...
        GasLimit: DepositCallGasLimit,  // 23,300
    }
}
```

`NewTransferCall` (used by `CadenceOwnedAccount.Transfer()`) hardcodes `GasLimit: DefaultGasLimitForTokenTransfer`:

```go
func NewTransferCall(...) *DirectCall {
    return &DirectCall{
        ...
        GasLimit: DefaultGasLimitForTokenTransfer,  // 23,300
    }
}
```

After the EVM charges 21,000 gas for the intrinsic transaction cost, only 2,300 gas is left for the recipient contract's `receive`/`fallback` function. Any contract that performs non-trivial logic in `receive`/`fallback` (e.g., emitting events, updating storage, delegating to a proxy, or implementing ERC-4337/multisig logic) will exceed this budget and revert.

The Cadence-level entry point `EVMAddress.deposit()` in `contract.cdc` calls `InternalEVM.deposit()`, which calls `account.Deposit()` in the handler, which ultimately executes `mintTo()` in the emulator using the `NewDepositCall` with the hardcoded 23,300 gas limit. The comment in the code itself acknowledges the 2,300 cap: `"21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods"`.

### Impact Explanation

**Impact: Medium**

Any EVM smart contract deployed on Flow EVM whose `receive` or `fallback` function requires more than 2,300 gas will be permanently unable to receive FLOW tokens via the Cadence-EVM bridge. This includes:

- Gnosis Safe / multisig wallets (which emit events and update storage in `receive`)
- ERC-4337 smart account wallets
- Proxy contracts that delegate in `receive`
- Any contract with non-trivial receive logic

The deposit call reverts with `ErrExecutionReverted`. The FLOW tokens are not lost (the Cadence transaction reverts), but the target EVM contract is permanently bricked as a FLOW recipient. Users cannot fund such contracts from Cadence, breaking a core cross-VM use case.

### Likelihood Explanation

**Likelihood: Medium**

Smart contract wallets and multisig accounts are common recipients of token transfers. Any Flow EVM user who deploys or interacts with such a contract and attempts to fund it via `EVMAddress.deposit()` will encounter this failure. The pattern is already confirmed to trigger in the existing test suite.

### Recommendation

Increase `DepositCallGasLimit` and `DefaultGasLimitForTokenTransfer` to a value that accommodates modern smart contract wallets (e.g., 100,000 gas), or allow the caller to specify the gas limit for deposit/transfer direct calls. Since these are protocol-level direct calls (not user-signed EVM transactions), the gas price is zero and there is no economic cost to increasing the limit.

### Proof of Concept

The existing test `"tokens deposit to an smart contract that doesn't accept native token"` in `fvm/evm/emulator/emulator_test.go` directly demonstrates the failure:

```go
call := types.NewDepositCall(bridgeAccount, testContract, types.MakeBigIntInFlow(1), 0)
res, err := blk.DirectCall(call)
require.NoError(t, err)
require.NoError(t, res.ValidationError)
require.Equal(t, res.VMError, gethVM.ErrExecutionReverted)  // deposit fails
```

**Attacker-controlled entry path:**
1. Deploy an EVM smart contract on Flow EVM with a `receive()` function that requires >2,300 gas (e.g., emits an event + updates a mapping — standard for any multisig or smart wallet).
2. Any unprivileged Cadence transaction calls `EVM.EVMAddress(bytes: contractAddr).deposit(from: <-vault)` to fund the contract.
3. The call executes `NewDepositCall` with `GasLimit = 23,300`. After 21,000 intrinsic gas, only 2,300 remains for `receive()`. The call reverts with `ErrExecutionReverted`.
4. The deposit permanently fails for this contract. No FLOW can ever be bridged into it via the Cadence deposit path.

**Root cause lines:** [1](#0-0) 

**`NewDepositCall` using the hardcoded limit:** [2](#0-1) 

**`NewTransferCall` using the same hardcoded limit:** [3](#0-2) 

**Cadence-level entry point (`EVMAddress.deposit`):** [4](#0-3) 

**Test confirming the revert:** [5](#0-4)

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

**File:** fvm/evm/stdlib/contract.cdc (L200-223)
```text
        /// Deposits the given vault into the EVM account with the given address
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            let amount = from.balance
            if amount == 0.0 {
                destroy from
                return
            }
            let depositedUUID = from.uuid
            InternalEVM.deposit(
                from: <-from,
                to: self.bytes
            )
            emit FLOWTokensDeposited(
                address: self.toString(),
                amount: amount,
                depositedUUID: depositedUUID,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
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
