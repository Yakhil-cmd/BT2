### Title
Fixed 2,300-Gas Stipend in `NewDepositCall` / `NewTransferCall` Causes Permanent Revert When Recipient Is a Smart Contract With Non-Trivial `receive()` — (File: `fvm/evm/types/call.go`)

### Summary
Flow EVM's native-token bridge uses a hard-coded gas ceiling of `21,000 + 2,300 = 23,300` for every `DepositCall` and `TransferCall`. The extra 2,300 units mirror Solidity's deprecated `transfer()` stipend and are insufficient for any EVM smart contract whose `receive()` / `fallback()` function performs storage writes, emits events, or calls other contracts. Any such deposit or transfer reverts unconditionally, making it impossible to fund those contracts with FLOW via the Cadence bridge.

### Finding Description

In `fvm/evm/types/call.go` the gas budget for all three bridge-initiated value transfers is fixed at compile time:

```go
// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300   // = 23_300

DepositCallGasLimit  = DefaultGasLimitForTokenTransfer   // used by NewDepositCall
WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer   // used by NewWithdrawCall
``` [1](#0-0) 

`NewDepositCall` and `NewTransferCall` both embed this limit unconditionally: [2](#0-1) 

After the EVM deducts the 21,000-unit intrinsic cost, only 2,300 gas remain for the recipient's `receive()` / `fallback()`. Any contract that writes to storage (~20,000 gas per `SSTORE`), emits an event, or delegates to another contract will exhaust this budget and revert.

The Cadence-layer entry point is `EVMAddress.deposit()` in `fvm/evm/stdlib/contract.cdc`: [3](#0-2) 

This calls `InternalEVM.deposit()`, which reaches `handler.Deposit()`: [4](#0-3) 

`panicOnErrorOrInvalidOrFailedState` is called on the result; a revert in the EVM sub-call propagates as a Cadence panic, rolling back the entire transaction.

The same ceiling applies to `CadenceOwnedAccount.deposit()`: [5](#0-4) 

### Impact Explanation

Any EVM smart contract whose `receive()` or `fallback()` function consumes more than 2,300 gas (e.g., a multisig wallet, a proxy, a DAO treasury, or any contract that emits an event or writes to storage on receipt) **cannot receive FLOW tokens through the Cadence bridge**. Every deposit or COA-initiated transfer to such an address reverts unconditionally. Funds already held in Cadence are not lost (the transaction rolls back), but the EVM contract is permanently unable to accumulate a FLOW balance via the bridge, breaking its intended cross-VM functionality. This constitutes a cross-VM asset-delivery failure.

### Likelihood Explanation

Modern EVM contract patterns — proxy contracts, multisig wallets (e.g., Gnosis Safe), ERC-4337 account-abstraction wallets, and any contract that tracks incoming ETH/FLOW — routinely exceed 2,300 gas in their `receive()` functions. A developer who deploys such a contract on Flow EVM and attempts to fund it via `EVMAddress.deposit()` or `CadenceOwnedAccount.deposit()` will encounter a silent, permanent revert with no recourse. No special privilege is required; any unprivileged Cadence transaction sender can trigger the condition.

### Recommendation

Replace the fixed `DefaultGasLimitForTokenTransfer` ceiling with a configurable or sufficiently large gas limit for deposit and transfer direct calls, analogous to the recommendation in the external report to use `.call{value: wad}("")` instead of `.transfer(wad)`. The `GasLimit` field of `DirectCall` already supports arbitrary values; `NewDepositCall` and `NewTransferCall` should accept a caller-supplied or protocol-defined higher gas limit (e.g., matching the block-level gas limit or a reasonable upper bound such as 100,000) rather than hard-coding the 2,300-unit Solidity-`transfer()` stipend.

### Proof of Concept

1. Deploy an EVM contract on Flow EVM with a `receive()` that writes to storage:
   ```solidity
   contract Receiver {
       uint256 public count;
       receive() external payable { count += 1; }  // ~20,000 gas for SSTORE
   }
   ```
2. From a Cadence transaction, call:
   ```cadence
   let addr = EVM.EVMAddress(bytes: <Receiver address bytes>)
   addr.deposit(from: <-vault)   // vault holds 1.0 FLOW
   ```
3. The `NewDepositCall` is created with `GasLimit = 23_300`. After the 21,000-unit intrinsic cost, only 2,300 gas remain. The `SSTORE` in `receive()` costs ~20,000 gas → out-of-gas revert.
4. `panicOnErrorOrInvalidOrFailedState` panics; the Cadence transaction aborts. The FLOW vault is returned to the caller, but the EVM contract can never be funded via this path.

The existing test at `fvm/evm/emulator/emulator_test.go:83` already demonstrates the revert for a contract that does not accept native tokens; the same mechanism silently blocks any contract whose `receive()` exceeds the 2,300-gas budget. [6](#0-5)

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

**File:** fvm/evm/types/call.go (L193-247)
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

// NewDepositCall constructs a new withdraw direct call
func NewWithdrawCall(
	bridge Address,
	address Address,
	amount *big.Int,
	nonce uint64,
) *DirectCall {
	return &DirectCall{
		Type:     DirectCallTxType,
		SubType:  WithdrawCallSubType,
		From:     address,
		To:       bridge,
		Data:     nil,
		Value:    amount,
		GasLimit: WithdrawCallGasLimit,
		Nonce:    nonce,
	}
}

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
