### Title
Hardcoded 2300 Gas Stipend in EVM Direct Calls Prevents Smart Contract Addresses from Receiving FLOW Tokens — (File: `fvm/evm/types/call.go`)

---

### Summary

`DefaultGasLimitForTokenTransfer` is hardcoded to `21_000 + 2_300 = 23_300` gas in `fvm/evm/types/call.go`. This constant is reused verbatim as `DepositCallGasLimit`, `WithdrawCallGasLimit`, and the gas limit for `NewTransferCall`. Because the EVM intrinsic cost of a transaction consumes 21 000 gas, only 2 300 gas remains for the recipient's `receive` or `fallback` function. Any EVM smart-contract address whose `receive`/`fallback` requires more than 2 300 gas will cause the deposit or transfer to fail, permanently blocking that address from receiving FLOW tokens through the Cadence-EVM bridge.

---

### Finding Description

In `fvm/evm/types/call.go` the following constants are defined:

```go
IntrinsicFeeForTokenTransfer    = gethParams.TxGas          // 21_000
DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300  // 23_300
DepositCallGasLimit             = DefaultGasLimitForTokenTransfer
WithdrawCallGasLimit            = DefaultGasLimitForTokenTransfer
``` [1](#0-0) 

`NewDepositCall` hard-codes `GasLimit: DepositCallGasLimit`: [2](#0-1) 

`NewTransferCall` hard-codes `GasLimit: DefaultGasLimitForTokenTransfer`: [3](#0-2) 

When a deposit is executed, `Account.Deposit` in `handler.go` constructs a `NewDepositCall` directed **from** the native-token bridge **to** the recipient EVM address, then calls `panicOnErrorOrInvalidOrFailedState`: [4](#0-3) 

Inside the EVM emulator, `mintTo` runs the call message with the capped gas limit. If the recipient's `receive`/`fallback` consumes more than 2 300 gas, `res.Failed()` is true, the state is reset, and the result is returned as a failure: [5](#0-4) 

`panicOnErrorOrInvalidOrFailedState` then panics, aborting the entire Cadence transaction. The same path applies to `Transfer` via `NewTransferCall`.

The existing test already documents that depositing to a contract that does not accept native tokens reverts: [6](#0-5) 

The comment in the constant definition itself acknowledges the 2 300 ceiling is the "max gas allowed for receive/fallback methods": [7](#0-6) 

---

### Impact Explanation

**Impact: High** — Any EVM smart-contract address (e.g., a multi-sig wallet, a vault contract, or a COA that has had a contract deployed at its address) whose `receive` or `fallback` function requires more than 2 300 gas cannot receive FLOW tokens through `EVMAddress.deposit` or `CadenceOwnedAccount.transfer`. The Cadence transaction panics and is fully reverted; the tokens are not lost, but the recipient address is permanently unable to receive FLOW via these bridge paths. Because COAs are explicitly described as "smart contract wallets" that support ERC-777 and ERC-1155 (which have non-trivial `receive` hooks), this is a realistic and protocol-level limitation. [8](#0-7) 

---

### Likelihood Explanation

**Likelihood: Low** — The affected recipient must be an EVM smart contract with a `receive` or `fallback` function that consumes more than 2 300 gas. Plain EOAs and simple contracts are unaffected. However, the Flow EVM ecosystem explicitly encourages smart-contract wallets (COAs, multi-sigs, ERC-4337 accounts), making this scenario realistic over time.

---

### Recommendation

Remove the hardcoded `+ 2_300` stipend from `DefaultGasLimitForTokenTransfer`. For deposit and transfer calls, either:

1. Allow the caller to specify a gas limit (as is already done for `deploy` and `call`), or
2. Set a higher default (e.g., `300_000`) that accommodates non-trivial `receive` implementations, consistent with how most EVM chains handle ETH transfers to contracts.

The same fix should be applied to `DepositCallGasLimit`, `WithdrawCallGasLimit`, and `NewTransferCall`. [9](#0-8) 

---

### Proof of Concept

1. Deploy an EVM smart contract on Flow EVM whose `receive()` function performs a storage write (costs > 2 300 gas), e.g.:

```solidity
contract HeavyReceiver {
    uint256 public counter;
    receive() external payable {
        counter += 1;   // SSTORE costs 20 000 gas on first write
    }
}
```

2. From a Cadence transaction, mint FLOW tokens and call:

```cadence
import EVM from <EVM_address>
import FlowToken from <FlowToken_address>

transaction {
    prepare(acct: auth(BorrowValue) &Account) {
        let admin = acct.storage.borrow<&FlowToken.Administrator>(from: /storage/flowTokenAdmin)!
        let minter <- admin.createNewMinter(allowedAmount: 1.0)
        let vault <- minter.mintTokens(amount: 1.0)
        destroy minter

        let target = EVM.EVMAddress(bytes: <HeavyReceiver_address_bytes>)
        target.deposit(from: <-vault)   // panics: EVM execution failed
    }
}
```

3. The transaction panics because `mintTo` returns `res.Failed() == true` (out of gas in `receive`), `panicOnErrorOrInvalidOrFailedState` is triggered, and the deposit is impossible regardless of how many times it is retried. [10](#0-9) [5](#0-4)

### Citations

**File:** fvm/evm/types/call.go (L25-38)
```go
	// Note that these gas values might need to change if we
	// change the transaction (e.g. add access list),
	// then it has to be updated to use Intrinsic function
	// to calculate the minimum gas needed to run the transaction.
	IntrinsicFeeForTokenTransfer = gethParams.TxGas

	// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
	DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300

	// the value is set to the gas limit for transfer to facilitate transfers
	// to smart contract addresses.
	DepositCallGasLimit  = DefaultGasLimitForTokenTransfer
	WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer
)
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

**File:** fvm/evm/emulator/emulator.go (L407-420)
```go
	// withdraw the amount and move it to the bridge account
	res, err := proc.run(call.Message(), call.Hash(), types.DirectCallTxType)
	if err != nil {
		return res, err
	}

	// if any error (invalid or vm) on the internal call, revert and don't commit any change
	// this prevents having cases that we add balance to the bridge but the transfer
	// fails due to gas, etc.
	if res.Invalid() || res.Failed() {
		// reset the state to revert the add balances
		proc.state.Reset()
		return res, nil
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

**File:** fvm/evm/stdlib/contract.cdc (L466-486)
```text
    /* 
        Cadence-Owned Accounts (COA) 
        A COA is a natively supported EVM smart contract wallet type 
        that allows a Cadence resource to own and control an EVM address.
        This native wallet provides the primitives needed to bridge
        or control assets across Flow EVM and Cadence.
        From the EVM perspective, COAs are smart contract wallets
        that accept native token transfers and support several ERCs
        including ERC-165, ERC-721, ERC-777, ERC-1155, ERC-1271.

        COAs are not controlled by a key.
        Instead, every COA account has a unique resource accessible
        on the Cadence side, and anyone who owns that resource submits transactions
        on behalf of this address. These direct transactions have COA’s EVM address
        as the tx.origin and a new EVM transaction type (TxType = 0xff)
        is used to differentiate these transactions from other types
        of EVM transactions (e.g, DynamicFeeTxType (0x02).

        Because of this, users are never able to access a key for their account,
        meaning that they cannot control their COA's address on other EVM blockchains.
    */
```
