### Title
Hardcoded 2,300-Gas Stipend in `DefaultGasLimitForTokenTransfer` Causes Permanent Revert for COA Deposit/Withdraw/Transfer to EVM Smart Contracts - (File: `fvm/evm/types/call.go`)

---

### Summary

`fvm/evm/types/call.go` defines `DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300` (i.e., 21,000 + 2,300 = 23,300 gas). This constant is used as the hardcoded `GasLimit` for all three native-token movement primitives: `NewDepositCall`, `NewWithdrawCall`, and `NewTransferCall`. Any EVM smart contract whose `receive()` or `fallback()` function consumes more than 2,300 gas will cause these calls to revert unconditionally, permanently blocking FLOW token bridging to or from that contract address.

---

### Finding Description

In `fvm/evm/types/call.go` lines 31–37, the gas budget for all direct-call token movements is fixed:

```go
// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300

DepositCallGasLimit  = DefaultGasLimitForTokenTransfer   // = 23_300
WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer   // = 23_300
``` [1](#0-0) 

These constants are consumed directly in the three call constructors:

- `NewDepositCall` sets `GasLimit: DepositCallGasLimit` [2](#0-1) 
- `NewWithdrawCall` sets `GasLimit: WithdrawCallGasLimit` [3](#0-2) 
- `NewTransferCall` sets `GasLimit: DefaultGasLimitForTokenTransfer` [4](#0-3) 

These constructors are called unconditionally from the handler:

- `Account.Deposit` → `types.NewDepositCall(...)` [5](#0-4) 
- `Account.Withdraw` → `types.NewWithdrawCall(...)` [6](#0-5) 
- `Account.Transfer` → `types.NewTransferCall(...)` [7](#0-6) 

All three handler methods call `panicOnErrorOrInvalidOrFailedState(res, err)` on the result. If the EVM execution reverts (e.g., because the target contract's `receive()` consumed more than 2,300 gas), the result is `Failed`, and the entire Cadence transaction panics and aborts.

The emulator test explicitly confirms this revert path — depositing to a contract that does not accept native tokens (or whose receive logic exceeds the stipend) produces `res.VMError == gethVM.ErrExecutionReverted`: [8](#0-7) 

The Cadence-layer entry points exposed to any transaction author are `EVM.EVMAddress.deposit(from:)` and `EVM.CadenceOwnedAccount.deposit(from:)` / `.withdraw(balance:)`: [9](#0-8) [10](#0-9) 

---

### Impact Explanation

Any EVM smart contract whose `receive()` or `fallback()` function requires more than 2,300 gas (e.g., a multisig wallet, a vault that emits events, a proxy that writes to storage) **can never receive FLOW tokens via the COA bridge**. The deposit, withdraw, and transfer operations will always revert for such addresses. Because `panicOnErrorOrInvalidOrFailedState` is called on every failure, the enclosing Cadence transaction aborts entirely, making the failure non-recoverable at the call site. This permanently blocks cross-VM FLOW token bridging to a broad class of legitimate EVM contracts.

---

### Likelihood Explanation

The 2,300-gas stipend is a well-known Ethereum anti-pattern. Many production EVM contracts (Gnosis Safe multisigs, ERC-4337 smart wallets, vault contracts, proxy contracts) require more than 2,300 gas in their receive/fallback logic. Any Flow EVM user who deploys or interacts with such a contract and attempts to bridge FLOW tokens to it via a COA will trigger this revert. The entry path requires only a standard unprivileged Cadence transaction — no special privileges, no staked nodes, no admin keys.

---

### Recommendation

Replace the hardcoded `2_300` stipend with a configurable or sufficiently large gas limit for deposit, withdraw, and transfer calls. The caller (or the protocol) should be able to specify a gas limit that accommodates the target contract's `receive()`/`fallback()` logic. At minimum, expose a parameter in the Cadence-layer `deposit` and `transfer` functions analogous to how `call` already accepts a `gasLimit: UInt64` argument:

```cadence
// Current (broken for contracts needing >2300 gas in receive/fallback):
fun deposit(from: @FlowToken.Vault)

// Recommended:
fun deposit(from: @FlowToken.Vault, gasLimit: UInt64)
```

On the Go side, `NewDepositCall`, `NewWithdrawCall`, and `NewTransferCall` should accept a `gasLimit uint64` parameter instead of hardcoding `DefaultGasLimitForTokenTransfer`.

---

### Proof of Concept

1. Deploy an EVM smart contract with a `receive()` function that writes to storage (costs >2,300 gas):
   ```solidity
   contract GasHeavyReceiver {
       uint256 public counter;
       receive() external payable {
           counter += 1; // SSTORE costs 20,000 gas on a cold slot
       }
   }
   ```

2. From a Cadence transaction, attempt to deposit FLOW to that contract:
   ```cadence
   import EVM from <EVM_ADDRESS>
   import FlowToken from <FLOW_TOKEN_ADDRESS>

   transaction(contractAddr: [UInt8; 20]) {
       prepare(signer: auth(Storage) &Account) {
           let vault <- signer.storage
               .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!
               .withdraw(amount: 1.0) as! @FlowToken.Vault
           let evmAddr = EVM.EVMAddress(bytes: contractAddr)
           evmAddr.deposit(from: <-vault)  // PANICS: ErrExecutionReverted
       }
   }
   ```

3. The transaction aborts with a panic because `DepositCallGasLimit = 23_300` is exhausted by the `SSTORE` in `receive()`, `proc.mintTo` returns `res.Failed()`, and `panicOnErrorOrInvalidOrFailedState` panics.

The gas limit is set at `fvm/evm/types/call.go:32,36,37` and is not overridable by the caller through any public Cadence API surface. [11](#0-10) [12](#0-11) [13](#0-12)

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

**File:** fvm/evm/types/call.go (L200-209)
```go
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
```

**File:** fvm/evm/types/call.go (L219-228)
```go
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
```

**File:** fvm/evm/types/call.go (L237-246)
```go
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
```

**File:** fvm/evm/handler/handler.go (L959-975)
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
```

**File:** fvm/evm/handler/handler.go (L980-995)
```go
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

**File:** fvm/evm/handler/handler.go (L999-1011)
```go
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

**File:** fvm/evm/emulator/emulator_test.go (L102-111)
```go
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

**File:** fvm/evm/stdlib/contract.cdc (L562-605)
```text
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }

        /// Gets the EVM address of the cadence owned account behind an entitlement,
        /// acting as proof of access
        access(Owner | Validate)
        view fun protectedAddress(): EVMAddress {
            return self.address()
        }

        /// Withdraws the balance from the cadence owned account's balance.
        /// Note that amounts smaller than 1e10 attoFlow can't be withdrawn,
        /// given that Flow Token Vaults use UFix64 to store balances.
        /// In other words, the smallest withdrawable amount is 1e10 attoFlow.
        /// Amounts smaller than 1e10 attoFlow, will cause the function to panic
        /// with: "withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow".
        /// If the given balance conversion to UFix64 results in rounding loss,
        /// the withdrawal amount will be truncated to the maximum precision for UFix64.
        ///
        /// @param balance: The EVM balance to withdraw
        ///
        /// @return A FlowToken Vault with the requested balance
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
