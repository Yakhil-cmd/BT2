### Title
Fixed 2,300-Gas Stipend in EVM Deposit/Transfer Direct Calls Mirrors Deprecated `.transfer` Pattern, Blocking Smart Contract Recipients - (File: `fvm/evm/types/call.go`)

### Summary
Flow's EVM integration hardcodes `DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300` (21,000 + 2,300 = 23,300 gas) for all deposit, withdraw, and COA-to-EVM transfer direct calls. This is structurally identical to Solidity's deprecated `.transfer` pattern: a fixed 2,300-gas stipend is forwarded to the recipient's `receive`/`fallback` function. Any EVM smart contract address whose `receive` or `fallback` function consumes more than 2,300 gas will permanently fail to receive FLOW tokens through these paths.

### Finding Description
In `fvm/evm/types/call.go`, the constant is defined and propagated as follows:

```go
// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300   // line 32

DepositCallGasLimit  = DefaultGasLimitForTokenTransfer   // line 36
WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer   // line 37
```

`NewDepositCall` (line 194–210), `NewWithdrawCall` (line 213–229), and `NewTransferCall` (line 231–247) all use this ceiling. The comment on line 31 explicitly acknowledges the 2,300 figure as "max gas allowed for receive/fallback methods" — the same stipend that Solidity's `.transfer` forwards and that the Consensys/ChainSecurity advisories cited in the external report identify as the root cause of breakage.

Any EVM smart contract that performs a storage write, emits an event, or calls another contract inside its `receive`/`fallback` will exceed 2,300 gas. Concrete examples: Gnosis Safe multi-sig wallets, ERC-4337 smart accounts, proxy contracts with non-trivial fallback logic, and any contract that updates an internal accounting variable on receipt.

The Cadence-side entry points that trigger these calls are:
- `EVMAddress.deposit(from: @FlowToken.Vault)` → `NewDepositCall` with `DepositCallGasLimit`
- `CadenceOwnedAccount.deposit(from: @FlowToken.Vault)` → same path via `self.address().deposit(...)`
- `CadenceOwnedAccount.call(to:, data:, gasLimit:, value:)` when used for a plain value transfer → `NewTransferCall` with `DefaultGasLimitForTokenTransfer`

### Impact Explanation
When the EVM execution of a deposit or transfer direct call runs out of gas at the recipient's `receive`/`fallback`, the EVM result carries `status: failed` (VMError = out-of-gas). The FLOW vault passed into `EVMAddress.deposit()` is consumed on the Cadence side before the EVM call is dispatched. If the handler does not panic on a `failed` result, the vault is destroyed and the tokens are permanently lost — cross-VM asset loss with no recovery path. Even in the case where the handler does panic and the Cadence transaction reverts, the protocol is structurally incapable of crediting FLOW to any smart contract EVM address whose receive logic exceeds 2,300 gas, breaking a fundamental cross-VM use case for all such addresses.

### Likelihood Explanation
Medium-to-high. The EVM ecosystem is dominated by smart contract wallets (Gnosis Safe, ERC-4337 accounts), proxy contracts, and DeFi vaults — all of which write to storage in their receive functions and therefore require more than 2,300 gas. Any Flow user or protocol that attempts to bridge FLOW tokens to such an address via `EVMAddress.deposit()` or a COA transfer will trigger this failure. The entry path requires no special privilege: any unprivileged Cadence transaction author can invoke `EVMAddress.deposit()` or `CadenceOwnedAccount.deposit()`.

### Recommendation
Replace the hardcoded `DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300` with a higher default (e.g., 100,000 gas, matching the COA `call` path) for `DepositCallGasLimit` and `WithdrawCallGasLimit`. For `NewTransferCall`, allow the caller to supply a gas limit rather than capping it at 23,300. Alternatively, expose an overloaded `deposit(from:gasLimit:)` variant so callers can specify sufficient gas for smart contract recipients. Ensure the handler explicitly panics (reverts the Cadence transaction) on any `failed` or `invalid` EVM result from a deposit call to prevent silent token loss.

### Proof of Concept
1. Deploy an EVM smart contract at address `0xSC` whose `receive()` function writes to a storage slot (costs ~5,000 gas minimum).
2. From a Cadence transaction, call:
   ```cadence
   let vault <- flowToken.withdraw(amount: 1.0) as! @FlowToken.Vault
   let target = EVM.EVMAddress(bytes: /* 0xSC bytes */)
   target.deposit(from: <-vault)
   ```
3. Internally, `NewDepositCall` is constructed with `GasLimit = 23_300`. The EVM executes the call; the recipient's `receive()` exhausts the 2,300 gas stipend and the call reverts with out-of-gas.
4. The EVM result has `status: failed`. The FLOW vault has already been consumed on the Cadence side. Depending on handler behavior, tokens are either permanently lost or the transaction reverts — in either case, the deposit to `0xSC` is impossible. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** fvm/evm/types/call.go (L29-38)
```go
	IntrinsicFeeForTokenTransfer = gethParams.TxGas

	// 21_000 is the minimum for a transaction + max gas allowed for receive/fallback methods
	DefaultGasLimitForTokenTransfer = IntrinsicFeeForTokenTransfer + 2_300

	// the value is set to the gas limit for transfer to facilitate transfers
	// to smart contract addresses.
	DepositCallGasLimit  = DefaultGasLimitForTokenTransfer
	WithdrawCallGasLimit = DefaultGasLimitForTokenTransfer
)
```

**File:** fvm/evm/types/call.go (L194-247)
```go
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
