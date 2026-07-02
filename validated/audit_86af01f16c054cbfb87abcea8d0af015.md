### Title
Missing Zero-Address Validation in `EVMAddress.deposit` Allows Permanent FLOW Token Loss - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `EVMAddress.deposit` function in the EVM Cadence contract does not validate that the target EVM address is non-zero before depositing FLOW tokens. Any unprivileged Cadence transaction can construct a zero `EVMAddress` and deposit real FLOW tokens into it, permanently locking them at the zero EVM address with no recovery path.

---

### Finding Description

`EVMAddress.deposit` in `contract.cdc` accepts a `@FlowToken.Vault` and deposits it to `self.bytes` (the EVM address). The only guard present is a zero-amount check; there is no check that `self.bytes` is not the all-zeros address:

```cadence
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
    // ...
    InternalEVM.deposit(
        from: <-from,
        to: self.bytes          // ← no zero-address guard
    )
``` [1](#0-0) 

The Go-layer host function `newInternalEVMTypeDepositFunction` in `impl.go` extracts `toAddress` from the Cadence argument and immediately calls `account.Deposit` with no zero-address check:

```go
toAddress, err := AddressBytesArrayValueToEVMAddress(context, toAddressValue)
// ...
account := handler.AccountByAddress(toAddress, isAuthorized)
account.Deposit(types.NewFlowTokenVault(amount))
``` [2](#0-1) 

The `Account.Deposit` handler in `handler.go` similarly passes `a.address` (which may be `EmptyAddress`) directly into a `NewDepositCall` with no validation: [3](#0-2) 

The EVM-level `EmptyAddress` is defined as all-zero bytes:

```go
var EmptyAddress = Address(gethCommon.Address{})
``` [4](#0-3) 

The same pattern exists in `EVM.run` / `EVM.batchRun`: the `coinbase: EVMAddress` parameter (the gas-fee collector) is passed directly to `runWithGasFeeRefund` → `cb.Transfer(gasFeeCollector, diff)` with no zero-address check, so gas fees can also be permanently sent to the zero EVM address: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

FLOW tokens deposited to the zero EVM address (`0x0000000000000000000000000000000000000000`) are permanently inaccessible. No private key controls that address in Flow EVM. The tokens remain locked in the EVM state forever, constituting a **cross-VM asset loss**: real FLOW tokens are bridged from Cadence into EVM and irrecoverably burned. The same applies to gas fees directed to the zero coinbase address via `EVM.run` / `EVM.batchRun`.

---

### Likelihood Explanation

The entry path requires no special privilege. Any Cadence transaction can:

1. Obtain a `@FlowToken.Vault` (e.g., from the signer's own storage).
2. Construct `EVM.EVMAddress(bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])`.
3. Call `address.deposit(from: <-vault)`.

This is a realistic accidental scenario (a developer passes a default-initialized or unset address) and also a griefing vector. The `EVM.run` coinbase variant is equally reachable by any relayer who omits or zero-initializes the coinbase argument.

---

### Recommendation

Add a zero-address pre-condition in `EVMAddress.deposit` in `contract.cdc`:

```cadence
pre {
    !EVM.isPaused(): "EVM operations are temporarily paused"
    self.bytes != [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
        "EVM.EVMAddress.deposit(): Cannot deposit to the zero address"
}
```

Similarly, add a zero-address guard in `EVM.run` and `EVM.batchRun` for the `coinbase` parameter:

```cadence
pre {
    !self.isPaused(): "EVM operations are temporarily paused"
    coinbase.bytes != [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
        "EVM.run(): coinbase cannot be the zero address"
}
```

At the Go layer, add a guard in `newInternalEVMTypeDepositFunction` (`impl.go`) and `runWithGasFeeRefund` (`handler.go`) checking `toAddress != types.EmptyAddress` and `gasFeeCollector != types.EmptyAddress` respectively, panicking with a descriptive error.

---

### Proof of Concept

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>
import FungibleToken from <FT_ADDRESS>
import FlowToken from <FLOW_TOKEN_ADDRESS>

transaction {
    prepare(signer: auth(BorrowValue) &Account) {
        let vaultRef = signer.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(
                from: /storage/flowTokenVault
            ) ?? panic("no vault")

        // Withdraw 1.0 FLOW
        let vault <- vaultRef.withdraw(amount: 1.0) as! @FlowToken.Vault

        // Construct the zero EVM address — no validation prevents this
        let zeroAddr = EVM.EVMAddress(
            bytes: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        )

        // Deposit 1.0 FLOW to the zero EVM address — tokens are permanently lost
        zeroAddr.deposit(from: <-vault)
    }
}
```

After execution, `1.0 FLOW` is credited to EVM address `0x0000000000000000000000000000000000000000` and is permanently inaccessible, constituting an irreversible cross-VM asset loss.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L201-223)
```text
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

**File:** fvm/evm/impl/impl.go (L660-679)
```go
			toAddressValue, ok := invocation.Arguments[1].(*interpreter.ArrayValue)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			toAddress, err := AddressBytesArrayValueToEVMAddress(context, toAddressValue)
			if err != nil {
				panic(err)
			}

			// NOTE: We're intentionally not destroying the vault here,
			// because the value of it is supposed to be "kept alive".
			// Destroying would incorrectly be equivalent to a burn and decrease the total supply,
			// and a withdrawal would then have to perform an actual mint of new tokens.

			// Deposit

			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))
```

**File:** fvm/evm/handler/handler.go (L252-266)
```go
func (h *ContractHandler) runWithGasFeeRefund(gasFeeCollector types.Address, f func()) {
	// capture coinbase init balance
	cb := h.AccountByAddress(types.CoinbaseAddress, true)
	initCoinbaseBalance := cb.Balance()
	f()
	// transfer the gas fees collected to the gas fee collector address
	afterBalance := cb.Balance()
	diff := new(big.Int).Sub(afterBalance, initCoinbaseBalance)
	if diff.Sign() > 0 {
		cb.Transfer(gasFeeCollector, diff)
	}
	if diff.Sign() < 0 { // this should never happen but in case
		panic(fvmErrors.NewEVMError(fmt.Errorf("negative balance change on coinbase")))
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

**File:** fvm/evm/types/address.go (L55-56)
```go
// EmptyAddress is an empty evm address
var EmptyAddress = Address(gethCommon.Address{})
```
