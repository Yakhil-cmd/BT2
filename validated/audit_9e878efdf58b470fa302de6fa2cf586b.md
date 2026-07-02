### Title
FLOW Tokens Permanently Locked in EVM State When `CadenceOwnedAccount` Is Destroyed Without Withdrawing — (File: fvm/evm/stdlib/contract.cdc)

---

### Summary

The `CadenceOwnedAccount` (COA) resource in `fvm/evm/stdlib/contract.cdc` has no destructor. Any FLOW tokens deposited into a COA's EVM address via the `access(all)` `deposit()` function are permanently locked in the EVM state if the COA resource is destroyed without first calling `withdraw()`. No rescue or recovery path exists for these tokens.

---

### Finding Description

The `CadenceOwnedAccount` resource is defined at lines 518–803 of `fvm/evm/stdlib/contract.cdc`. It exposes two key functions:

- `deposit(from: @FlowToken.Vault)` — marked `access(all)`, callable by any transaction sender or script.
- `withdraw(balance: Balance)` — marked `access(Owner | Withdraw)`, requiring an entitlement held only by the resource owner. [1](#0-0) [2](#0-1) 

When `deposit()` is called, the Cadence `FlowToken.Vault` is consumed by `InternalEVM.deposit`, which credits the COA's EVM address with the corresponding balance. The Go-layer implementation in `fvm/evm/impl/impl.go` explicitly notes that the vault is **not destroyed** — it is kept alive in the EVM storage account to back the EVM-side balance: [3](#0-2) 

The COA's EVM address is derived from the resource's `uuid` at creation time via `InternalEVM.createCadenceOwnedAccount(uuid: acc.uuid)`: [4](#0-3) 

**The `CadenceOwnedAccount` resource body (lines 518–803) contains no `destroy` function.** Cadence's resource model allows `destroy coa` to succeed silently even when the COA's EVM address holds a non-zero balance. After destruction:

1. The COA resource and its `uuid` are gone.
2. The EVM state at the COA's address persists with the full balance.
3. No new COA can ever be assigned the same EVM address (UUIDs are monotonically unique).
4. COA EVM addresses are smart-contract wallets that require the Cadence COA resource to authorize any outgoing transaction — without the resource, the address is permanently uncontrollable.
5. There is no rescue or sweep function anywhere in the EVM contract that can recover tokens from an arbitrary EVM address.

The `deposit()` function being `access(all)` means a third party can deposit FLOW tokens into any COA they can reference, including one that the owner subsequently destroys — making the loss externally triggerable.

---

### Impact Explanation

FLOW tokens deposited into a COA's EVM address are permanently and irrecoverably lost when the COA resource is destroyed without withdrawing. The tokens remain visible in the EVM state (queryable via `EVMAddress.balance()`) but are completely inaccessible. This is a **cross-VM asset loss**: real FLOW token value is consumed on the Cadence side (the vault is moved into EVM storage) and the corresponding EVM balance becomes permanently orphaned.

---

### Likelihood Explanation

Moderate. The `deposit()` function is `access(all)`, so any unprivileged transaction sender can deposit FLOW tokens into any COA they hold a reference to. Realistic loss scenarios include:

- A user creates a temporary COA for scripting, deposits tokens, and destroys it without withdrawing (as shown in existing tests).
- A third party deposits tokens into a COA (e.g., as a payment), and the COA owner later destroys the resource without checking the EVM balance first.
- A transaction that creates a COA, deposits tokens, and then panics or reverts after the deposit but before the withdraw — if the COA was already stored and later cleaned up.

The existing test suite itself demonstrates this pattern without any guard: [5](#0-4) [6](#0-5) 

---

### Recommendation

Add a `destroy` function (destructor) to the `CadenceOwnedAccount` resource in `fvm/evm/stdlib/contract.cdc` that enforces one of the following:

1. **Panic on non-zero balance** — prevent destruction if `self.balance().attoflow > 0`, forcing the caller to explicitly withdraw first.
2. **Auto-withdraw on destruction** — automatically withdraw the full EVM balance back to a Cadence vault and deposit it into a designated receiver before the resource is destroyed.

Option 1 is safer because it makes the loss explicit and forces the developer to handle it consciously, consistent with Cadence's resource-safety philosophy.

---

### Proof of Concept

```cadence
import EVM from <EVM_ADDRESS>
import FlowToken from <FLOW_TOKEN_ADDRESS>

access(all)
fun main() {
    let admin = getAuthAccount<auth(BorrowValue) &Account>(<SERVICE_ADDRESS>)
        .storage.borrow<&FlowToken.Administrator>(from: /storage/flowTokenAdmin)!
    let minter <- admin.createNewMinter(allowedAmount: 1.23)
    let vault <- minter.mintTokens(amount: 1.23)
    destroy minter

    // Step 1: Create COA and record its EVM address
    let coa <- EVM.createCadenceOwnedAccount()
    let coaEVMAddress = coa.address()

    // Step 2: Deposit 1.23 FLOW into the COA's EVM address (access(all))
    coa.deposit(from: <-vault)
    // coaEVMAddress.balance().inFLOW() == 1.23

    // Step 3: Destroy the COA resource without withdrawing
    // No destructor exists — this succeeds silently
    destroy coa

    // Step 4: Tokens are permanently stuck
    // coaEVMAddress.balance().inFLOW() still == 1.23
    // No COA resource exists to authorize a withdrawal
    // No rescue function exists in the EVM contract
    // The address can never be re-assigned to a new COA
}
```

The root cause is in `fvm/evm/stdlib/contract.cdc` at the `CadenceOwnedAccount` resource definition, which spans lines 518–803 and contains no `destroy` function: [7](#0-6) 

The Go-layer deposit handler that consumes the vault without destroying it: [8](#0-7) 

The handler-level deposit that routes through the `NativeTokenBridgeAddress`, confirming the EVM balance is credited and the Cadence vault is consumed: [9](#0-8)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L518-528)
```text
    access(all) resource CadenceOwnedAccount: Addressable {

        access(self) var addressBytes: [UInt8; 20]

        init() {
            // address is initially set to zero
            // but updated through initAddress later
            // we have to do this since we need resource id (uuid)
            // to calculate the EVM address for this cadence owned account
            self.addressBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
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

**File:** fvm/evm/stdlib/contract.cdc (L807-816)
```text
    fun createCadenceOwnedAccount(): @CadenceOwnedAccount {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        let acc <-create CadenceOwnedAccount()
        let addr = InternalEVM.createCadenceOwnedAccount(uuid: acc.uuid)
        acc.initAddress(addressBytes: addr)

        emit CadenceOwnedAccountCreated(address: acc.address().toString(), uuid: acc.uuid)
        return <-acc
```

**File:** fvm/evm/impl/impl.go (L631-683)
```go
func newInternalEVMTypeDepositFunction(
	gauge common.MemoryGauge,
	handler types.ContractHandler,
) *interpreter.HostFunctionValue {
	return interpreter.NewStaticHostFunctionValue(
		gauge,
		stdlib.InternalEVMTypeDepositFunctionType,
		func(invocation interpreter.Invocation) interpreter.Value {
			context := invocation.InvocationContext

			// Get from vault

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

			return interpreter.Void
		},
	)
```

**File:** fvm/evm/evm_test.go (L2195-2197)
```go
					let cadenceOwnedAccount <- EVM.createCadenceOwnedAccount()
					cadenceOwnedAccount.deposit(from: <-vault)
					destroy cadenceOwnedAccount
```

**File:** fvm/evm/stdlib/contract_test.go (L5192-5193)
```go
          let cadenceOwnedAccount1 <- EVM.createCadenceOwnedAccount()
          destroy cadenceOwnedAccount1
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
