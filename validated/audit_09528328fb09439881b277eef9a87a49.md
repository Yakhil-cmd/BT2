### Title
FLOW Tokens Deposited to Arbitrary EVM Addresses via `EVM.EVMAddress.deposit()` Are Permanently Irrecoverable — (`fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.EVMAddress.deposit(from: @FlowToken.Vault)` is `access(all)` and accepts any caller-supplied 20-byte EVM address. It consumes the vault resource and credits the balance to that address with no verification that the target has a recovery path. The only mechanism to move FLOW back from the EVM environment to Cadence is `CadenceOwnedAccount.withdraw()`, which requires owning the COA resource for that specific address. FLOW deposited to any address that is neither a COA nor an EOA with a known private key is permanently trapped.

---

### Finding Description

`EVMAddress.deposit()` in `fvm/evm/stdlib/contract.cdc` is declared `access(all)` and takes a `@FlowToken.Vault` resource:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    ...
    InternalEVM.deposit(
        from: <-from,
        to: self.bytes
    )
    ...
}
``` [1](#0-0) 

The `EVMAddress` struct is a plain value type constructed from any 20-byte array — no validation that the address is a COA, an EOA with a known key, or any address with a withdrawal path:

```cadence
access(all) struct EVMAddress {
    access(all) let bytes: [UInt8; 20]
    view init(bytes: [UInt8; 20]) {
        self.bytes = bytes
    }
    ...
}
``` [2](#0-1) 

The Go-layer `newInternalEVMTypeDepositFunction` confirms the vault is consumed and credited to the target address with no address validation:

```go
account := handler.AccountByAddress(toAddress, isAuthorized)
account.Deposit(types.NewFlowTokenVault(amount))
``` [3](#0-2) 

The **only** path to recover FLOW from the EVM environment back to Cadence is `CadenceOwnedAccount.withdraw()`, which requires the caller to hold the `@EVM.CadenceOwnedAccount` resource for that specific EVM address:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    ...
    let vault <- InternalEVM.withdraw(
        from: self.addressBytes,
        amount: balance.attoflow
    ) as! @FlowToken.Vault
    ...
}
``` [4](#0-3) 

COA addresses are allocated deterministically from a UUID and carry the `FlowEVMCOAAddressPrefix`:

```go
FlowEVMCOAAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
``` [5](#0-4) 

Any EVM address that does not match a live COA resource and has no corresponding EVM private key has no withdrawal path. The `Account.Withdraw()` implementation in the handler enforces `isAuthorized = true`, meaning it only works for COA-controlled addresses:

```go
const isAuthorized = true
account := handler.AccountByAddress(fromAddress, isAuthorized)
vault := account.Withdraw(amount)
``` [6](#0-5) 

---

### Impact Explanation

FLOW tokens deposited to a non-COA, non-EOA EVM address are permanently trapped in the EVM environment. There is no admin escape hatch, no protocol-level burn/recovery function, and no way to call `withdraw()` without the COA resource. The loss is irreversible on-chain.

---

### Likelihood Explanation

`EVM.EVMAddress.deposit()` is `access(all)` — any unprivileged Cadence transaction can call it with an arbitrary 20-byte address. This is a realistic user-error scenario (e.g., depositing to a zero address, a precompile address, a mistyped address, or a freshly generated address whose private key was discarded). No protocol-level guard prevents it.

---

### Recommendation

Add a pre-condition in `EVMAddress.deposit()` that verifies the target address carries the COA address prefix (`FlowEVMCOAAddressPrefix`), or restrict the function to `access(contract)` and expose deposit only through `CadenceOwnedAccount.deposit()`. At minimum, emit a structured warning event when FLOW is deposited to a non-COA address so off-chain tooling can alert users before the transaction is finalized.

---

### Proof of Concept

Any unprivileged transaction sender can execute:

```cadence
import EVM from 0x...
import FungibleToken from 0x...
import FlowToken from 0x...

transaction {
    prepare(account: auth(BorrowValue) &Account) {
        let vaultRef = account.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)
            ?? panic("no vault")

        let vault <- vaultRef.withdraw(amount: 10.0) as! @FlowToken.Vault

        // Arbitrary address — no COA resource, no private key
        let sink = EVM.EVMAddress(
            bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        )
        sink.deposit(from: <-vault)
        // 10 FLOW are now permanently trapped; no CadenceOwnedAccount exists
        // for this address, so withdraw() can never be called.
    }
}
```

The vault resource is consumed by `InternalEVM.deposit()` [7](#0-6) , the balance is credited to the sink address in EVM state, and no recovery path exists because `CadenceOwnedAccount.withdraw()` requires the caller to hold the resource for that exact address. [8](#0-7)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L157-165)
```text
    access(all) struct EVMAddress {

        /// Bytes of the address
        access(all) let bytes: [UInt8; 20]

        /// Constructs a new EVM address from the given byte representation
        view init(bytes: [UInt8; 20]) {
            self.bytes = bytes
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

**File:** fvm/evm/impl/impl.go (L677-679)
```go
			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))
```

**File:** fvm/evm/impl/impl.go (L789-791)
```go
			const isAuthorized = true
			account := handler.AccountByAddress(fromAddress, isAuthorized)
			vault := account.Withdraw(amount)
```

**File:** fvm/evm/types/address.go (L39-41)
```go
	FlowEVMCOAAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	// Coinbase address
	CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
```
