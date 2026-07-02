### Title
Missing `isPaused` Check in `CadenceOwnedAccount.deposit()` Allows FLOW Token Deposits into Paused EVM - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `deposit()` function on `CadenceOwnedAccount` is the only asset-moving EVM operation that lacks the `!EVM.isPaused()` pre-condition check. When an admin pauses EVM to halt all asset movements (e.g., during a security incident), any unprivileged user can still deposit FLOW tokens into EVM addresses. Because `withdraw()` correctly enforces the pause check, this creates a one-way door: tokens enter the paused EVM environment but cannot exit, resulting in cross-VM asset loss.

---

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, every asset-moving operation on `CadenceOwnedAccount` enforces `!EVM.isPaused()` — except `deposit()`:

| Function | Pause Check |
|---|---|
| `withdraw()` | ✅ `pre { !EVM.isPaused() }` |
| `depositNFT()` | ✅ `pre { !EVM.isPaused() }` |
| `withdrawNFT()` | ✅ `pre { !EVM.isPaused() }` |
| `depositTokens()` | ✅ `pre { !EVM.isPaused() }` |
| `withdrawTokens()` | ✅ `pre { !EVM.isPaused() }` |
| `run()` | ✅ `pre { !self.isPaused() }` |
| `createCadenceOwnedAccount()` | ✅ `pre { !self.isPaused() }` |
| **`deposit()`** | ❌ **No check** |

The `withdraw()` function correctly enforces the pause:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [1](#0-0) 

But `deposit()` has no such guard:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    self.address().deposit(from: <-from)
}
``` [2](#0-1) 

The internal Go-layer implementation of deposit (`newInternalEVMTypeDepositFunction`) also contains no pause check:

```go
account := handler.AccountByAddress(toAddress, isAuthorized)
account.Deposit(types.NewFlowTokenVault(amount))
return interpreter.Void
``` [3](#0-2) 

The `depositNFT()` and `depositTokens()` bridge functions do enforce the pause: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

When EVM is paused (an admin-controlled state change), the protocol's intent is to halt all EVM asset movements. The missing check in `deposit()` breaks this invariant:

1. FLOW tokens can still be deposited into any EVM address while EVM is paused.
2. `withdraw()` correctly blocks recovery of those tokens until EVM is unpaused.
3. If EVM was paused due to a vulnerability in EVM state (e.g., a reentrancy or accounting bug), tokens deposited during the pause window are exposed to that vulnerability.
4. Automated systems, DeFi protocols, or uninformed users may continue depositing, permanently or temporarily losing access to their FLOW tokens.

This is a **cross-VM asset loss** scenario: tokens cross from Cadence into a paused, potentially compromised EVM environment with no ability to exit.

---

### Likelihood Explanation

`deposit()` is declared `access(all)`, meaning any transaction sender can invoke it on any `CadenceOwnedAccount`. No entitlement or capability is required beyond possessing a `FlowToken.Vault`. The attacker-controlled entry path is a standard Cadence transaction calling `coaRef.deposit(from: <-vault)`. No staked node, admin key, or privileged access is needed after EVM has been paused. Automated bridging scripts and DeFi integrations that are unaware of the pause state will trigger this path naturally.

---

### Recommendation

Add the `!EVM.isPaused()` pre-condition to `deposit()`, consistent with every other asset-moving operation:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    self.address().deposit(from: <-from)
}
```

---

### Proof of Concept

1. Admin calls the EVM pause mechanism, setting `EVM.isPaused() == true`.
2. An unprivileged user submits a transaction:
   ```cadence
   import EVM from <addr>
   import FlowToken from <addr>
   transaction {
       prepare(signer: auth(BorrowValue) &Account) {
           let coa = signer.storage.borrow<&EVM.CadenceOwnedAccount>(from: /storage/evm)!
           let vault <- signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(
               from: /storage/flowTokenVault)!.withdraw(amount: 1.0) as! @FlowToken.Vault
           coa.deposit(from: <-vault)  // succeeds — no pause check
       }
   }
   ```
3. The deposit succeeds. The user's 1.0 FLOW is now inside the paused EVM.
4. The user attempts `coa.withdraw(balance: ...)` — this panics with `"EVM operations are temporarily paused"`.
5. The 1.0 FLOW is trapped in the paused EVM environment, inaccessible until the admin unpauses EVM.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L562-565)
```text
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L586-590)
```text
        access(Owner | Withdraw)
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L739-742)
```text
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            EVM.borrowBridgeAccessor().depositNFT(nft: <-nft, to: self.address(), feeProvider: feeProvider)
```

**File:** fvm/evm/stdlib/contract.cdc (L778-781)
```text
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            EVM.borrowBridgeAccessor().depositTokens(vault: <-vault, to: self.address(), feeProvider: feeProvider)
```

**File:** fvm/evm/impl/impl.go (L677-681)
```go
			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))

			return interpreter.Void
```
