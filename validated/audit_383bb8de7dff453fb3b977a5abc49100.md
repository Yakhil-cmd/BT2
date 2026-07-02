### Title
Unrestricted `CadenceOwnedAccount.deposit()` Allows Anyone to Fund a COA While Only the Owner Can Drain It - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
`CadenceOwnedAccount.deposit()` is declared `access(all)` — requiring no Cadence entitlement — while `withdraw()` is gated behind `access(Owner | Withdraw)`. Any transaction sender who obtains any reference to a COA (including an unentitled public capability) can deposit FLOW tokens into it. The COA owner retains exclusive withdrawal rights and can drain all deposited tokens at will. This is the direct Flow analog of the reported `depositETH()` / malicious-admin-drain pattern.

---

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, the `CadenceOwnedAccount` resource exposes two asymmetric functions:

```cadence
// Line 562-565 — no entitlement required
access(all)
fun deposit(from: @FlowToken.Vault) {
    self.address().deposit(from: <-from)
}
``` [1](#0-0) 

```cadence
// Line 586-606 — Owner or Withdraw entitlement required
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [2](#0-1) 

`deposit()` delegates to `EVMAddress.deposit()`, which itself is also `access(all)` and only checks the global pause flag:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
    InternalEVM.deposit(from: <-from, to: self.bytes)
    ...
}
``` [3](#0-2) 

There is no check that the caller owns or is authorized to interact with the target COA. The entitlement system (`Owner`, `Withdraw`, `Call`, `Deploy`, `Bridge`) is defined for all privileged operations, but `deposit` is deliberately left open: [4](#0-3) 

The Go-layer `newInternalEVMTypeDepositFunction` confirms `isAuthorized = false` is hardcoded — no authorization is checked at the host-function level either: [5](#0-4) 

---

### Impact Explanation

**Analog to Part A (bypass of state checks):** `deposit()` carries no entitlement guard and no state check beyond the global pause. Any unprivileged transaction sender who holds an unentitled reference to a COA (e.g., via a public capability published by the COA owner) can deposit FLOW tokens into it at any time, bypassing any application-level invariants the COA owner may have intended to enforce.

**Analog to Part B (malicious owner drain):** Because `withdraw()` is exclusively gated by `access(Owner | Withdraw)`, the COA owner retains the sole right to pull funds out. A malicious COA owner can:
1. Publish an unentitled public capability to their COA (allowing `access(all)` calls, including `deposit`).
2. Attract users to deposit FLOW tokens into the COA (e.g., as part of a DeFi protocol or escrow service).
3. Call `withdraw()` — which requires only the `Owner` or `Withdraw` entitlement they already hold — to drain all deposited tokens.

The deposited tokens are cross-VM FLOW assets; loss is irreversible on-chain.

---

### Likelihood Explanation

Medium. The attack requires:
- The COA owner to publish a public (unentitled) capability — a common pattern for DeFi protocols built on COAs.
- Users to deposit tokens into the COA — the normal intended usage of the `deposit` path.
- The COA owner to act maliciously — realistic for a rug-pull scenario.

No privileged node access, key compromise, or social engineering beyond normal DeFi interaction is required. The entry path is a standard unprivileged Cadence transaction.

---

### Recommendation

1. **Require an entitlement for `deposit()`** — mirror the pattern used for `withdraw()`, `call()`, `deploy()`, etc., by gating `deposit()` behind `access(Owner | Bridge)` or a new `Deposit` entitlement. This prevents unentitled references from depositing.
2. **Alternatively**, document clearly that `deposit()` is intentionally open and that COA owners who publish public capabilities accept the risk of receiving unsolicited deposits — and ensure no protocol-level accounting assumes deposits only come from authorized senders.
3. For `EVMAddress.deposit()` (the struct-level path), consider whether arbitrary-address deposits into the native token bridge address or other system addresses should be restricted.

---

### Proof of Concept

```cadence
// Attacker transaction — no entitlement needed
import EVM from <EVMContractAddress>
import FlowToken from <FlowTokenAddress>

transaction(coaCapPath: PublicPath) {
    prepare(attacker: auth(BorrowValue) &Account) {
        // 1. Borrow an unentitled reference to the victim's COA via public capability
        let victimCOA = getAccount(<victimAddress>)
            .capabilities.borrow<&EVM.CadenceOwnedAccount>(coaCapPath)!

        // 2. Deposit attacker's own tokens — succeeds because deposit() is access(all)
        let vault <- FlowToken.createEmptyVault(...)
        // ... fund vault ...
        victimCOA.deposit(from: <-vault)
        // Tokens are now in the COA; only the COA owner can withdraw them.
    }
}
```

The COA owner then calls `withdraw()` with their `Owner`/`Withdraw` entitlement to drain all deposited tokens, including those sent by third parties.

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

**File:** fvm/evm/stdlib/contract.cdc (L488-506)
```text
    /* Entitlements enabling finer-grained access control on a CadenceOwnedAccount */

    /// Allows validating ownership of a COA
    access(all) entitlement Validate

    /// Allows withdrawing FLOW from the COA back to Cadence
    access(all) entitlement Withdraw

    /// Allows sending Call transactions from the COA
    access(all) entitlement Call

    /// Allows sending deploy contract transactions from the COA
    access(all) entitlement Deploy

    /// Allows access to all the privliged functionality on a COA
    access(all) entitlement Owner

    /// Allows access to all bridging functionality for COAs
    access(all) entitlement Bridge
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

**File:** fvm/evm/impl/impl.go (L675-679)
```go
			// Deposit

			const isAuthorized = false
			account := handler.AccountByAddress(toAddress, isAuthorized)
			account.Deposit(types.NewFlowTokenVault(amount))
```
