### Title
Wrong Capability Borrow Type Causes `fundAccountTemplate` Transaction to Always Panic - (File: `fvm/blueprints/scripts/fundAccountTemplate.cdc`)

### Summary
`fundAccountTemplate.cdc` borrows the recipient's receiver capability using the concrete type `<&FlowToken.Vault>` instead of the interface type `<&{FungibleToken.Receiver}>`. Because the capability at `/public/flowTokenReceiver` is published as `&{FungibleToken.Receiver}`, the borrow always returns `nil`, causing the transaction to always panic and fail.

### Finding Description

In `fvm/blueprints/scripts/fundAccountTemplate.cdc`, the `execute` block attempts to borrow the recipient's token receiver capability using the wrong type:

```cadence
let receiverRef = getAccount(recipient)
    .capabilities.borrow<&FlowToken.Vault>(/public/flowTokenReceiver)
    ?? panic("failed to borrow reference to recipient vault")
receiverRef.deposit(from: <-self.sentVault)
``` [1](#0-0) 

In Cadence's capability system, a borrow succeeds only if the requested type is a supertype of (or equal to) the published capability's borrow type. The standard Flow token setup publishes the receiver capability at `/public/flowTokenReceiver` as `&{FungibleToken.Receiver}`. Requesting the more specific concrete type `&FlowToken.Vault` is a downcast that the capability system does not permit — the borrow returns `nil`.

Every other analogous script in the codebase correctly uses `<&{FungibleToken.Receiver}>`:

```cadence
// Correct pattern used everywhere else:
let receiverRef = recipient.capabilities.borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)
``` [2](#0-1) [3](#0-2) 

### Impact Explanation

Any transaction that uses `fundAccountTemplate.cdc` to fund an account will always panic at the `?? panic(...)` guard because the capability borrow returns `nil`. The `prepare` phase successfully withdraws tokens from the signer's vault into `self.sentVault`, but the `execute` phase always panics before the deposit occurs. Because the transaction reverts on panic, the withdrawn vault is returned to the signer — but the intended recipient funding operation is permanently broken for any caller using this template. This is a direct analog to the original bug: the wrong method is used, causing the function to always revert/panic, making the operation inaccessible.

**Impact: Medium** — the account-funding operation via this blueprint is permanently non-functional.

### Likelihood Explanation

**Likelihood: High** — the failure is deterministic. Every invocation of this transaction against any recipient whose receiver capability is published as `&{FungibleToken.Receiver}` (the standard) will panic. No special conditions are required.

### Recommendation

Change the borrow type from the concrete `&FlowToken.Vault` to the interface `&{FungibleToken.Receiver}`:

```diff
- let receiverRef = getAccount(recipient)
-     .capabilities.borrow<&FlowToken.Vault>(/public/flowTokenReceiver)
-     ?? panic("failed to borrow reference to recipient vault")
+ let receiverRef = getAccount(recipient)
+     .capabilities.borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)
+     ?? panic("failed to borrow reference to recipient vault")
```

### Proof of Concept

1. Deploy a standard Flow token setup (receiver capability published as `&{FungibleToken.Receiver}` at `/public/flowTokenReceiver`).
2. Submit the `fundAccountTemplate.cdc` transaction with any valid `recipient` address and a non-zero `amount`.
3. Observe: the `prepare` phase succeeds (tokens withdrawn from signer's vault), but `execute` panics with `"failed to borrow reference to recipient vault"` because `capabilities.borrow<&FlowToken.Vault>(/public/flowTokenReceiver)` returns `nil`.
4. The transaction reverts; the recipient receives no tokens.

Compare with the correct borrow type used in `setupStorageForAccount.cdc` (line 27) and `tokenTransferTransaction.cdc` (line 15), both of which use `<&{FungibleToken.Receiver}>` and succeed. [4](#0-3) [5](#0-4)

### Citations

**File:** fvm/blueprints/scripts/fundAccountTemplate.cdc (L1-20)
```text
import "FungibleToken"
import "FlowToken"

transaction(amount: UFix64, recipient: Address) {

	let sentVault: @{FungibleToken.Vault}

	prepare(signer: auth(BorrowValue) &Account) {
	    let vaultRef = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)
		    ?? panic("failed to borrow reference to sender vault")
	    self.sentVault <- vaultRef.withdraw(amount: amount)
	}

	execute {
	    let receiverRef =  getAccount(recipient)
		    .capabilities.borrow<&FlowToken.Vault>(/public/flowTokenReceiver)
		    ?? panic("failed to borrow reference to recipient vault")
	    receiverRef.deposit(from: <-self.sentVault)
	}
}
```

**File:** fvm/blueprints/scripts/setupStorageForAccount.cdc (L26-30)
```text
        let receiver = account.capabilities
            .borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)
            ?? panic("Could not borrow receiver reference to the recipient's Vault")

        receiver.deposit(from: <-storageReservation)
```

**File:** integration/benchmark/scripts/tokenTransferTransaction.cdc (L14-17)
```text
        let receiverRef =  getAccount(to)
            .capabilities.borrow<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)
			?? panic("Could not borrow receiver reference to the recipient's Vault")
        receiverRef.deposit(from: <-self.sentVault)
```
