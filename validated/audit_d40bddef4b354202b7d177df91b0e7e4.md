### Title
Hardcoded `self.address()` as EVM Destination in COA Bridge Functions Can Permanently Lock Bridged Assets - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `CadenceOwnedAccount.depositNFT` and `CadenceOwnedAccount.depositTokens` functions in `fvm/evm/stdlib/contract.cdc` hardcode `to: self.address()` as the EVM destination when bridging assets from Cadence to Flow EVM. Because COA EVM addresses are exclusively controlled by the Cadence resource (no EVM private key exists), if the COA resource is destroyed after bridging, all assets at that EVM address are permanently inaccessible — there is no recovery path.

---

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, the two Cadence-to-EVM bridge entry points on `CadenceOwnedAccount` hardcode the EVM destination as the COA's own address:

```cadence
// Line 742
fun depositNFT(
    nft: @{NonFungibleToken.NFT},
    feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
) {
    EVM.borrowBridgeAccessor().depositNFT(nft: <-nft, to: self.address(), feeProvider: feeProvider)
}
``` [1](#0-0) 

```cadence
// Line 781
fun depositTokens(
    vault: @{FungibleToken.Vault},
    feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
) {
    EVM.borrowBridgeAccessor().depositTokens(vault: <-vault, to: self.address(), feeProvider: feeProvider)
}
``` [2](#0-1) 

The underlying `BridgeAccessor` interface already accepts an explicit `to: EVMAddress` parameter:

```cadence
fun depositNFT(nft: @{NonFungibleToken.NFT}, to: EVMAddress, ...)
fun depositTokens(vault: @{FungibleToken.Vault}, to: EVMAddress, ...)
``` [3](#0-2) 

However, `borrowBridgeAccessor()` is `access(self)`, meaning it is inaccessible to external callers: [4](#0-3) 

The only externally reachable path for bridging Cadence assets to EVM is through the COA wrapper functions, which unconditionally set `to: self.address()`.

COA EVM addresses are special addresses with the `FlowEVMCOAAddressPrefix` (`{0,0,0,0,0,0,0,0,0,0,0,2,...}`): [5](#0-4) 

These addresses have **no EVM private key**. They are exclusively controlled by the Cadence `CadenceOwnedAccount` resource. The `withdraw`, `withdrawNFT`, and `withdrawTokens` functions all require a live reference to the COA resource with the appropriate entitlement (`Owner | Withdraw` or `Owner | Bridge`): [6](#0-5) [7](#0-6) 

The `CadenceOwnedAccount` resource holds only `addressBytes: [UInt8; 20]` — no sub-resources — so it can be destroyed with a plain `destroy` statement without any forced asset handling: [8](#0-7) 

---

### Impact Explanation

If a COA resource is destroyed after assets have been bridged to its EVM address via `depositNFT` or `depositTokens`:

- The bridged NFTs and fungible tokens remain at the COA's EVM address in Flow EVM state.
- There is no Cadence-side resource to call `withdrawNFT` or `withdrawTokens` on.
- There is no EVM-side private key to sign a transfer transaction from the COA address.
- The assets are **permanently locked** with no recovery mechanism.

This is a direct cross-VM asset loss: assets leave the Cadence escrow and arrive at an EVM address that becomes permanently inaccessible.

---

### Likelihood Explanation

The attacker-controlled entry path is a standard unprivileged Cadence transaction:

1. Any user creates a COA via `EVM.createCadenceOwnedAccount()`.
2. The user calls `coa.depositNFT(nft: <-nft, feeProvider: ...)` or `coa.depositTokens(vault: <-vault, feeProvider: ...)` — assets are bridged to `self.address()`.
3. The user (or a Cadence contract managing the COA) calls `destroy coa`.
4. Assets at the COA's EVM address are permanently inaccessible.

This is realistic in contract-managed COA patterns (e.g., a Cadence contract that creates a COA, bridges assets, and later destroys the COA as part of lifecycle management). It is also reachable by any user who misunderstands the relationship between the COA resource and its EVM address.

---

### Recommendation

Allow callers to specify an explicit EVM destination address in `depositNFT` and `depositTokens`, mirroring the existing `BridgeAccessor` interface signature:

```cadence
fun depositNFT(
    nft: @{NonFungibleToken.NFT},
    to: EVMAddress,                  // explicit destination
    feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
) {
    EVM.borrowBridgeAccessor().depositNFT(nft: <-nft, to: to, feeProvider: feeProvider)
}
```

This allows callers to bridge to any EVM address (including non-COA addresses), and avoids the implicit dependency on the COA resource remaining alive. Alternatively, add a `destroy` hook that panics if the COA's EVM address holds a non-zero balance or escrowed assets.

---

### Proof of Concept

```cadence
import EVM from <EVMContractAddress>
import ExampleNFT from <NFTContractAddress>

transaction {
    prepare(signer: auth(Storage) &Account) {
        // Step 1: create COA
        let coa <- EVM.createCadenceOwnedAccount()

        // Step 2: bridge NFT to EVM — destination hardcoded as coa.address()
        let nft <- signer.storage.load<@ExampleNFT.NFT>(from: /storage/exampleNFT)!
        let feeVault = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(
            from: /storage/flowTokenVault)!
        coa.depositNFT(nft: <-nft, feeProvider: feeVault)
        // NFT is now at coa.address() in Flow EVM

        // Step 3: destroy the COA — no sub-resource check prevents this
        destroy coa
        // NFT is now permanently locked at the former COA EVM address.
        // No Cadence reference exists to call withdrawNFT.
        // No EVM private key exists to transfer the NFT from the EVM side.
    }
}
```

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

**File:** fvm/evm/stdlib/contract.cdc (L586-598)
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
```

**File:** fvm/evm/stdlib/contract.cdc (L734-743)
```text
        access(all)
        fun depositNFT(
            nft: @{NonFungibleToken.NFT},
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            EVM.borrowBridgeAccessor().depositNFT(nft: <-nft, to: self.address(), feeProvider: feeProvider)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L755-769)
```text
        access(Owner | Bridge)
        fun withdrawNFT(
            type: Type,
            id: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{NonFungibleToken.NFT} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return <- EVM.borrowBridgeAccessor().withdrawNFT(
                caller: &self as auth(Call) &CadenceOwnedAccount,
                type: type,
                id: id,
                feeProvider: feeProvider
            )
```

**File:** fvm/evm/stdlib/contract.cdc (L773-782)
```text
        access(all)
        fun depositTokens(
            vault: @{FungibleToken.Vault},
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            EVM.borrowBridgeAccessor().depositTokens(vault: <-vault, to: self.address(), feeProvider: feeProvider)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1122-1144)
```text
        access(Bridge)
        fun depositNFT(
            nft: @{NonFungibleToken.NFT},
            to: EVMAddress,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        )

        /// Endpoint enabling the bridging of an NFT from EVM
        access(Bridge)
        fun withdrawNFT(
            caller: auth(Call) &CadenceOwnedAccount,
            type: Type,
            id: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{NonFungibleToken.NFT}

        /// Endpoint enabling the bridging of a fungible token vault to EVM
        access(Bridge)
        fun depositTokens(
            vault: @{FungibleToken.Vault},
            to: EVMAddress,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        )
```

**File:** fvm/evm/stdlib/contract.cdc (L1184-1189)
```text
    access(self)
    view fun borrowBridgeAccessor(): auth(Bridge) &{BridgeAccessor} {
        return self.account.storage.borrow<auth(Bridge) &{BridgeRouter}>(from: /storage/evmBridgeRouter)
            ?.borrowBridgeAccessor()
            ?? panic("EVM.borrowBridgeAccessor(): Could not borrow a reference to the EVM bridge.")
    }
```

**File:** fvm/evm/types/address.go (L38-41)
```go
	// Prefix for the COA addresses
	FlowEVMCOAAddressPrefix = [FlowEVMSpecialAddressPrefixLen]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	// Coinbase address
	CoinbaseAddress = Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0}
```
