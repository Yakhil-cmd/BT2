### Title
Cross-VM Asset Loss: Cadence Bridge Escrow Assets Permanently Locked When Bridged EVM Tokens Are Transferred to Non-COA Addresses — (`File: fvm/evm/stdlib/contract.cdc`)

---

### Summary

The Flow EVM bridge's return path (`withdrawNFT` / `withdrawTokens`) is exclusively gated on the caller presenting an `auth(Call) &CadenceOwnedAccount` (COA) resource. Because a COA can freely issue arbitrary EVM calls — including standard ERC-721 `transferFrom` and ERC-20 `transfer` — a user can move bridged EVM tokens to any EVM address (regular EOA or non-COA smart contract) that has no corresponding COA resource. Once that transfer occurs, the Cadence-side assets locked in the bridge escrow (`FlowEVMBridgeNFTEscrow` / `FlowEVMBridgeTokenEscrow`) become permanently inaccessible: the original COA no longer owns the EVM token, and the new EVM owner has no COA with which to invoke the bridge-back. This is a direct structural analog to the TimeLockPool "shares transferred, deposits stuck" class of vulnerability.

---

### Finding Description

When a Cadence NFT or fungible token is bridged to EVM, two things happen simultaneously:

1. The Cadence asset is locked in the bridge escrow contract (`FlowEVMBridgeNFTEscrow` / `FlowEVMBridgeTokenEscrow`).
2. A corresponding ERC-721 or ERC-20 token is minted to the COA's EVM address.

`depositNFT` hard-codes the destination as `self.address()` (the calling COA's EVM address):

```cadence
EVM.borrowBridgeAccessor().depositNFT(nft: <-nft, to: self.address(), feeProvider: feeProvider)
``` [1](#0-0) 

The only bridge-back path is `withdrawNFT` / `withdrawTokens`, both of which pass `&self as auth(Call) &CadenceOwnedAccount` to the `BridgeAccessor`:

```cadence
return <- EVM.borrowBridgeAccessor().withdrawNFT(
    caller: &self as auth(Call) &CadenceOwnedAccount,
    ...
)
``` [2](#0-1) 

The `BridgeAccessor` interface enforces this at the type level — there is no overload that accepts an arbitrary EVM address or a raw EVM proof of ownership:

```cadence
fun withdrawNFT(
    caller: auth(Call) &CadenceOwnedAccount,
    type: Type,
    id: UInt256,
    feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
): @{NonFungibleToken.NFT}
``` [3](#0-2) 

```cadence
fun withdrawTokens(
    caller: auth(Call) &CadenceOwnedAccount,
    type: Type,
    amount: UInt256,
    feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
): @{FungibleToken.Vault}
``` [4](#0-3) 

Meanwhile, the COA's `call()` function (entitlement `Owner | Call`) allows the COA owner to issue arbitrary EVM transactions — including calling `transferFrom` on the ERC-721 contract to move the bridged token to any EVM address. Once the ERC-721 / ERC-20 leaves the COA's EVM address:

- The original COA can no longer satisfy the bridge's EVM ownership check (the bridge verifies the caller's COA address owns the token, as documented: *"Note: the caller has to own the requested NFT in EVM"*).
- The new EVM address (regular EOA or non-COA contract) has no `CadenceOwnedAccount` resource and therefore cannot call `withdrawNFT` / `withdrawTokens` at all.

The Cadence asset is permanently locked in escrow with no recovery path.

---

### Impact Explanation

**Cross-VM asset loss.** Any Cadence NFT or fungible token that has been bridged to EVM and whose corresponding ERC-721 / ERC-20 token is subsequently transferred to a non-COA EVM address is permanently unrecoverable. The bridge escrow holds the Cadence asset indefinitely; neither the original depositor nor the new EVM token holder can release it. This is not a theoretical edge case: standard EVM DeFi interactions (listing an NFT on an EVM marketplace, depositing ERC-20 into an EVM liquidity pool, sending tokens to a friend's EOA) all involve transferring the EVM token away from the COA's address.

---

### Likelihood Explanation

**Medium.** The COA `call()` function is a first-class, publicly documented feature intended for EVM interoperability. Any user who bridges a Cadence asset to EVM and then interacts with EVM protocols (marketplaces, DEXes, lending protocols) will naturally transfer the ERC-721 / ERC-20 away from their COA address. There is no on-chain warning, no guard, and no recovery mechanism. The scenario requires only two unprivileged transactions by the asset owner and no special privileges or coordination.

---

### Recommendation

1. **Decouple bridge-back authorization from current EVM ownership.** The `BridgeAccessor.withdrawNFT` / `withdrawTokens` interface should accept either a COA caller (current path) **or** a proof that the caller controls the EVM address that currently holds the token (e.g., an EVM signature or a COA whose address matches the current ERC-721 owner).
2. **Alternatively, track the original depositing COA address in the escrow record** and allow the original depositor to reclaim the Cadence asset if the EVM token has been transferred away (analogous to the TimeLockPool recommendation to rewrite deposit records on transfer).
3. **At minimum, emit a warning** in `depositNFT` / `depositTokens` that transferring the resulting EVM token to a non-COA address will permanently strand the Cadence-side escrow asset.

---

### Proof of Concept

```
Step 1 — Bridge Cadence NFT to EVM (unprivileged transaction by User1):
  User1 calls coa.depositNFT(nft: <-myNFT, feeProvider: ...)
  → myNFT is locked in FlowEVMBridgeNFTEscrow
  → ERC-721 token #42 is minted to coa.address() (User1's COA EVM address)

Step 2 — Transfer ERC-721 to a regular EOA (unprivileged EVM call via COA):
  User1 calls coa.call(
      to: erc721ContractAddress,
      data: abi.encodeCall(transferFrom, (coa.address(), regularEOA, 42)),
      gasLimit: 100_000,
      value: EVM.Balance(attoflow: 0)
  )
  → ERC-721 #42 is now owned by regularEOA (a plain EVM address with no COA)

Step 3 — User1 attempts bridge-back (fails):
  User1 calls coa.withdrawNFT(type: ..., id: 42, feeProvider: ...)
  → Bridge checks: does coa.address() own ERC-721 #42? NO → transaction reverts.
  → myNFT remains locked in FlowEVMBridgeNFTEscrow.

Step 4 — regularEOA attempts bridge-back (impossible):
  regularEOA has no CadenceOwnedAccount resource.
  withdrawNFT requires auth(Call) &CadenceOwnedAccount — there is no callable path.
  → myNFT is permanently stuck in FlowEVMBridgeNFTEscrow.
```

Root cause lines: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** fvm/evm/stdlib/contract.cdc (L755-770)
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
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L787-802)
```text
        access(Owner | Bridge)
        fun withdrawTokens(
            type: Type,
            amount: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{FungibleToken.Vault} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return <- EVM.borrowBridgeAccessor().withdrawTokens(
                caller: &self as auth(Call) &CadenceOwnedAccount,
                type: type,
                amount: amount,
                feeProvider: feeProvider
            )
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L1129-1154)
```text
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

        /// Endpoint enabling the bridging of fungible tokens from EVM
        access(Bridge)
        fun withdrawTokens(
            caller: auth(Call) &CadenceOwnedAccount,
            type: Type,
            amount: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{FungibleToken.Vault}
    }
```
