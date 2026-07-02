### Title
Destroyed `CadenceOwnedAccount` Resource Permanently Orphans EVM Address and Locks Bridge-Escrowed Assets — (`File: fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `CadenceOwnedAccount` (COA) resource in `fvm/evm/stdlib/contract.cdc` is the sole controller of its associated EVM address. Its EVM address is derived once from the resource's Cadence `uuid` and can never be re-created. The resource defines no destruction guard. Any owner can call `destroy cadenceOwnedAccount` in a Cadence transaction, permanently orphaning the EVM address and irrecoverably locking all FLOW tokens held there, all Cadence NFTs/FTs escrowed in the bridge on the Cadence side, and all EVM-side ERC721/ERC20 tokens at that address. There is no re-register or re-assign mechanism.

---

### Finding Description

`EVM.createCadenceOwnedAccount()` allocates a new EVM address deterministically from the Cadence resource `uuid`:

```cadence
let acc <-create CadenceOwnedAccount()
let addr = InternalEVM.createCadenceOwnedAccount(uuid: acc.uuid)
acc.initAddress(addressBytes: addr)
``` [1](#0-0) 

Because every Cadence resource gets a globally unique, monotonically increasing `uuid`, no two COA resources can ever share the same EVM address. `initAddress` enforces a one-time write:

```cadence
pre {
    self.addressBytes == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
        "EVM.CadenceOwnedAccount.initAddress(): Cannot initialize the address bytes if it has already been set!"
}
``` [2](#0-1) 

The COA resource has **no `destroy` hook** and **no pre-condition** preventing destruction while assets are held. The resource body ends at line 803 with no destructor defined: [3](#0-2) 

Every privileged operation that moves value out of the COA requires a live, entitled reference to the resource:

- `withdraw` (FLOW back to Cadence) requires `auth(Owner | Withdraw)`: [4](#0-3) 

- `withdrawNFT` (bridge NFT back to Cadence) requires `auth(Owner | Bridge)` and passes `&self as auth(Call) &CadenceOwnedAccount` to the bridge accessor: [5](#0-4) 

- `withdrawTokens` (bridge FTs back to Cadence) requires `auth(Owner | Bridge)` and passes the same self-reference: [6](#0-5) 

`depositNFT` and `depositTokens` are `access(all)` — no entitlement is needed to lock assets into the bridge: [7](#0-6) 

Once the COA resource is destroyed, the entitled self-reference required by all three withdrawal paths ceases to exist. Because the EVM address is not controlled by any private key (by design — COAs are keyless), the EVM address is also permanently inaccessible from the EVM side.

---

### Impact Explanation

Destroying a COA resource causes simultaneous, permanent, irrecoverable loss of:

1. **FLOW tokens** held at the COA's EVM address — `withdraw` can never be called again.
2. **Cadence NFTs escrowed in the bridge** — `withdrawNFT` requires the live COA reference; the Cadence-side escrow vault is permanently locked.
3. **Cadence FTs escrowed in the bridge** — `withdrawTokens` has the same dependency; the Cadence-side escrow vault is permanently locked.
4. **EVM-side ERC721/ERC20 tokens** at the orphaned address — no key and no COA resource means no EVM transaction can ever originate from that address.

There is no re-register or re-assign path: `createCadenceOwnedAccount` always allocates a fresh `uuid` → fresh EVM address. The orphaned address is unreachable forever.

This is a **cross-VM asset loss** impact matching the target scope.

---

### Likelihood Explanation

The entry path is reachable by any unprivileged transaction sender who owns a COA. `destroy cadenceOwnedAccount` is valid Cadence syntax, demonstrated throughout the test suite: [8](#0-7) 

Realistic scenarios:
- A developer destroys a COA in a cleanup transaction after bridging assets but before bridging back.
- A compromised or buggy Cadence contract destroys the COA resource it holds.
- A user misunderstands the keyless nature of COAs and destroys the resource thinking the EVM address remains accessible.

No admin access, no leaked keys, and no staked-node compromise is required.

---

### Recommendation

Add a `ResourceDestroyed` event or a `destroy` pre-condition to the `CadenceOwnedAccount` resource that panics (or at minimum emits a warning) if the COA's EVM balance is non-zero or if the bridge escrow holds assets for that address. Alternatively, enforce that `withdraw` is called to zero out the EVM balance before the resource can be destroyed, mirroring how Cadence `FungibleToken.Vault` resources enforce zero-balance destruction. A re-assign mechanism — allowing a new COA to claim control of an orphaned EVM address via a governance or proof-of-prior-ownership path — would fully close the gap.

---

### Proof of Concept

```cadence
import EVM from <EVMAddress>
import FlowToken from <FlowTokenAddress>
import NonFungibleToken from <NFTAddress>

transaction {
    prepare(account: auth(Storage) &Account) {
        // Step 1: Create a COA and fund it
        let coa <- EVM.createCadenceOwnedAccount()
        let vault <- account.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!
            .withdraw(amount: 10.0) as! @FlowToken.Vault
        coa.deposit(from: <-vault)

        // Step 2: Bridge a Cadence NFT to EVM — NFT is now locked in Cadence-side escrow
        let nft <- account.storage.borrow<auth(NonFungibleToken.Withdraw) &{NonFungibleToken.Collection}>(
            from: /storage/myNFTCollection)!.withdraw(withdrawID: 42)
        let feeVault <- account.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!
            .withdraw(amount: 0.001) as! @FlowToken.Vault
        coa.depositNFT(nft: <-nft, feeProvider: &feeVault as auth(FungibleToken.Withdraw) &{FungibleToken.Provider})
        destroy feeVault

        // Step 3: Destroy the COA — no guard prevents this
        destroy coa
        // Result:
        //   - 10.0 FLOW at the COA's EVM address: permanently inaccessible
        //   - NFT #42 in Cadence-side bridge escrow: permanently locked
        //   - EVM-side ERC721 at orphaned address: permanently locked
        //   - No re-register or re-assign path exists
    }
}
```

The `CadenceOwnedAccount` resource definition carries no destructor guard: [9](#0-8) 

The address allocation is uuid-bound and one-time: [10](#0-9)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L518-803)
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

        /// Sets the EVM address for the COA. Only callable once on initial creation.
        ///
        /// @param addressBytes: The 20 byte EVM address
        access(contract)
        fun initAddress(addressBytes: [UInt8; 20]) {
            // only allow set address for the first time
            // check address is empty
            pre {
                self.addressBytes == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]:
                    "EVM.CadenceOwnedAccount.initAddress(): Cannot initialize the address bytes if it has already been set!"
            }
           self.addressBytes = addressBytes
        }

        /// Gets The EVM address of the cadence owned account
        ///
        access(all)
        view fun address(): EVMAddress {
            // Always create a new EVMAddress instance
            return EVMAddress(bytes: self.addressBytes)
        }

        /// Gets the balance of the cadence owned account
        ///
        access(all)
        view fun balance(): Balance {
            return Balance(attoflow: InternalEVM.balance(address: self.addressBytes))
        }

        /// Deposits the given vault into the cadence owned account's balance
        ///
        /// @param from: The FlowToken Vault to deposit to this cadence owned account
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }

        /// Gets the EVM address of the cadence owned account behind an entitlement,
        /// acting as proof of access
        access(Owner | Validate)
        view fun protectedAddress(): EVMAddress {
            return self.address()
        }

        /// Withdraws the balance from the cadence owned account's balance.
        /// Note that amounts smaller than 1e10 attoFlow can't be withdrawn,
        /// given that Flow Token Vaults use UFix64 to store balances.
        /// In other words, the smallest withdrawable amount is 1e10 attoFlow.
        /// Amounts smaller than 1e10 attoFlow, will cause the function to panic
        /// with: "withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow".
        /// If the given balance conversion to UFix64 results in rounding loss,
        /// the withdrawal amount will be truncated to the maximum precision for UFix64.
        ///
        /// @param balance: The EVM balance to withdraw
        ///
        /// @return A FlowToken Vault with the requested balance
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

        /// Deploys a contract to the EVM environment.
        /// Returns the result which contains address of
        /// the newly deployed contract
        ///
        /// @param code: The bytecode of the Solidity contract
        /// @param gasLimit: The EVM Gas limit for the deployment transaction
        /// @param value: The value, as an EVM.Balance object, to send with the deployment
        ///
        /// @return The EVM transaction result
        access(Owner | Deploy)
        fun deploy(
            code: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.deploy(
                from: self.addressBytes,
                code: code,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
        }

        /// Calls a function with the given data.
        /// The execution is limited by the given amount of gas
        access(Owner | Call)
        fun call(
            to: EVMAddress,
            data: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.call(
                from: self.addressBytes,
                to: to.bytes,
                data: data,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
        }

        /// Calls a contract function with the given signature and args.
        /// The execution is limited by the given amount of gas.
        /// The value is attoflow.  If the resultTypes is provided,
        /// the evm call results are decoded and returned in ResultDecoded.results;
        /// otherwise, the evm call results are discarded and not returned.
        access(Owner | Call)
        fun callWithSigAndArgs(
            to: EVMAddress,
            signature: String,
            args: [AnyStruct],
            gasLimit: UInt64,
            value: UInt,
            resultTypes: [Type]?
        ): ResultDecoded {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            return InternalEVM.callWithSigAndArgs(
                from: self.addressBytes,
                to: to.bytes,
                signature: signature,
                args: args,
                gasLimit: gasLimit,
                value: value,
                resultTypes: resultTypes
            ) as! ResultDecoded
        }

        /// Calls a contract function with the given data.
        /// The execution is limited by the given amount of gas.
        /// The transaction state changes are not persisted.
        access(all)
        fun dryCall(
            to: EVMAddress,
            data: [UInt8],
            gasLimit: UInt64,
            value: Balance,
        ): Result {
            return InternalEVM.dryCall(
                from: self.addressBytes,
                to: to.bytes,
                data: data,
                gasLimit: gasLimit,
                value: value.attoflow
            ) as! Result
        }

        /// Calls a contract function with the given signature and args.
        /// The execution is limited by the given amount of gas.
        /// The value is attoflow.  If the resultTypes is provided,
        /// the evm call results are decoded and returned in ResultDecoded.results;
        /// otherwise, the evm call results are discarded and not returned.
        /// The transaction state changes are not persisted.
        access(all)
        fun dryCallWithSigAndArgs(
            to: EVMAddress,
            signature: String,
            args: [AnyStruct],
            gasLimit: UInt64,
            value: UInt,
            resultTypes: [Type]?
        ): ResultDecoded {
            return InternalEVM.dryCallWithSigAndArgs(
                from: self.addressBytes,
                to: to.bytes,
                signature: signature,
                args: args,
                gasLimit: gasLimit,
                value: value,
                resultTypes: resultTypes,
            ) as! ResultDecoded
        }

        /// Bridges the given NFT to the EVM environment, requiring a Provider
        /// from which to withdraw a fee to fulfill the bridge request
        ///
        /// @param nft: The NFT to bridge to the COA's address in Flow EVM
        /// @param feeProvider: A Withdraw entitled Provider reference to a FlowToken Vault
        ///                     that contains the fees to be taken to pay for bridging
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

        /// Bridges the given NFT from the EVM environment, requiring a Provider
        /// from which to withdraw a fee to fulfill the bridge request.
        /// Note: the caller has to own the requested NFT in EVM
        ///
        /// @param type: The Cadence type of the NFT to withdraw
        /// @param id: The EVM ERC721 ID of the NFT to withdraw
        /// @param feeProvider: A Withdraw entitled Provider reference to a FlowToken Vault
        ///                     that contains the fees to be taken to pay for bridging
        ///
        /// @return The requested NFT
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

        /// Bridges the given Vault to the EVM environment
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

        /// Bridges the given fungible tokens from the EVM environment, requiring a Provider from which to withdraw a
        /// fee to fulfill the bridge request. Note: the caller should own the requested tokens & sufficient balance of
        /// requested tokens in EVM
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
    }
```

**File:** fvm/evm/stdlib/contract.cdc (L807-817)
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
    }
```

**File:** fvm/evm/evm_test.go (L2445-2446)
```go
						destroy cadenceOwnedAccount
						destroy vault2
```
