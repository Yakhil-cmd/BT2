### Title
Users Lose Access to EVM-Held Assets When EVM Is Paused With No Emergency Withdrawal Path - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

When the Governance Committee pauses EVM operations by setting `/storage/evmOperationsPaused`, every withdrawal path from a `CadenceOwnedAccount` (COA) is unconditionally blocked by a `!EVM.isPaused()` pre-condition. There is no emergency withdrawal function that bypasses the pause, so any FLOW tokens or bridged assets already held inside EVM become inaccessible for the entire duration of the pause.

### Finding Description

`EVM.isPaused()` reads a boolean from contract storage and returns `true` when the Governance Committee has paused EVM: [1](#0-0) 

Every function that moves value out of EVM carries an unconditional pre-condition that aborts the transaction when the flag is set:

- `CadenceOwnedAccount.withdraw()` (FLOW tokens out of COA): [2](#0-1) 

- `CadenceOwnedAccount.withdrawNFT()` (NFT bridge back to Cadence): [3](#0-2) 

- `CadenceOwnedAccount.withdrawTokens()` (fungible token bridge back to Cadence): [4](#0-3) 

No alternative code path exists that allows a user to recover assets from their COA while the pause is active. The contract provides no `emergencyWithdraw`-style function that skips the pause guard.

### Impact Explanation

Any user who deposited FLOW tokens into their COA (via `EVMAddress.deposit` or `CadenceOwnedAccount.deposit`) before the pause, or who bridged Cadence tokens/NFTs to EVM (escrowing the Cadence asset and minting an EVM counterpart), is left with no on-chain mechanism to recover those assets for the full duration of the pause. If the pause is extended or permanent, the loss is permanent. The Cadence-side escrow for bridged tokens remains locked because the bridge's `withdrawTokens`/`withdrawNFT` paths also require EVM execution, which is blocked. [5](#0-4) 

### Likelihood Explanation

The Governance Committee can legitimately pause EVM for maintenance or emergency governance situations, as documented in the contract comments: [6](#0-5) 

Any user who holds a COA balance at the moment of a pause is immediately affected. The entry path is fully unprivileged: any Cadence transaction sender can deposit FLOW into a COA before the pause occurs. The pause itself is a legitimate, expected protocol operation, not an attack.

### Recommendation

Introduce an emergency withdrawal function on `CadenceOwnedAccount` that does not check `EVM.isPaused()`. Because the FLOW token accounting in EVM is backed 1-to-1 by the `FlowToken` vault held by the EVM contract, a withdrawal can be executed as a direct vault transfer without running EVM state-transition logic. This mirrors the fix recommended in the LaunchEvent report: pay out the underlying asset (LP tokens / FLOW vault) directly in the emergency path, bypassing the state that the pause is protecting.

### Proof of Concept

1. User calls a Cadence transaction that deposits 100 FLOW into their COA:
   ```cadence
   coa.deposit(from: <-vault)   // succeeds, FLOW moves into EVM
   ```
2. Governance Committee stores `true` at `/storage/evmOperationsPaused` (legitimate maintenance pause).
3. User attempts to recover funds:
   ```cadence
   let vault <- coa.withdraw(balance: bal)  // pre-condition !EVM.isPaused() FAILS
   ```
   Transaction aborts with `"EVM operations are temporarily paused"`.
4. No other on-chain path exists to retrieve the 100 FLOW. Assets remain locked in EVM for the duration of the pause with no recourse. [2](#0-1) [7](#0-6)

### Citations

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

**File:** fvm/evm/stdlib/contract.cdc (L756-763)
```text
        fun withdrawNFT(
            type: Type,
            id: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{NonFungibleToken.NFT} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L788-795)
```text
        fun withdrawTokens(
            type: Type,
            amount: UInt256,
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ): @{FungibleToken.Vault} {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L1223-1230)
```text
    /// Returns whether EVM transactions have been paused, either for
    /// maintenance or any situation that requires special governance
    /// handling.
    ///
    /// Only the Governance Committee can pause the EVM transactions, with
    /// a multi-sig Cadence transaction. The EVM enters a read-only mode,
    /// where all EVM state is available for reading, but no state updates
    /// are executed.
```

**File:** fvm/evm/stdlib/contract.cdc (L1231-1236)
```text
    access(all)
    view fun isPaused(): Bool {
        return self.account.storage.copy<Bool>(
            from: /storage/evmOperationsPaused
        ) ?? false
    }
```
