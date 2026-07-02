### Title
EVM Pause Blocks User Withdrawal of FLOW Tokens and Bridged Assets from CadenceOwnedAccount - (File: fvm/evm/stdlib/contract.cdc)

### Summary
The `CadenceOwnedAccount.withdraw()`, `withdrawNFT()`, and `withdrawTokens()` functions in the EVM Cadence contract each contain an `!EVM.isPaused()` precondition that prevents users from reclaiming their assets when EVM operations are paused. The Governance Committee can set this flag at any time, leaving user FLOW tokens, NFTs, and fungible tokens permanently locked inside their Cadence-Owned Accounts (COAs).

### Finding Description
In `fvm/evm/stdlib/contract.cdc`, the three user-exit methods on `CadenceOwnedAccount` all gate on the global pause flag:

**`CadenceOwnedAccount.withdraw()`** — the sole path for a COA owner to move FLOW tokens back to Cadence: [1](#0-0) 

**`CadenceOwnedAccount.withdrawNFT()`** — the sole path to retrieve a bridged NFT from EVM: [2](#0-1) 

**`CadenceOwnedAccount.withdrawTokens()`** — the sole path to retrieve bridged fungible tokens from EVM: [3](#0-2) 

The pause flag is read from the EVM contract account's own storage: [4](#0-3) 

The comment in the contract confirms the Governance Committee can set this flag unilaterally via a multi-sig Cadence transaction: [5](#0-4) 

Notably, `CadenceOwnedAccount.deposit()` delegates to `EVMAddress.deposit()`, which also carries the same pause guard: [6](#0-5) 

This means that when EVM is paused, users can neither deposit into nor withdraw from their COAs — but the asymmetry that matters for fund safety is the withdrawal side: assets already inside a COA cannot be recovered.

### Impact Explanation
**High.** A COA is the only Cadence-native mechanism for holding and interacting with EVM-side FLOW balances, NFTs, and fungible tokens. When `EVM.isPaused()` returns `true`, every call to `withdraw()`, `withdrawNFT()`, or `withdrawTokens()` panics unconditionally. If the Governance Committee pauses EVM and subsequently loses the ability to unpause (key loss, governance failure, or intentional renunciation), all assets held in every COA on the network are permanently frozen with no escape path.

### Likelihood Explanation
**Low.** Triggering this requires the Governance Committee to act maliciously or to pause EVM and then lose control of the unpause capability. This is the same likelihood profile as the reference report (malicious or compromised owner). The multi-sig requirement raises the bar, but does not eliminate the risk of governance failure or key loss.

### Recommendation
Remove the `!EVM.isPaused()` precondition from `CadenceOwnedAccount.withdraw()`, `withdrawNFT()`, and `withdrawTokens()`. These are pure user-exit operations: they move assets from EVM state back to Cadence and do not advance EVM execution or mutate shared EVM state in a way that requires the EVM to be live. State-mutating operations (`call`, `deploy`, `run`, `batchRun`, `deposit`) can retain the pause guard. This mirrors the standard recommendation in the reference report: preserve the pause for entry/execution paths, but never block user exits.

### Proof of Concept
1. Governance Committee stores `true` at `/storage/evmOperationsPaused` in the EVM contract account via a multi-sig transaction.
2. `EVM.isPaused()` now returns `true` for all callers.
3. A user who holds FLOW tokens in their COA submits:
   ```cadence
   import EVM from <EVMAddress>
   transaction {
       prepare(account: auth(Storage) &Account) {
           let bal = EVM.Balance(attoflow: 0)
           bal.setFLOW(flow: 1.0)
           let coa = account.storage
               .borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(from: /storage/coa)!
           let vault <- coa.withdraw(balance: bal)   // panics here
           destroy <- vault
       }
   }
   ```
4. The precondition `!EVM.isPaused()` evaluates to `false`; the transaction aborts with `"EVM operations are temporarily paused"`.
5. The user's FLOW tokens remain locked in the COA with no alternative withdrawal path. The same outcome applies to `withdrawNFT()` and `withdrawTokens()`. [7](#0-6)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L201-205)
```text
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
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

**File:** fvm/evm/stdlib/contract.cdc (L755-763)
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
```

**File:** fvm/evm/stdlib/contract.cdc (L787-795)
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
