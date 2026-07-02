### Title
EVM Pause Mechanism Blocks User Withdrawals, Locking Funds in CadenceOwnedAccount - (File: fvm/evm/stdlib/contract.cdc)

---

### Summary
The `EVM` contract in `fvm/evm/stdlib/contract.cdc` applies the `isPaused()` guard uniformly to both deposit and withdrawal operations on `CadenceOwnedAccount`. When the Governance Committee pauses EVM for maintenance or a security incident, users are unable to withdraw their FLOW tokens, NFTs, or fungible tokens from their COA accounts back to Cadence, effectively locking all bridged assets for the duration of the pause.

---

### Finding Description
The `isPaused()` function reads a boolean flag from `/storage/evmOperationsPaused` on the EVM contract account. [1](#0-0) 

This guard is applied to the following **withdrawal** functions inside `CadenceOwnedAccount`:

**`CadenceOwnedAccount.withdraw()`** — moves FLOW tokens from EVM back to Cadence: [2](#0-1) 

**`CadenceOwnedAccount.withdrawNFT()`** — bridges an NFT from EVM back to Cadence: [3](#0-2) 

**`CadenceOwnedAccount.withdrawTokens()`** — bridges fungible tokens from EVM back to Cadence: [4](#0-3) 

The same guard is also applied to `EVMAddress.deposit()` and `CadenceOwnedAccount.deposit()` (via delegation), which is the intended protective behavior: [5](#0-4) 

The design intent documented in the contract is that EVM enters a "read-only mode" during a pause: [6](#0-5) 

However, withdrawals (moving assets **out** of EVM **to** Cadence) are not state mutations that pose a security risk to the EVM environment — they are asset recovery operations. Blocking them during a pause traps user funds.

---

### Impact Explanation
Any user who has FLOW tokens, NFTs, or fungible tokens held in a `CadenceOwnedAccount` (COA) is unable to recover those assets for the entire duration of the EVM pause. The assets remain locked inside the EVM environment with no escape path. This is a direct loss of asset accessibility for all COA holders — not merely a degraded experience, but a complete inability to access on-chain assets the user legitimately owns.

---

### Likelihood Explanation
The Governance Committee can pause EVM at any time via a multi-sig Cadence transaction. Pauses are explicitly anticipated for maintenance and security incidents. Given that the Flow EVM bridge holds real user funds, any pause of non-trivial duration directly materializes this impact. The behavior is confirmed by the existing test suite, which asserts that `CadenceOwnedAccount.withdraw` **fails** when EVM is paused: [7](#0-6) 

---

### Recommendation
Remove the `!EVM.isPaused()` precondition from the three withdrawal functions: `CadenceOwnedAccount.withdraw()`, `CadenceOwnedAccount.withdrawNFT()`, and `CadenceOwnedAccount.withdrawTokens()`. The pause guard should only apply to operations that introduce new state into EVM (deposits, `run`, `call`, `deploy`, `createCadenceOwnedAccount`). Withdrawals move assets from EVM to Cadence and do not require EVM state mutation in a way that poses a security risk during a pause.

---

### Proof of Concept

1. Governance Committee sets `/storage/evmOperationsPaused = true` on the EVM contract account (standard governance multi-sig transaction).
2. A user who previously deposited FLOW into their COA submits a transaction calling:
   ```cadence
   let bal = EVM.Balance(attoflow: 0)
   bal.setFLOW(flow: 1.0)
   let vault <- coa.withdraw(balance: bal)
   ```
3. The `pre` condition `!EVM.isPaused()` evaluates to `false`, causing the transaction to abort with `"EVM operations are temporarily paused"`.
4. The user's FLOW tokens remain locked inside EVM with no alternative withdrawal path.
5. The same outcome applies to `withdrawNFT` and `withdrawTokens` for any bridged NFTs or fungible tokens held in the COA. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** fvm/evm/evm_test.go (L6794-6832)
```go
			t.Run("testing CadenceOwnedAccount.withdraw when EVM is paused", func(t *testing.T) {
				code = fmt.Appendf(nil,
					`
					import EVM from %s
					import FlowToken from %s

					transaction {
						prepare(account: auth(Storage) &Account) {
							let bal = EVM.Balance(attoflow: 0)
							bal.setFLOW(flow: 1.23)
							let coa = account.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(
								from: /storage/coa
							)!
							let vault2 <- coa.withdraw(balance: bal)
							destroy <- vault2
						}
					}
					`,
					sc.EVMContract.Address.HexWithPrefix(),
					sc.FlowToken.Address.HexWithPrefix(),
				)

				txBody, err = flow.NewTransactionBodyBuilder().
					SetScript(code).
					SetPayer(sc.FlowServiceAccount.Address).
					AddAuthorizer(sc.FlowServiceAccount.Address).
					Build()
				require.NoError(t, err)

				tx = fvm.Transaction(txBody, 0)
				_, output, err = vm.Run(ctx, tx, snapshot)
				require.NoError(t, err)
				require.Error(t, output.Err)
				require.ErrorContains(
					t,
					output.Err,
					"EVM operations are temporarily paused",
				)
			})
```
