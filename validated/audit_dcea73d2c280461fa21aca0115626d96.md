### Title
Inability to Withdraw FLOW Tokens from COA Due to `isPaused()` Check in `EVM.CadenceOwnedAccount.withdraw()` - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

The `EVM.CadenceOwnedAccount.withdraw()` function enforces a `pre { !EVM.isPaused() }` condition that prevents any user from withdrawing their FLOW tokens from their Cadence Owned Account (COA) back to Cadence when EVM operations are paused by the Governance Committee. This traps user funds in EVM with no emergency exit path.

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, the `CadenceOwnedAccount.withdraw()` function contains a precondition that unconditionally blocks execution when EVM is paused:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
```

The `isPaused()` function reads a boolean flag from contract storage:

```cadence
access(all)
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
```

The contract documentation states the intent of the pause is to put EVM into a "read-only mode, where all EVM state is available for reading, but no state updates are executed." However, `CadenceOwnedAccount.withdraw()` — which moves a user's own FLOW tokens from EVM back to Cadence — is also blocked by this check. There is no emergency withdrawal path that bypasses the pause for fund-recovery purposes.

The same `!EVM.isPaused()` guard also blocks `withdrawNFT()` and `withdrawTokens()`, meaning all asset-recovery operations from EVM to Cadence are frozen simultaneously. [1](#0-0) [2](#0-1) 

### Impact Explanation

Any user who holds FLOW tokens (or bridged NFTs/fungible tokens) inside a COA is unable to recover those assets for the entire duration of the EVM pause. The pause is a governance-level action with no defined maximum duration. Because the `withdraw()` precondition is a hard panic, the transaction reverts entirely — there is no partial or degraded path to retrieve funds. This constitutes direct, on-chain asset inaccessibility for all COA holders simultaneously. [3](#0-2) 

### Likelihood Explanation

The EVM pause is activated by the Governance Committee via a multi-sig Cadence transaction. The pause mechanism is explicitly designed for "maintenance or any situation that requires special governance handling," meaning it is a realistic operational event. Any COA holder active at the time of a pause — which could include DeFi protocols, bridges, or individual users — is immediately and completely locked out of their funds with no recourse. The attacker-controlled entry path is simply submitting a `CadenceOwnedAccount.withdraw()` transaction while the pause flag is set; the precondition check is the necessary vulnerable step. [4](#0-3) 

### Recommendation

Separate the pause semantics for inbound (new usage) versus outbound (fund recovery) operations. The `withdraw()`, `withdrawNFT()`, and `withdrawTokens()` functions should be exempt from the `isPaused()` guard, since they move assets from EVM back to Cadence and do not introduce new EVM state — they reduce it. Alternatively, introduce a dedicated `emergencyWithdraw()` function that bypasses the pause check and allows users to recover their FLOW tokens without executing any EVM logic (e.g., by directly crediting the Cadence vault from the bridge escrow). [1](#0-0) [3](#0-2) 

### Proof of Concept

1. Alice deposits 100 FLOW into her COA via `CadenceOwnedAccount.deposit()`.
2. The Governance Committee executes a multi-sig transaction that sets `/storage/evmOperationsPaused` to `true`.
3. Alice submits a transaction calling `coa.withdraw(balance: bal)` to recover her 100 FLOW.
4. The `pre { !EVM.isPaused() }` check evaluates to `false`, causing the transaction to panic with `"EVM operations are temporarily paused"`.
5. Alice's 100 FLOW remains locked in EVM with no available exit path until the Governance Committee unpauses — with no defined timeline.

This behavior is confirmed by the existing test suite, which explicitly asserts that `CadenceOwnedAccount.withdraw` **must fail** when EVM is paused, treating the fund-trapping as correct behavior rather than a design flaw. [5](#0-4)

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

**File:** fvm/evm/stdlib/contract.cdc (L755-802)
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
```

**File:** fvm/evm/stdlib/contract.cdc (L1223-1236)
```text
    /// Returns whether EVM transactions have been paused, either for
    /// maintenance or any situation that requires special governance
    /// handling.
    ///
    /// Only the Governance Committee can pause the EVM transactions, with
    /// a multi-sig Cadence transaction. The EVM enters a read-only mode,
    /// where all EVM state is available for reading, but no state updates
    /// are executed.
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
