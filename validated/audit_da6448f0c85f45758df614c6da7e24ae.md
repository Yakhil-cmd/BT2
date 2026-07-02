### Title
Users Cannot Withdraw Assets from `CadenceOwnedAccount` When EVM Is Paused - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
The `CadenceOwnedAccount.withdraw`, `withdrawNFT`, and `withdrawTokens` functions in the EVM contract enforce an `isPaused()` guard that prevents users from retrieving their own FLOW tokens, bridged NFTs, and bridged fungible tokens from their Cadence Owned Accounts (COAs) whenever the EVM is paused by the Governance Committee. Blocking withdrawals during a pause is a critical design flaw: users should always be able to exit their positions and reclaim their assets, even in a degraded or emergency state.

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, the `CadenceOwnedAccount.withdraw` function contains the following precondition:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [1](#0-0) 

The same guard is applied to `withdrawNFT` and `withdrawTokens`: [2](#0-1) [3](#0-2) 

`EVM.isPaused()` reads a boolean flag from `/storage/evmOperationsPaused` on the EVM contract account. The Governance Committee sets this flag via a multi-sig Cadence transaction to enter "read-only mode": [4](#0-3) 

When `isPaused` is `true`, any Cadence transaction calling `coa.withdraw(...)`, `coa.withdrawNFT(...)`, or `coa.withdrawTokens(...)` panics with `"EVM operations are temporarily paused"`, as confirmed by the integration test: [5](#0-4) 

### Impact Explanation

Users who hold FLOW tokens, bridged NFTs, or bridged fungible tokens inside their COA are completely unable to retrieve those assets while EVM is paused. A COA is the only mechanism for a Cadence account to own and control an EVM address — there is no alternative exit path. Assets are effectively frozen on-chain for the duration of the pause. This is a direct blocking of user access to their own on-chain assets, not merely a degraded service. Users who need to repay Cadence-side loans, fulfill obligations, or respond to market conditions are unable to do so.

**Impact: Medium** — Users lose access to their own on-chain assets (FLOW, NFTs, fungible tokens) for the duration of the pause. The assets are not permanently lost, but the inability to exit is a material harm, especially in time-sensitive financial scenarios.

### Likelihood Explanation

**Likelihood: Medium** — The EVM pause is a governance-controlled action intended for maintenance or emergency situations. The contract documentation explicitly states it is for "maintenance or any situation that requires special governance handling." While pauses are not expected to be frequent, they are a designed and reachable code path. Any pause, however brief, triggers this vulnerability for all COA holders. [6](#0-5) 

### Recommendation

Remove the `!EVM.isPaused()` precondition from `CadenceOwnedAccount.withdraw`, `withdrawNFT`, and `withdrawTokens`. Withdrawals move assets from EVM back to Cadence and represent a user reclaiming their own funds — they should remain available even in paused/read-only mode. The pause guard is appropriate for state-mutating operations that interact with EVM execution (`deposit`, `call`, `deploy`, `run`, `batchRun`), but not for asset-exit paths.

```cadence
// Remove from withdraw:
pre {
    !EVM.isPaused(): "EVM operations are temporarily paused"  // <-- remove
}

// Remove from withdrawNFT:
pre {
    !EVM.isPaused(): "EVM operations are temporarily paused"  // <-- remove
}

// Remove from withdrawTokens:
pre {
    !EVM.isPaused(): "EVM operations are temporarily paused"  // <-- remove
}
```

### Proof of Concept

1. A user creates a COA and deposits FLOW tokens into it.
2. The Governance Committee pauses EVM by setting `/storage/evmOperationsPaused` to `true`.
3. The user submits a Cadence transaction:
   ```cadence
   import EVM from <EVMContractAddress>
   transaction {
       prepare(account: auth(Storage) &Account) {
           let bal = EVM.Balance(attoflow: 0)
           bal.setFLOW(flow: 1.0)
           let coa = account.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(
               from: /storage/coa
           )!
           let vault <- coa.withdraw(balance: bal)  // PANICS: "EVM operations are temporarily paused"
           destroy <- vault
       }
   }
   ```
4. The transaction fails. The user's FLOW tokens remain locked in the COA with no alternative exit path until the Governance Committee unpauses EVM.

The test `TestEVMPauseFunctionality / testing CadenceOwnedAccount.withdraw when EVM is paused` in `fvm/evm/evm_test.go` confirms this behavior is the current enforced design: [5](#0-4)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L586-590)
```text
        access(Owner | Withdraw)
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
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
