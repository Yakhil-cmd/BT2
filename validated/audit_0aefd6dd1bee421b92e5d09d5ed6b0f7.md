### Title
Missing Emergency Withdrawal Path in `EVM.CadenceOwnedAccount` Locks User FLOW Tokens When EVM Is Paused - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `EVM` contract implements a governance-controlled pause mechanism (`isPaused()`) that blocks **all** state-mutating operations on `CadenceOwnedAccount`, including the only user-facing withdrawal path (`withdraw()`). When EVM is paused, there is no emergency withdrawal function that bypasses the pause guard, meaning all FLOW tokens held in COA EVM addresses are permanently inaccessible for the duration of the pause with no recovery path.

---

### Finding Description

`EVM.isPaused()` reads a `Bool` from `/storage/evmOperationsPaused` in the EVM contract account's storage:

```cadence
access(all)
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
``` [1](#0-0) 

When this flag is set to `true` by governance, every state-mutating function on `CadenceOwnedAccount` is blocked by a `pre` condition:

- `CadenceOwnedAccount.withdraw()` — the only path to move FLOW tokens from EVM back to Cadence:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [2](#0-1) 

- `CadenceOwnedAccount.withdrawNFT()` — the only path to bridge NFTs back from EVM: [3](#0-2) 

- `CadenceOwnedAccount.withdrawTokens()` — the only path to bridge fungible tokens back from EVM: [4](#0-3) 

- `EVM.run()`, `EVM.batchRun()`, `CadenceOwnedAccount.deploy()`, `CadenceOwnedAccount.call()`, `depositNFT()`, `depositTokens()`, and `EVMAddress.deposit()` are all similarly blocked. [5](#0-4) 

There is **no** emergency withdrawal function anywhere in the contract that bypasses the `isPaused()` guard. The contract has no analog to MasterChef's `emergencyWithdraw()` — a function that skips reward accounting and simply returns the principal to the user.

The pause is activated by any transaction that saves `true` to `/storage/evmOperationsPaused` in the EVM contract account's storage. The test confirms this mechanism is real and fully operational: [6](#0-5) 

---

### Impact Explanation

All FLOW tokens held in `CadenceOwnedAccount` EVM addresses are inaccessible while EVM is paused. The `CadenceOwnedAccount.withdraw()` function is the **only** mechanism for a COA owner to move FLOW tokens from the EVM environment back to Cadence. With no emergency withdrawal path, users cannot recover their principal. Bridged NFTs and fungible tokens escrowed on the Cadence side of the VM bridge are similarly unrecoverable via `withdrawNFT()` and `withdrawTokens()`. This constitutes a cross-VM asset loss for the entire duration of the pause, and permanently if the pause is never lifted.

---

### Likelihood Explanation

The EVM pause mechanism is a documented, production-ready governance feature explicitly described in the contract comments as usable "for maintenance or any situation that requires special governance handling." The governance committee can activate it via a multi-sig Cadence transaction at any time. The pause is designed to be used in real emergencies — precisely the scenario where users most urgently need to recover their funds. The likelihood of the pause being activated at some point during the protocol's lifetime is non-trivial.

---

### Recommendation

Add an emergency withdrawal function to `CadenceOwnedAccount` that bypasses the `isPaused()` guard and allows users to recover their FLOW token principal without requiring EVM state execution. This mirrors the MasterChef `emergencyWithdraw()` pattern: skip all reward/bridge accounting and simply return the user's principal. For example:

```cadence
access(Owner | Withdraw)
fun emergencyWithdraw(balance: Balance): @FlowToken.Vault {
    // No isPaused() check — emergency exit always available
    let vault <- InternalEVM.withdraw(
        from: self.addressBytes,
        amount: balance.attoflow
    ) as! @FlowToken.Vault
    return <-vault
}
```

Similarly, `withdrawNFT()` and `withdrawTokens()` should have emergency variants that bypass the pause guard.

---

### Proof of Concept

1. Governance saves `true` to `/storage/evmOperationsPaused` in the EVM contract account (as shown in `TestEVMPauseFunctionality`).
2. A user with FLOW tokens in their COA submits a transaction calling `coa.withdraw(balance: bal)`.
3. The `pre { !EVM.isPaused() }` condition evaluates to `false`, reverting the transaction with `"EVM operations are temporarily paused"`. [7](#0-6) 

4. The user has no alternative Cadence-level path to recover their FLOW tokens from the COA. The `InternalEVM.withdraw` host function is only exposed through `CadenceOwnedAccount.withdraw()`, which is blocked. The funds remain locked in the EVM state for the entire duration of the pause.

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

**File:** fvm/evm/stdlib/contract.cdc (L828-836)
```text
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        return InternalEVM.run(
            tx: tx,
            coinbase: coinbase.bytes
        ) as! Result
    }
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

**File:** fvm/evm/evm_test.go (L6382-6385)
```go
			prepare(account: auth(Storage) &Account) {
				account.storage.save(<- EVM.createCadenceOwnedAccount(), to: /storage/coa)
				account.storage.save(true, to: /storage/evmOperationsPaused)
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
