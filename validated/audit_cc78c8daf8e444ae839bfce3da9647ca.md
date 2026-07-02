### Title
EVM Pause Blocks Asset Withdrawal from COA, Freezing User Funds - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

When the Flow EVM is paused by governance, the `EVM.isPaused()` guard is applied uniformly to all state-mutating operations — including `CadenceOwnedAccount.withdraw()`, `withdrawNFT()`, and `withdrawTokens()`. This prevents users from recovering their own assets (FLOW tokens, NFTs, fungible tokens) from the EVM environment back to Cadence for the entire duration of the pause, directly mirroring the Isomorph H-6 pattern where a pause flag blocked loan closure and liquidation.

---

### Finding Description

The `EVM.isPaused()` function reads a boolean stored at `/storage/evmOperationsPaused` on the EVM contract account:

```cadence
access(all)
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
``` [1](#0-0) 

When this flag is `true`, the following asset-recovery operations on `CadenceOwnedAccount` all revert:

**`withdraw` (FLOW tokens from COA → Cadence):**
```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [2](#0-1) 

**`withdrawNFT` (NFT from EVM → Cadence):**
```cadence
access(Owner | Bridge)
fun withdrawNFT(...): @{NonFungibleToken.NFT} {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [3](#0-2) 

**`withdrawTokens` (fungible tokens from EVM → Cadence):**
```cadence
access(Owner | Bridge)
fun withdrawTokens(...): @{FungibleToken.Vault} {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [4](#0-3) 

The same guard also blocks `EVM.run()`, `EVM.batchRun()`, `createCadenceOwnedAccount()`, `deploy()`, `depositNFT()`, and `depositTokens()`. [5](#0-4) [6](#0-5) 

The coupling is exact: a single boolean flag simultaneously blocks both new activity (new EVM transactions, new COA creation) **and** existing-position recovery (withdrawals of already-escrowed assets). This is structurally identical to the Isomorph bug where `collateralValid[_collateralAddress] = false` simultaneously blocked new loans and existing loan closure.

The pause is activated by a governance multi-sig transaction that stores `true` at `/storage/evmOperationsPaused` on the EVM contract account: [7](#0-6) 

---

### Impact Explanation

Any user who has FLOW tokens, NFTs, or fungible tokens escrowed in their `CadenceOwnedAccount` (COA) in the Flow EVM environment is unable to withdraw those assets back to Cadence for the entire duration of the pause. The assets are not lost permanently, but they are completely inaccessible — the user cannot call `withdraw`, `withdrawNFT`, or `withdrawTokens` without the transaction reverting. This constitutes a temporary but total freeze of user funds held in COA balances, directly analogous to the Isomorph scenario where users could not close loans to recover their collateral.

---

### Likelihood Explanation

The EVM pause is a documented governance mechanism intended for maintenance or emergency situations. [8](#0-7) 

The `PauseBridgeTransaction` helper in `fvm/blueprints/bridge.go` shows this is an operational tool that governance is expected to use. [7](#0-6) 

Any legitimate governance pause — even a brief maintenance window — triggers the fund-freeze for all COA holders. The likelihood of a pause occurring is non-trivial given it is an explicitly supported governance action.

---

### Recommendation

Decouple the `isPaused()` guard for asset-recovery operations from the general EVM pause, mirroring the Isomorph fix exactly. Specifically:

- Remove the `!EVM.isPaused()` pre-condition from `CadenceOwnedAccount.withdraw()`, `withdrawNFT()`, and `withdrawTokens()`.
- Retain the guard on all state-creating or state-advancing operations: `EVM.run()`, `EVM.batchRun()`, `deploy()`, `createCadenceOwnedAccount()`, `depositNFT()`, `depositTokens()`, and `call()`/`callWithSigAndArgs()`.

This ensures that a paused EVM still blocks new activity while allowing users to recover assets they already hold in their COA.

---

### Proof of Concept

1. Governance stores `true` at `/storage/evmOperationsPaused` on the EVM contract account (via the `PauseBridgeTransaction` helper or equivalent multi-sig transaction).
2. A user who previously deposited 10 FLOW into their COA submits a Cadence transaction calling `coa.withdraw(balance: EVM.Balance(attoflow: 10_000_000_000_000_000_000))`.
3. The transaction reverts with `"EVM operations are temporarily paused"` at the `pre` condition in `withdraw()`. [9](#0-8) 
4. The user's 10 FLOW remain locked in the COA EVM address with no recovery path until governance unpauses EVM.
5. The same applies to NFTs and fungible tokens via `withdrawNFT()` and `withdrawTokens()`. [10](#0-9) [11](#0-10) 

This is confirmed by the existing test suite, which explicitly verifies that `CadenceOwnedAccount.withdraw` reverts with `"EVM operations are temporarily paused"` when the pause flag is set: [12](#0-11)

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

**File:** fvm/evm/stdlib/contract.cdc (L828-831)
```text
    fun run(tx: [UInt8], coinbase: EVMAddress): Result {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L918-921)
```text
    fun batchRun(txs: [[UInt8]], coinbase: EVMAddress): [Result] {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
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

**File:** fvm/blueprints/bridge.go (L107-122)
```go
// PauseBridgeTransaction returns the transaction body for the transaction
// to pause or unpause the VM bridge
func PauseBridgeTransaction(
	env templates.Environment,
	bridgeEnv bridge.Environment,
	service flow.Address,
	pause bool,
) (*flow.TransactionBody, error) {
	txScript, _ := bridge.GetCadenceTransactionCode("cadence/transactions/bridge/admin/pause/update_bridge_pause_status.cdc", bridgeEnv, env)
	return flow.NewTransactionBodyBuilder().
		SetScript(txScript).
		AddArgument(jsoncdc.MustEncode(cadence.Bool(pause))).
		AddAuthorizer(service).
		SetPayer(service).
		Build()
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
