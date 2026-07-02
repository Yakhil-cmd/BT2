### Title
EVM Pause Guard Blocks COA Withdrawals, Trapping User Funds During Emergency - (`File: fvm/evm/stdlib/contract.cdc`)

### Summary

When the EVM is paused by the Governance Committee, the `!EVM.isPaused()` pre-condition applied to `CadenceOwnedAccount.withdraw`, `CadenceOwnedAccount.withdrawNFT`, and `CadenceOwnedAccount.withdrawTokens` prevents users from recovering their FLOW tokens, NFTs, and fungible tokens from their Cadence-Owned Accounts (COAs). This is the direct analog of the reported vulnerability: a blanket "disabled" guard that should only block inbound operations (deposits, calls, deployments) also incorrectly blocks outbound withdrawal operations that users need to protect their assets.

### Finding Description

The EVM contract in `fvm/evm/stdlib/contract.cdc` implements a governance-controlled pause mechanism via `EVM.isPaused()`, which reads a boolean from `/storage/evmOperationsPaused`. The contract documentation describes the pause as putting EVM into "read-only mode, where all EVM state is available for reading, but no state updates are executed."

The `!EVM.isPaused()` guard is applied uniformly to all state-mutating operations, including:

- `EVMAddress.deposit` (line 203–205) — blocks depositing FLOW into EVM
- `CadenceOwnedAccount.withdraw` (line 588–590) — blocks withdrawing FLOW from COA back to Cadence
- `CadenceOwnedAccount.withdrawNFT` (line 761–763) — blocks bridging NFTs from EVM back to Cadence
- `CadenceOwnedAccount.withdrawTokens` (line 793–795) — blocks bridging fungible tokens from EVM back to Cadence
- `CadenceOwnedAccount.depositNFT` (line 739–741), `depositTokens` (line 778–780), `deploy` (line 623–625), `call` (line 643–645), `EVM.run` (line 829–831), `EVM.batchRun` (line 919–921), `EVM.createCadenceOwnedAccount` (line 808–810)

Blocking deposits, calls, and deployments during a pause is correct — these add new state or execute arbitrary logic. However, blocking `withdraw`, `withdrawNFT`, and `withdrawTokens` is incorrect: these operations move assets **out** of EVM back to Cadence, which is precisely what users need to do when EVM is paused due to an emergency or exploit.

The `CadenceOwnedAccount.deposit` function (line 563–565) delegates to `EVMAddress.deposit`, which carries the guard. This means both directions of the bridge are blocked symmetrically, but only the inbound direction (deposit) is appropriate to block.

### Impact Explanation

When EVM is paused — the scenario where user funds are most at risk — COA owners cannot call `coa.withdraw(balance: bal)`, `coa.withdrawNFT(...)`, or `coa.withdrawTokens(...)`. Their FLOW tokens, NFTs, and fungible tokens are locked inside the EVM environment until the Governance Committee lifts the pause. If the pause was triggered because of an exploit or critical bug in EVM, users have no recourse to exit their positions and protect their assets. This is a direct loss-of-access-to-funds scenario during an emergency.

### Likelihood Explanation

The EVM pause is a governance-controlled emergency mechanism. It is triggered precisely when there is a problem with EVM — the exact scenario where users most urgently need to withdraw. Any unprivileged user who holds a COA with a non-zero balance is affected. The entry path is a standard Cadence transaction calling `coa.withdraw(...)`, which any COA owner can submit. No special privileges are required to be impacted.

### Recommendation

Remove the `!EVM.isPaused()` pre-condition from `CadenceOwnedAccount.withdraw`, `CadenceOwnedAccount.withdrawNFT`, and `CadenceOwnedAccount.withdrawTokens`. Withdrawals move assets from EVM back to Cadence and do not execute arbitrary EVM logic; they should remain available as an emergency exit path regardless of pause state. The guard should remain on all inbound and execution operations (deposit, call, deploy, run, batchRun, createCadenceOwnedAccount).

### Proof of Concept

The `CadenceOwnedAccount.withdraw` function has the guard:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"  // line 589
    }
    ...
}
``` [1](#0-0) 

Similarly for `withdrawNFT`:

```cadence
access(Owner | Bridge)
fun withdrawNFT(...): @{NonFungibleToken.NFT} {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"  // line 762
    }
    ...
}
``` [2](#0-1) 

And `withdrawTokens`:

```cadence
access(Owner | Bridge)
fun withdrawTokens(...): @{FungibleToken.Vault} {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"  // line 794
    }
    ...
}
``` [3](#0-2) 

The `isPaused()` function reads from storage:

```cadence
access(all)
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
``` [4](#0-3) 

The existing integration test at `fvm/evm/evm_test.go` confirms that `coa.withdraw(balance: bal)` fails with `"EVM operations are temporarily paused"` when EVM is paused, demonstrating the issue is present and exercised: [5](#0-4) 

A user with a COA holding funds submits:
```cadence
let coa = account.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(from: /storage/coa)!
let vault <- coa.withdraw(balance: bal)  // panics: "EVM operations are temporarily paused"
```

Their funds remain locked in EVM with no exit path until governance lifts the pause.

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

**File:** fvm/evm/stdlib/contract.cdc (L1232-1236)
```text
    view fun isPaused(): Bool {
        return self.account.storage.copy<Bool>(
            from: /storage/evmOperationsPaused
        ) ?? false
    }
```

**File:** fvm/evm/evm_test.go (L6794-6831)
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
```
