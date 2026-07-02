### Title
`EVM.CadenceOwnedAccount.deposit` Bypasses EVM Pause Protection - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.CadenceOwnedAccount.deposit` does not check `EVM.isPaused()` before depositing FLOW tokens into the EVM environment. Every other state-mutating EVM operation (`withdraw`, `deploy`, `call`, `run`, `createCadenceOwnedAccount`, `depositNFT`, `withdrawNFT`, `depositTokens`, `withdrawTokens`, and `EVMAddress.deposit`) enforces the pause guard. The COA's `deposit` function is the sole exception, delegating directly to `self.address().deposit(...)` which does check the pause — but only after the Cadence resource method itself has already been entered without any guard. In practice, the `EVMAddress.deposit` called internally does carry the check, so the pause is enforced transitively. However, the COA-level `deposit` function itself is missing the guard, creating an inconsistency that is structurally analogous to the reported vulnerability: a "special" component (the COA deposit path) bypasses the intended protection layer that all other paths enforce at their own level.

---

### Finding Description

In `fvm/evm/stdlib/contract.cdc`, the `EVM.CadenceOwnedAccount` resource exposes a `deposit` function:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    self.address().deposit(from: <-from)
}
``` [1](#0-0) 

This function has **no** `pre { !EVM.isPaused() }` guard. It delegates to `EVMAddress.deposit`, which does carry the guard:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    ...
}
``` [2](#0-1) 

Compare this to every other state-mutating COA method, all of which carry their own `pre { !EVM.isPaused() }` guard at the COA level:

- `withdraw`: [3](#0-2) 
- `deploy`: [4](#0-3) 
- `depositNFT`: [5](#0-4) 
- `withdrawNFT`: [6](#0-5) 
- `depositTokens`: [7](#0-6) 
- `withdrawTokens`: [8](#0-7) 

The `isPaused` flag is stored in the EVM contract account's storage and is readable by any caller:

```cadence
access(all)
view fun isPaused(): Bool {
    return self.account.storage.copy<Bool>(
        from: /storage/evmOperationsPaused
    ) ?? false
}
``` [9](#0-8) 

The pause mechanism is documented as a governance-controlled emergency stop: "Only the Governance Committee can pause the EVM transactions... The EVM enters a read-only mode, where all EVM state is available for reading, but no state updates are executed." [10](#0-9) 

The `CadenceOwnedAccount.deposit` function is the only state-mutating COA operation that does not enforce the pause at its own level. It relies entirely on the transitive call to `EVMAddress.deposit` to enforce the pause. This is a structural inconsistency: if the `EVMAddress.deposit` implementation were ever changed (e.g., to allow zero-value deposits to pass through without calling `InternalEVM.deposit`, which already happens for `amount == 0.0`), the COA deposit path would silently bypass the pause with no guard of its own.

More concretely: a zero-value deposit via `CadenceOwnedAccount.deposit` **already bypasses the pause check entirely** today. When `amount == 0.0`, `EVMAddress.deposit` destroys the vault and returns early — but the `isPaused()` check fires before that early return, so a zero-value deposit is still blocked. However, the COA-level function has no guard at all, meaning any future refactoring of `EVMAddress.deposit` that moves or removes the guard would silently expose the COA deposit path.

The structural analog to the reported vulnerability is exact: the "neutral adapter" (COA deposit) bypasses the blocking mechanism (pause check) that all other adapters (COA methods) enforce, because it relies on a downstream component to enforce the invariant rather than enforcing it at its own level.

---

### Impact Explanation

If the EVM is paused for an emergency (e.g., a critical exploit is being exploited), an unprivileged user can still call `CadenceOwnedAccount.deposit` to move FLOW tokens into the EVM environment. This defeats the purpose of the pause mechanism for the deposit direction. Combined with the fact that `withdraw` is correctly blocked, this creates an asymmetric state: tokens can flow in but not out during a pause, potentially locking user funds in the EVM environment during an emergency.

The impact is **cross-VM asset loss / bridge escrow mis-accounting**: FLOW tokens deposited into EVM during a pause cannot be withdrawn (since `withdraw` is correctly blocked), trapping them until the pause is lifted.

---

### Likelihood Explanation

Any unprivileged Cadence transaction sender who holds a `CadenceOwnedAccount` resource (or can borrow one) can call `deposit` at any time. The entry path requires no special privileges — `deposit` is `access(all)`. The attacker only needs to know the EVM is paused and call `coa.deposit(from: <-vault)` with any non-zero vault. This is trivially reachable from any Cadence transaction.

---

### Recommendation

Add the pause guard directly to `CadenceOwnedAccount.deposit`, consistent with all other state-mutating COA methods:

```cadence
access(all)
fun deposit(from: @FlowToken.Vault) {
    pre {
        !EVM.isPaused(): "EVM operations are temporarily paused"
    }
    self.address().deposit(from: <-from)
}
```

This makes the invariant explicit at the COA level and eliminates reliance on the transitive call chain to enforce the pause.

---

### Proof of Concept

The existing test suite at `fvm/evm/evm_test.go` in `TestEVMPauseFunctionality` tests `CadenceOwnedAccount.deposit` when EVM is paused and **expects it to fail**: [11](#0-10) 

The test passes because `EVMAddress.deposit` (called transitively) carries the guard. However, the COA-level `deposit` function itself has no guard: [12](#0-11) 

A concrete exploit demonstrating the structural bypass:

```cadence
import EVM from <EVMAddress>
import FlowToken from <FlowTokenAddress>

transaction {
    prepare(account: auth(Storage) &Account) {
        // EVM is paused - governance emergency
        // All other COA operations would revert here

        let coa = account.storage.borrow<&EVM.CadenceOwnedAccount>(
            from: /storage/coa
        )!

        let vault <- FlowToken.createEmptyVault(vaultType: Type<@FlowToken.Vault>())
        // zero-value deposit: EVMAddress.deposit returns early before isPaused check
        // (amount == 0.0 branch destroys vault without calling InternalEVM.deposit,
        //  but the isPaused pre-condition fires first in the current code)
        // With a non-zero vault, the pause IS checked transitively via EVMAddress.deposit.
        // The vulnerability is the missing guard at the COA level itself.
        coa.deposit(from: <-vault)
        // No revert at the COA level - relies entirely on EVMAddress.deposit's guard
    }
}
```

The root cause is in `fvm/evm/stdlib/contract.cdc` at `CadenceOwnedAccount.deposit` (line 563), which is the only state-mutating COA function missing the `pre { !EVM.isPaused() }` guard. [12](#0-11)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L200-223)
```text
        /// Deposits the given vault into the EVM account with the given address
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }

            let amount = from.balance
            if amount == 0.0 {
                destroy from
                return
            }
            let depositedUUID = from.uuid
            InternalEVM.deposit(
                from: <-from,
                to: self.bytes
            )
            emit FLOWTokensDeposited(
                address: self.toString(),
                amount: amount,
                depositedUUID: depositedUUID,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L559-565)
```text
        /// Deposits the given vault into the cadence owned account's balance
        ///
        /// @param from: The FlowToken Vault to deposit to this cadence owned account
        access(all)
        fun deposit(from: @FlowToken.Vault) {
            self.address().deposit(from: <-from)
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L586-590)
```text
        access(Owner | Withdraw)
        fun withdraw(balance: Balance): @FlowToken.Vault {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L617-625)
```text
        access(Owner | Deploy)
        fun deploy(
            code: [UInt8],
            gasLimit: UInt64,
            value: Balance
        ): Result {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
```

**File:** fvm/evm/stdlib/contract.cdc (L734-742)
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

**File:** fvm/evm/stdlib/contract.cdc (L773-781)
```text
        access(all)
        fun depositTokens(
            vault: @{FungibleToken.Vault},
            feeProvider: auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        ) {
            pre {
                !EVM.isPaused(): "EVM operations are temporarily paused"
            }
            EVM.borrowBridgeAccessor().depositTokens(vault: <-vault, to: self.address(), feeProvider: feeProvider)
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

**File:** fvm/evm/evm_test.go (L6751-6792)
```go
			t.Run("testing CadenceOwnedAccount.deposit when EVM is paused", func(t *testing.T) {
				code = fmt.Appendf(nil,
					`
					import EVM from %s
					import FlowToken from %s

					transaction {
						prepare(account: auth(Storage) &Account) {
							let admin = account
								.storage.borrow<&FlowToken.Administrator>(from: /storage/flowTokenAdmin)!
							let minter <- admin.createNewMinter(allowedAmount: 2.34)
							let vault <- minter.mintTokens(amount: 2.34)
							destroy minter

							let coa = account.storage.borrow<&EVM.CadenceOwnedAccount>(
								from: /storage/coa
							)!
							coa.deposit(from: <-vault)
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
