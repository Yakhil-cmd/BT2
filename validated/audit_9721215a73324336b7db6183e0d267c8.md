### Title
Sub-minimum attoFlow Remainder Permanently Stranded in `CadenceOwnedAccount` After EVM Gas Deduction — (`fvm/evm/impl/impl.go`, `fvm/evm/types/balance.go`, `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`CadenceOwnedAccount.withdraw()` enforces a hard minimum of `1e10 attoFlow` on every withdrawal. EVM-native operations (gas fee deductions, direct EVM transfers of arbitrary wei amounts) can reduce a COA's balance to a value between `1` and `9,999,999,999 attoFlow`. That residual balance can never be bridged back to Cadence: the only withdrawal path panics unconditionally on any amount below the minimum, permanently stranding the funds on the EVM side.

---

### Finding Description

`newInternalEVMTypeWithdrawFunction` in `fvm/evm/impl/impl.go` calls `types.AttoFlowBalanceIsValidForFlowVault` before executing any withdrawal:

```go
// check balance is not prone to rounding error
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}
``` [1](#0-0) 

`AttoFlowBalanceIsValidForFlowVault` returns `false` for any value strictly less than `UFixToAttoConversionMultiplier` (= `10^10`):

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
``` [2](#0-1) 

The same guard is present in the emulator-level `withdrawFrom`: [3](#0-2) 

The Cadence contract documents this as a known constraint but provides no escape hatch:

```cadence
/// Note that amounts smaller than 1e10 attoFlow can't be withdrawn …
/// Amounts smaller than 1e10 attoFlow, will cause the function to panic
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    …
    let vault <- InternalEVM.withdraw(from: self.addressBytes, amount: balance.attoflow) …
``` [4](#0-3) 

EVM-native operations operate at full `attoFlow` (18-decimal) precision and are not constrained to multiples of `1e10`. Specifically:

- **EVM gas fees** are deducted as `gasUsed × gasPrice` in attoFlow. A COA holding exactly `1e10 attoFlow` that pays even `1 attoFlow` in gas is left with `9,999,999,999 attoFlow` — below the minimum.
- **Direct EVM transfers**: any EVM EOA or contract can send an arbitrary wei amount (e.g., `1 attoFlow`) to a COA's EVM address, pushing its balance below `1e10`.

Once the balance falls below `1e10 attoFlow`, the only Cadence-side withdrawal path (`CadenceOwnedAccount.withdraw`) panics unconditionally. There is no "withdraw all" or "sweep dust" path. The funds remain locked in the EVM state and cannot be represented in a `FlowToken.Vault`.

---

### Impact Explanation

Any COA balance in the range `[1, 9_999_999_999]` attoFlow is permanently unrecoverable via the Cadence bridge. The maximum per-COA loss is `9,999,999,999 attoFlow ≈ 0.00000001 FLOW`. While small per account, the loss is **permanent and irreversible**: the user cannot bridge those tokens back to Cadence regardless of how many transactions they submit. This is a direct cross-VM asset loss caused by the minimum-amount check interacting with EVM's higher-precision balance arithmetic.

---

### Likelihood Explanation

The scenario is reachable by any unprivileged user who:
1. Creates a COA and deposits FLOW.
2. Executes any EVM transaction (call, deploy) that deducts gas fees, leaving a sub-`1e10` attoFlow remainder.

This is a normal operational path. No special privileges, leaked keys, or compromised nodes are required. The existing test suite explicitly confirms that amounts below `1e10 attoFlow` are rejected: [5](#0-4) 

---

### Recommendation

Add a "withdraw full balance" path that bypasses the minimum check when the requested amount equals the COA's entire EVM balance, or introduce a `sweepDust()` function that rounds sub-`1e10` attoFlow remainders to zero and destroys them (burning the dust) rather than leaving them permanently locked. Alternatively, allow `withdraw` to silently return an empty vault when the requested amount is non-zero but below `1e10 attoFlow`, consistent with the existing zero-balance fast path: [6](#0-5) 

---

### Proof of Concept

1. Alice creates a COA and deposits exactly `0.00000001 FLOW` (= `1e10 attoFlow`).
2. Alice calls `cadenceOwnedAccount.call(...)` targeting any EVM contract; the transaction consumes `1 attoFlow` in gas fees.
3. Alice's COA EVM balance is now `9,999,999,999 attoFlow`.
4. Alice attempts: `cadenceOwnedAccount.withdraw(balance: EVM.Balance(attoflow: 9999999999))`.
5. `newInternalEVMTypeWithdrawFunction` calls `AttoFlowBalanceIsValidForFlowVault(9_999_999_999)` → `false` → `panic(ErrWithdrawBalanceRounding)`.
6. The transaction reverts. Alice's `9,999,999,999 attoFlow` is permanently stranded in the EVM state with no recovery path.

### Citations

**File:** fvm/evm/impl/impl.go (L778-781)
```go
			// check balance is not prone to rounding error
			if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
				panic(types.ErrWithdrawBalanceRounding)
			}
```

**File:** fvm/evm/types/balance.go (L105-107)
```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
	return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
```

**File:** fvm/evm/emulator/emulator.go (L440-447)
```go
	// check balance is not prone to rounding error
	if !types.AttoFlowBalanceIsValidForFlowVault(call.Value) {
		return types.NewInvalidResult(
			call.Type,
			call.Hash(),
			types.ErrWithdrawBalanceRounding,
		), nil
	}
```

**File:** fvm/evm/stdlib/contract.cdc (L574-606)
```text
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
```

**File:** fvm/evm/evm_test.go (L2303-2336)
```go
						// since 1e10 attoFlow is the minimum withdrawable amount,
						// verify any amount below 1e10 can not be withdrawn.
						let bal = EVM.Balance(attoflow: 9999999999)
						let vault2 <- cadenceOwnedAccount.withdraw(balance: bal)
						let balance = vault2.balance
						destroy cadenceOwnedAccount
						destroy vault2
					}
				}
				`,
					sc.EVMContract.Address.HexWithPrefix(),
					sc.FlowToken.Address.HexWithPrefix(),
				)

				txBody, err := flow.NewTransactionBodyBuilder().
					SetScript(code).
					SetPayer(sc.FlowServiceAccount.Address).
					AddAuthorizer(sc.FlowServiceAccount.Address).
					Build()
				require.NoError(t, err)
				tx := fvm.Transaction(txBody, 0)

				_, output, err := vm.Run(
					ctx,
					tx,
					snapshot,
				)
				require.NoError(t, err)
				require.Error(t, output.Err)
				require.ErrorContains(
					t,
					output.Err,
					types.ErrWithdrawBalanceRounding.Error(),
				)
```
