### Title
Sub-Threshold FLOW Tokens Permanently Trapped in EVM CadenceOwnedAccount with No Retrieval Mechanism - (File: fvm/evm/stdlib/contract.cdc)

---

### Summary

The `EVM.CadenceOwnedAccount.withdraw()` function enforces a hard minimum of 1e10 attoFlow (0.00000001 FLOW) per withdrawal due to the UFix64 precision gap between EVM (18 decimal places) and Cadence `FlowToken.Vault` (8 decimal places). Any FLOW balance below this threshold that accumulates in a COA's EVM address — through EVM gas fee remainders, sub-threshold EVM transfers, or truncated withdrawal remainders — is permanently trapped with no retrieval path. There is no `withdrawAll()`, sweep, or burn-to-recover function anywhere in the contract.

---

### Finding Description

When FLOW tokens are deposited into a `CadenceOwnedAccount` (COA) via `deposit()`, they enter the EVM environment as an attoFlow balance (1 FLOW = 1e18 attoFlow). The only path back to Cadence is `withdraw(balance: Balance)`, which calls `InternalEVM.withdraw()`.

Inside `newInternalEVMTypeWithdrawFunction` in `fvm/evm/impl/impl.go`, the very first validation is:

```go
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}
```

`AttoFlowBalanceIsValidForFlowVault` in `fvm/evm/types/balance.go` returns `false` for any amount strictly less than `UFixToAttoConversionMultiplier` (= 1e10):

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
```

So any call to `withdraw()` with an amount in the range `[1, 9_999_999_999]` attoFlow panics with `ErrWithdrawBalanceRounding`. Calling `withdraw()` with zero returns an empty vault (no-op). There is no other function on `CadenceOwnedAccount` or `EVMAddress` that moves sub-threshold FLOW back to Cadence.

Sub-threshold balances accumulate through normal EVM operations:

1. **EVM gas fee remainders**: A COA that executes EVM calls pays gas fees deducted from its EVM balance. If the post-fee balance has a sub-1e10 attoFlow component, that component is irrecoverable. For example, a COA with `10_000_000_001` attoFlow that pays `21_000` attoFlow in gas is left with `9_999_979_001` attoFlow — entirely below the withdrawal threshold.

2. **Sub-threshold EVM transfers**: Any EVM EOA or Solidity contract can `transfer()` a sub-threshold amount (e.g., 1 wei = 1 attoFlow) to a COA's EVM address. The COA owner cannot withdraw it.

3. **Truncated withdrawal remainders**: The `withdraw()` function truncates the requested amount to the nearest 1e10 attoFlow boundary (as shown in the `test coa withdraw with remainder truncation` test). If the COA's total balance is not a multiple of 1e10, the remainder after all possible withdrawals is permanently stranded.

The `contract.cdc` `withdraw()` function explicitly documents this as a known limitation but provides no escape hatch:

> "Note that amounts smaller than 1e10 attoFlow can't be withdrawn... Amounts smaller than 1e10 attoFlow, will cause the function to panic."

---

### Impact Explanation

**Cross-VM asset loss**: FLOW tokens deposited from Cadence into the EVM environment via a COA can become permanently irrecoverable if the EVM-side balance falls below 1e10 attoFlow. The tokens exist in the EVM state (they are not burned — the EVM total supply is not reduced), but they cannot be bridged back to Cadence. There is no protocol-level sweep, burn-to-recover, or admin rescue function. The maximum trapped amount per COA is 9,999,999,999 attoFlow ≈ 0.000000009999 FLOW, but this applies to every COA independently and accumulates across the entire user base with no recovery path.

---

### Likelihood Explanation

This is triggered by routine EVM usage. Any unprivileged user who:
- Creates a COA (`EVM.createCadenceOwnedAccount()`),
- Deposits FLOW into it,
- Executes any EVM call (gas fees are deducted in attoFlow),

will produce a sub-threshold remainder if the gas cost is not a multiple of 1e10 attoFlow. Since EVM gas prices are set in attoFlow (wei) and gas usage is arbitrary, non-aligned remainders are the norm rather than the exception. Additionally, any EVM contract can deliberately or accidentally send a sub-threshold amount to a COA address, creating a trapped balance the COA owner cannot recover.

---

### Recommendation

Introduce a `withdrawAll()` function on `CadenceOwnedAccount` that:
1. Reads the current EVM balance.
2. Computes `floor(balance / 1e10) * 1e10` as the withdrawable amount.
3. Withdraws that amount to a Cadence `FlowToken.Vault`.
4. Burns or protocol-sweeps the sub-threshold remainder (e.g., transfers it to the EVM coinbase or a designated protocol address within EVM, where it can accumulate until it crosses the threshold).

Alternatively, allow intra-EVM transfer of sub-threshold amounts to a shared accumulator address so users can consolidate dust across multiple COAs before bridging back.

---

### Proof of Concept

**Step 1**: Create a COA and deposit exactly `9_999_999_999` attoFlow (just below the 1e10 threshold). This can be achieved by depositing 1 FLOW and then having an EVM contract drain all but 9,999,999,999 attoFlow via gas fees or a transfer.

**Step 2**: Attempt to withdraw the entire balance:
```cadence
let bal = EVM.Balance(attoflow: 9999999999)
let vault <- coa.withdraw(balance: bal)  // PANICS: ErrWithdrawBalanceRounding
```

**Step 3**: Attempt to withdraw zero:
```cadence
let bal = EVM.Balance(attoflow: 0)
let vault <- coa.withdraw(balance: bal)  // Returns empty vault, balance unchanged
```

**Step 4**: Confirm no other withdrawal path exists — `CadenceOwnedAccount` exposes only `withdraw()`, `withdrawNFT()`, and `withdrawTokens()` (the latter two are for bridge assets, not native FLOW). The 9,999,999,999 attoFlow is permanently trapped.

The `handler_test.go` explicitly confirms this behavior:
```go
assertPanic(t, types.IsAWithdrawBalanceRoundingError, func() {
    foa.Deposit(vault)
    foa.Withdraw(types.NewBalance(big.NewInt(1)))  // panics
})
```

**Root cause chain**:
- `fvm/evm/stdlib/contract.cdc` lines 586–606 (`withdraw()` → `InternalEVM.withdraw()`)
- `fvm/evm/impl/impl.go` lines 778–781 (`AttoFlowBalanceIsValidForFlowVault` check → panic)
- `fvm/evm/types/balance.go` lines 105–107 (`AttoFlowBalanceIsValidForFlowVault` definition)
- `fvm/evm/types/errors.go` lines 100–102 (`ErrWithdrawBalanceRounding` definition) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** fvm/evm/impl/impl.go (L778-781)
```go
			// check balance is not prone to rounding error
			if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
				panic(types.ErrWithdrawBalanceRounding)
			}
```

**File:** fvm/evm/types/balance.go (L97-107)
```go
// AttoFlowBalanceIsValidForFlowVault returns true if the given balance,
// represented as atto-flow, can be stored in a Flow Vault, without loss
// in precision.
//
// Warning! The smallest unit of Flow token that a Flow Vault (Cadence)
// can store, is 1e-8 .
// This means the minimum balance, in atto-flow, that can be stored in a
// Flow Vault, is 1e10 .
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
	return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
```

**File:** fvm/evm/types/errors.go (L100-102)
```go
	// ErrWithdrawBalanceRounding is returned when withdraw call has a balance that could
	// result in rounding error, i.e. the balance contains fractions smaller than 10^8 Flow (smallest unit allowed to transfer).
	ErrWithdrawBalanceRounding = errors.New("withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow")
```
