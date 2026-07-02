### Title
Incorrect Validity Check in `AttoFlowBalanceIsValidForFlowVault` Silently Truncates EVM Withdrawal Amounts - (`File: fvm/evm/types/balance.go`)

---

### Summary

`AttoFlowBalanceIsValidForFlowVault` uses a minimum-size comparison (`>= 10^10`) instead of a divisibility check (`% 10^10 == 0`) to guard EVM→Cadence withdrawals. Any withdrawal amount that is ≥ 1e10 attoFlow but not an exact multiple of 1e10 passes the guard, is silently truncated by integer division, and the sub-unit remainder stays locked in the EVM account without any error being raised.

---

### Finding Description

`AttoFlowBalanceIsValidForFlowVault` in `fvm/evm/types/balance.go` is documented as returning `true` if the balance "can be stored in a Flow Vault, **without loss in precision**." Its implementation is:

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0   // checks bal >= 1e10
}
```

The correct predicate for "no precision loss" is divisibility, not minimum size. The codebase already contains the correct helper:

```go
func BalanceConversionToUFix64ProneToRoundingError(bal Balance) bool {
    return new(big.Int).Mod(bal, UFixToAttoConversionMultiplier).BitLen() != 0
}
```

`AttoFlowBalanceIsValidForFlowVault` should be equivalent to `!BalanceConversionToUFix64ProneToRoundingError(bal)`, but it is not.

In `newInternalEVMTypeWithdrawFunction` (`fvm/evm/impl/impl.go`), the guard is applied and then the amount is immediately truncated by integer division:

```go
// check balance is not prone to rounding error   ← wrong check
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}

// this is where rounding from Atto scale to UFix scale happens.
value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))
```

For a withdrawal of `1.5e10` attoFlow:
1. Guard: `1.5e10 >= 1e10` → **passes** (incorrectly)
2. Truncation: `1.5e10 / 1e10 = 1` → only `1e10` attoFlow is withdrawn
3. The redundant post-withdrawal check (`roundedOff`) operates on the already-truncated vault balance (`1e10 % 1e10 == 0`), so it also **passes** silently

The user receives `1e10` attoFlow worth of FLOW tokens instead of the `1.5e10` they specified. The `5e9` attoFlow remainder stays in the EVM account. No error is raised.

---

### Impact Explanation

**Impact: Low.** The sub-unit remainder is not permanently destroyed — it stays in the caller's EVM account. However, the user's withdrawal is silently truncated: they receive less FLOW than they specified, with no error or event indicating the discrepancy. For a withdrawal of `N * 1e10 + R` attoFlow (where `0 < R < 1e10`), the user loses `R / (N * 1e10 + R)` of their intended withdrawal in the current transaction. The maximum truncation per call is just under `1e10` attoFlow (just under `1e-8` FLOW ≈ fractions of a cent at current prices), matching the "low impact" classification of the reference report.

---

### Likelihood Explanation

**Likelihood: High.** Any unprivileged Cadence transaction that calls `cadenceOwnedAccount.withdraw(balance: EVM.Balance(attoflow: X))` with any `X` that is ≥ 1e10 but not a multiple of 1e10 triggers the truncation. EVM balances accumulate gas fees and arbitrary transfer amounts in attoFlow, making non-multiple-of-1e10 balances routine. No special privilege or unusual condition is required.

---

### Recommendation

Replace the incorrect size comparison in `AttoFlowBalanceIsValidForFlowVault` with a divisibility check, consistent with the function's documented contract and with the existing `BalanceConversionToUFix64ProneToRoundingError` helper:

```go
// Correct: returns true only if bal is an exact multiple of UFixToAttoConversionMultiplier
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return new(big.Int).Mod(bal, UFixToAttoConversionMultiplier).BitLen() == 0
}
```

This ensures that any non-multiple-of-1e10 withdrawal amount is rejected with `ErrWithdrawBalanceRounding` before truncation occurs, rather than silently delivering less than requested.

---

### Proof of Concept

A Cadence transaction calling:

```cadence
let bal = EVM.Balance(attoflow: 15000000000)  // 1.5e10 — not a multiple of 1e10
let vault <- cadenceOwnedAccount.withdraw(balance: bal)
// vault.balance == 1.00000000 FLOW  (only 1e10 attoFlow)
// 5000000000 attoFlow silently remains in the EVM account
// No error is raised
```

With the corrected check, this call would panic with `ErrWithdrawBalanceRounding`, forcing the caller to supply an exact multiple of 1e10.

**Root cause:** [1](#0-0) 

**Call site where the wrong guard is applied and truncation follows:** [2](#0-1) 

**Correct divisibility helper that should have been used:** [3](#0-2)

### Citations

**File:** fvm/evm/types/balance.go (L91-95)
```go
// BalanceConversionToUFix64ProneToRoundingError returns true
// if casting to UFix64 could result in rounding error
func BalanceConversionToUFix64ProneToRoundingError(bal Balance) bool {
	return new(big.Int).Mod(bal, UFixToAttoConversionMultiplier).BitLen() != 0
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

**File:** fvm/evm/impl/impl.go (L778-801)
```go
			// check balance is not prone to rounding error
			if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
				panic(types.ErrWithdrawBalanceRounding)
			}

			// this is where rounding from Atto scale to UFix scale happens.
			value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
			amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))

			// Withdraw

			const isAuthorized = true
			account := handler.AccountByAddress(fromAddress, isAuthorized)
			vault := account.Withdraw(amount)

			ufix, roundedOff, err := types.ConvertBalanceToUFix64(vault.Balance())
			if err != nil {
				panic(err)
			}
			// We have already truncated the remainder above, but we still leave
			// the rounding check in as a redundancy.
			if roundedOff {
				panic(types.ErrWithdrawBalanceRounding)
			}
```
