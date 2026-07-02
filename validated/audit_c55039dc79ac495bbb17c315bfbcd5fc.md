### Title
Insufficient Rounding Guard in EVM-to-Cadence Withdrawal Allows Sub-Precision attoFlow to Be Permanently Locked - (`fvm/evm/types/balance.go`)

---

### Summary

`AttoFlowBalanceIsValidForFlowVault` is documented as the guard that ensures a balance "can be stored in a Flow Vault, without loss in precision," but its implementation only checks `bal >= 1e10`. It does **not** check `bal % 1e10 == 0`. Any user who calls `CadenceOwnedAccount.withdraw` with an attoFlow amount that is ≥ 1e10 but not a multiple of 1e10 passes the guard, then loses the sub-precision remainder to integer division. That remainder is permanently inaccessible because it falls below the minimum withdrawable threshold enforced by the same guard.

---

### Finding Description

`UFixToAttoConversionMultiplier` is `10^10` (the ratio between atto-FLOW's 18-decimal precision and UFix64's 8-decimal precision). [1](#0-0) 

`AttoFlowBalanceIsValidForFlowVault` is the sole pre-flight guard used before the integer division that converts an attoFlow amount into a UFix64 amount. Its docstring explicitly states it returns `true` only when the balance can be stored "without loss in precision," but the implementation only tests `bal >= 1e10`: [2](#0-1) 

The correct predicate for "no precision loss" is `bal % 1e10 == 0`, which is exactly what the separate helper `BalanceConversionToUFix64ProneToRoundingError` checks: [3](#0-2) 

In `newInternalEVMTypeWithdrawFunction`, the broken guard is called with the comment "check balance is not prone to rounding error," then the integer division immediately follows:

```
// check balance is not prone to rounding error
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}
// this is where rounding from Atto scale to UFix scale happens.
value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))
``` [4](#0-3) 

`account.Withdraw(amount)` is then called with the truncated amount, not the user-specified amount. The EVM account is debited only `floor(X / 1e10) * 1e10`, leaving `X % 1e10` attoFlow in the account. Because that remainder is always < 1e10, any future attempt to withdraw it will fail the same guard, making it permanently inaccessible.

The same broken guard is also applied in the emulator's `withdrawFrom`: [5](#0-4) 

The existing test "test coa withdraw with remainder truncation" confirms the truncation is live and accepted: withdrawing `1230000789912345678` attoFlow returns only `1.23000078` FLOW (`1230000780000000000` attoFlow), silently discarding `9912345678` attoFlow: [6](#0-5) 

---

### Impact Explanation

Any attoFlow amount in the range `[1e10, 2e10)` that is not an exact multiple of `1e10` will have its sub-precision tail (up to `9,999,999,999` attoFlow ≈ `9.99 × 10⁻⁹` FLOW) permanently locked in the EVM account after a single withdrawal call. The locked amount can never be recovered: it is below the minimum the guard allows, and there is no other withdrawal path. This is a direct, irreversible cross-VM asset loss triggered by a single unprivileged transaction.

---

### Likelihood Explanation

Any COA owner who constructs an `EVM.Balance` struct directly with a raw `attoflow` value that is not a UFix64-aligned multiple of `1e10` will trigger this. The `Balance` struct's `attoflow` field is a plain `UInt` with no alignment enforcement: [7](#0-6) 

Users interacting directly with the EVM contract (e.g., via scripts, custom frontends, or Cadence transactions that read an EVM balance and pass it back to `withdraw`) are likely to supply non-aligned values, since EVM balances are stored at 18-decimal precision and the alignment requirement is not enforced at the type level.

---

### Recommendation

Replace the insufficient magnitude check in `AttoFlowBalanceIsValidForFlowVault` with a divisibility check:

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    // Must be a non-zero multiple of 1e10 to round-trip through UFix64 without loss
    return bal.Sign() > 0 &&
        new(big.Int).Mod(bal, UFixToAttoConversionMultiplier).BitLen() == 0
}
```

This is equivalent to `!BalanceConversionToUFix64ProneToRoundingError(bal)` and aligns the guard with its documented contract. Both call sites (`impl.go` and `emulator.go`) will then correctly reject any non-aligned amount before the integer division is reached.

---

### Proof of Concept

**Scenario:** A user holds `15,000,000,000` attoFlow (`1.5 × 1e10`) in their COA and calls:

```cadence
let bal = EVM.Balance(attoflow: 15000000000)  // 1.5e10, >= 1e10 → guard passes
let vault <- coa.withdraw(balance: bal)
// vault.balance == 0.00000001 FLOW (= 1e10 attoFlow)
// 5,000,000,000 attoFlow remain in EVM account, permanently unwithdrawable
```

**Step-by-step through the code:**

1. `amountValue.BigInt = 15000000000`
2. `AttoFlowBalanceIsValidForFlowVault(15000000000)` → `15000000000 >= 10000000000` → **`true`** (guard passes)
3. `value = 15000000000 / 10000000000 = 1` (integer division, remainder `5000000000` discarded)
4. `amount = NewBalanceFromUFix64(1) = 1 * 1e10 = 10000000000` attoFlow
5. `account.Withdraw(10000000000)` — EVM account debited `1e10`, not `1.5e10`
6. `vault.Balance() = 10000000000` → `ConvertBalanceToUFix64` → `roundedOff = false` (second check passes)
7. User receives `0.00000001` FLOW; `5,000,000,000` attoFlow is permanently locked

The existing test at `fvm/evm/evm_test.go:2622` ("test coa withdraw with remainder truncation") demonstrates this exact truncation succeeding without error, confirming the code path is live. [8](#0-7)

### Citations

**File:** fvm/evm/types/balance.go (L15-16)
```go
	UFixedToAttoConversionScale    = AttoScale - UFixedScale
	UFixToAttoConversionMultiplier = new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(UFixedToAttoConversionScale)), nil)
```

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

**File:** fvm/evm/impl/impl.go (L778-785)
```go
			// check balance is not prone to rounding error
			if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
				panic(types.ErrWithdrawBalanceRounding)
			}

			// this is where rounding from Atto scale to UFix scale happens.
			value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
			amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))
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

**File:** fvm/evm/evm_test.go (L2622-2692)
```go
	t.Run("test coa withdraw with remainder truncation", func(t *testing.T) {
		t.Parallel()

		RunWithNewEnvironment(t,
			chain, func(
				ctx fvm.Context,
				vm fvm.VM,
				snapshot snapshot.SnapshotTree,
				testContract *TestContract,
				testAccount *EOATestAccount,
			) {
				code := fmt.Appendf(nil,
					`
				import EVM from %s
				import FlowToken from %s
				transaction() {
					prepare(account: auth(BorrowValue) &Account) {
						let admin = account.storage.borrow<&FlowToken.Administrator>(
							from: /storage/flowTokenAdmin
						)!

						let minter <- admin.createNewMinter(allowedAmount: 2.34)
						let vault <- minter.mintTokens(amount: 2.34)
						destroy minter

						let cadenceOwnedAccount <- EVM.createCadenceOwnedAccount()
						cadenceOwnedAccount.deposit(from: <-vault)

						let bal = EVM.Balance(attoflow: 1230000789912345678)
						let vault2 <- cadenceOwnedAccount.withdraw(balance: bal)
						let balance = vault2.balance
						assert(balance == 1.23000078, message: "mismatching vault balance")
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
				require.NoError(t, output.Err)

				withdrawEvent := output.Events[7]

				ev, err := events.FlowEventToCadenceEvent(withdrawEvent)
				require.NoError(t, err)

				evPayload, err := events.DecodeFLOWTokensWithdrawnEventPayload(ev)
				require.NoError(t, err)

				// 2.34000000 - 1.23000078 = 1.10999922
				expectedBalanceAfterWithdraw := big.NewInt(1_109_999_220_000_000_000)
				require.Equal(t, expectedBalanceAfterWithdraw, evPayload.BalanceAfterInAttoFlow.Value)
			},
		)
	})
```

**File:** fvm/evm/stdlib/contract.cdc (L304-310)
```text
        access(all) var attoflow: UInt

        /// Constructs a new balance
        access(all)
        view init(attoflow: UInt) {
            self.attoflow = attoflow
        }
```
