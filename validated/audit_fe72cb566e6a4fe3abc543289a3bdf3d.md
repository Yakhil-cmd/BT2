### Title
Silent Precision Loss in EVM-to-Cadence FLOW Withdrawal Truncates User Funds Without Notification - (File: fvm/evm/impl/impl.go)

### Summary

When a `CadenceOwnedAccount` (COA) owner withdraws FLOW from the EVM environment back to Cadence, the requested attoflow amount is silently truncated to the nearest UFix64-representable value (i.e., the nearest multiple of 1e10 attoflow). The truncated remainder stays locked in the EVM account with no mechanism to recover it, and the `FLOWTokensWithdrawn` event emits the *pre-truncation* attoflow value as the `amount` field (via `balance.inFLOW()`), which itself is also a rounded-down UFix64. This is a cross-VM asset loss: the user specifies an exact attoflow amount, the EVM state deducts the truncated (smaller) amount, and the sub-1e10 remainder is permanently stranded.

### Finding Description

The EVM-to-Cadence bridge withdrawal path is:

1. **Cadence contract** (`fvm/evm/stdlib/contract.cdc`, `CadenceOwnedAccount.withdraw`): passes `balance.attoflow` (a raw `UInt`) directly to `InternalEVM.withdraw`. [1](#0-0) 

2. **Go host function** (`fvm/evm/impl/impl.go`, `newInternalEVMTypeWithdrawFunction`): receives the raw attoflow value, checks it is `>= UFixToAttoConversionMultiplier` (1e10), then **truncates** it by integer-dividing by `UFixToAttoConversionMultiplier` and re-multiplying: [2](#0-1) 

   ```
   value = amountValue / 1e10          // truncates sub-1e10 remainder
   amount = value * 1e10               // re-expands, losing the remainder
   account.Withdraw(amount)            // EVM deducts only the truncated amount
   ```

3. The `AttoFlowBalanceIsValidForFlowVault` guard only rejects amounts **strictly less than** 1e10 attoflow. Any amount ≥ 1e10 that has a non-zero sub-1e10 remainder (e.g., `1230000789912345678`) passes the guard and proceeds to silent truncation. [3](#0-2) 

4. The `FLOWTokensWithdrawn` event emits `amount: balance.inFLOW()`, which is the *caller-supplied* attoflow value rounded down to UFix64 — not the actual amount deducted from EVM state. The sub-1e10 remainder (up to 9,999,999,999 attoflow ≈ 0.00000001 FLOW per call) is silently stranded in the EVM account. [4](#0-3) 

The test `"test coa withdraw with remainder truncation"` explicitly confirms this behavior: requesting `1230000789912345678` attoflow yields a vault of `1.23000078` FLOW (i.e., `1230000780000000000` attoflow), with `912345678` attoflow silently lost. [5](#0-4) 

### Impact Explanation

**Cross-VM asset loss**: Each withdrawal call with a non-aligned attoflow amount permanently strands up to 9,999,999,999 attoflow (≈ 0.00000001 FLOW) in the EVM account. The stranded amount cannot be recovered because:
- The minimum withdrawable amount is 1e10 attoflow, so sub-1e10 remainders can never be withdrawn.
- There is no dust-sweep or recovery mechanism.

Over many withdrawals, or in automated bridge/DeFi protocols that operate at attoflow precision, the cumulative loss is proportional to the number of calls. An attacker who controls a Cadence contract or script that repeatedly calls `withdraw` with carefully chosen attoflow values can cause a victim COA to accumulate permanently stranded dust. More broadly, any user who withdraws an attoflow amount with a non-zero sub-1e10 remainder loses that remainder with no warning beyond the documented comment.

The `FLOWTokensWithdrawn` event's `amount` field is also misleading: it reports `balance.inFLOW()` (the caller's requested amount, rounded down to UFix64), not the actual amount deducted from EVM state, making off-chain accounting incorrect. [4](#0-3) 

### Likelihood Explanation

**Medium**. Any unprivileged Cadence transaction or script that calls `cadenceOwnedAccount.withdraw(balance: EVM.Balance(attoflow: X))` where `X` is not a multiple of 1e10 triggers this. This is a normal, reachable user operation. EVM contracts that accumulate fractional attoflow balances (e.g., from gas refunds, ERC-20 transfers at 18-decimal precision, or DeFi yield) will naturally produce non-aligned balances. The `EVM.Balance` struct accepts any `UInt` attoflow value with no alignment requirement, so users are not warned at the point of constructing the balance. [6](#0-5) 

### Recommendation

1. **Reject non-aligned amounts**: Extend the existing `AttoFlowBalanceIsValidForFlowVault` guard (or add a new check) to also reject amounts where `amountValue % UFixToAttoConversionMultiplier != 0`, returning `ErrWithdrawBalanceRounding`. This is consistent with the existing guard philosophy. [7](#0-6) 

2. **Fix the event emission**: Emit `amount` as `vault.balance` (the actual UFix64 amount transferred) rather than `balance.inFLOW()` (the caller's requested amount, which may differ after truncation). [4](#0-3) 

### Proof of Concept

The following Cadence transaction, submittable by any unprivileged account that owns a COA, demonstrates the loss:

```cadence
import EVM from <EVMAddress>
import FlowToken from <FlowTokenAddress>

transaction() {
    prepare(account: auth(BorrowValue) &Account) {
        let admin = account.storage.borrow<&FlowToken.Administrator>(
            from: /storage/flowTokenAdmin)!
        let minter <- admin.createNewMinter(allowedAmount: 2.34)
        let vault <- minter.mintTokens(amount: 2.34)
        destroy minter

        let coa <- EVM.createCadenceOwnedAccount()
        coa.deposit(from: <-vault)

        // Request 1230000789912345678 attoflow (has 912345678 sub-1e10 remainder)
        let bal = EVM.Balance(attoflow: 1230000789912345678)
        let vault2 <- coa.withdraw(balance: bal)

        // vault2.balance == 1.23000078 FLOW (== 1230000780000000000 attoflow)
        // 912345678 attoflow is permanently stranded in the EVM account
        // coa.balance().attoflow == 1109999220000000000 (not 1109999209912345678)
        assert(vault2.balance == 1.23000078, message: "truncation confirmed")

        destroy coa
        destroy vault2
    }
}
```

This matches the confirmed behavior in the existing test suite: [8](#0-7) 

The `912345678` attoflow remainder is deducted from neither the EVM account nor returned to the caller — it is simply not deducted from the EVM account at all, meaning it remains there but is permanently below the 1e10 minimum withdrawal threshold and cannot be recovered. [2](#0-1) [3](#0-2)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L307-310)
```text
        access(all)
        view init(attoflow: UInt) {
            self.attoflow = attoflow
        }
```

**File:** fvm/evm/stdlib/contract.cdc (L595-598)
```text
            let vault <- InternalEVM.withdraw(
                from: self.addressBytes,
                amount: balance.attoflow
            ) as! @FlowToken.Vault
```

**File:** fvm/evm/stdlib/contract.cdc (L599-604)
```text
            emit FLOWTokensWithdrawn(
                address: self.address().toString(),
                amount: balance.inFLOW(),
                withdrawnUUID: vault.uuid,
                balanceAfterInAttoFlow: self.balance().attoflow
            )
```

**File:** fvm/evm/impl/impl.go (L783-791)
```go
			// this is where rounding from Atto scale to UFix scale happens.
			value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
			amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))

			// Withdraw

			const isAuthorized = true
			account := handler.AccountByAddress(fromAddress, isAuthorized)
			vault := account.Withdraw(amount)
```

**File:** fvm/evm/types/balance.go (L91-95)
```go
// BalanceConversionToUFix64ProneToRoundingError returns true
// if casting to UFix64 could result in rounding error
func BalanceConversionToUFix64ProneToRoundingError(bal Balance) bool {
	return new(big.Int).Mod(bal, UFixToAttoConversionMultiplier).BitLen() != 0
}
```

**File:** fvm/evm/types/balance.go (L105-107)
```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
	return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
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
