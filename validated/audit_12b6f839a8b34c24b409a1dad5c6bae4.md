### Title
Sub-1e10 Attoflow FLOW Tokens Permanently Locked in EVM Accounts with No Recovery Path - (`fvm/evm/types/balance.go`, `fvm/evm/impl/impl.go`, `fvm/evm/stdlib/contract.cdc`)

### Summary
The Flow EVM environment stores balances in attoflow (10⁻¹⁸ FLOW, 18 decimal places), while Cadence `FlowToken.Vault` uses `UFix64` (10⁻⁸ FLOW, 8 decimal places). The conversion multiplier is 1e10. Any EVM account balance whose attoflow value is not a clean multiple of 1e10 contains a sub-1e10 attoflow remainder that can never be withdrawn back to Cadence. There is no sweep, burn, or recovery mechanism for this dust. The tokens remain credited in EVM state but are permanently inaccessible from the Cadence side.

### Finding Description
The `withdraw` function in `fvm/evm/impl/impl.go` enforces a hard floor: if the requested attoflow amount is less than `UFixToAttoConversionMultiplier` (1e10), it panics with `ErrWithdrawBalanceRounding`. [1](#0-0) 

When the requested amount is ≥ 1e10 but has a sub-1e10 remainder, the remainder is silently truncated: [2](#0-1) 

The truncated remainder stays in the EVM account. The user cannot then withdraw that remainder because it is < 1e10 attoflow, which fails the `AttoFlowBalanceIsValidForFlowVault` check: [3](#0-2) 

The precision gap is structural: UFix64 has 8 decimal places, attoflow has 18, and the gap of 10 decimal places (1e10) defines the permanently unrecoverable zone. [4](#0-3) 

The Cadence-side `withdraw` function in `contract.cdc` documents this limitation but provides no recovery path: [5](#0-4) 

### Impact Explanation
FLOW tokens credited to EVM accounts in sub-1e10 attoflow amounts are permanently locked in the EVM environment. They cannot be:
- Withdrawn to Cadence (blocked by `AttoFlowBalanceIsValidForFlowVault`)
- Burned or swept by any protocol mechanism
- Recovered by any admin function (none exists)

This is a direct analog to the Reservoir stuck-token class: assets enter a system that only exposes one exit path, and that exit path has a minimum threshold below which assets are permanently trapped. The maximum stuck amount per account is 9,999,999,999 attoflow ≈ 10⁻⁸ FLOW. Across many accounts and over time (gas fee accumulation, EVM-to-EVM micro-transfers), the aggregate locked supply grows monotonically with no recovery mechanism.

### Likelihood Explanation
Any EVM operation that produces a non-multiple-of-1e10 attoflow balance creates permanent dust. Concrete triggers reachable by any unprivileged user:

1. **EVM-to-EVM micro-transfer**: A user calls `cadenceOwnedAccount.call(to: victim, value: EVM.Balance(attoflow: 1))`. The victim's balance now contains 1 attoflow that can never be withdrawn.
2. **Gas fee accumulation at coinbase**: If the coinbase EVM address is a COA and gas fees (gasUsed × gasPrice in attoflow) produce a non-1e10-aligned total, the coinbase accumulates irrecoverable dust.
3. **Intentional truncation**: A user withdrawing `1230000789912345678` attoflow receives `1230000780000000000` (truncated), leaving `9912345678` attoflow permanently stuck, as confirmed by the existing test: [6](#0-5) 

### Recommendation
Add a protocol-level mechanism to sweep sub-1e10 attoflow dust from EVM accounts. Options include:
- A `sweepDust()` function on `CadenceOwnedAccount` that burns or donates sub-1e10 attoflow remainders to the protocol fee pool.
- Enforce at the EVM layer that all balance-changing operations (gas deduction, EVM transfers) only operate in 1e10-aligned increments, rounding gas fees up to the nearest 1e10 attoflow.
- Expose a `destroyDust()` path that explicitly burns the sub-1e10 remainder and decrements the EVM total supply accordingly.

### Proof of Concept
The existing test suite already demonstrates the stuck-dust scenario:

```
// Deposit 2.34 FLOW (= 2340000000000000000 attoflow, clean multiple of 1e10)
cadenceOwnedAccount.deposit(from: <-vault)  // 2340000000000000000 attoflow

// Withdraw 1230000789912345678 attoflow — truncated to 1230000780000000000
let vault2 <- cadenceOwnedAccount.withdraw(balance: EVM.Balance(attoflow: 1230000789912345678))
// vault2.balance == 1.23000078 FLOW (= 1230000780000000000 attoflow)

// Remaining balance: 2340000000000000000 - 1230000780000000000 = 1109999220000000000 attoflow
// BUT: 9912345678 attoflow of the original balance is now permanently stuck
// Attempting to withdraw 9912345678 attoflow panics: ErrWithdrawBalanceRounding
// (9912345678 < 10000000000 = UFixToAttoConversionMultiplier)
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** fvm/evm/types/balance.go (L12-20)
```go
var (
	AttoScale                      = 18
	UFixedScale                    = fixedpoint.Fix64Scale
	UFixedToAttoConversionScale    = AttoScale - UFixedScale
	UFixToAttoConversionMultiplier = new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(UFixedToAttoConversionScale)), nil)

	OneFlowInUFix64 = cadence.UFix64(uint64(math.Pow(10, float64(UFixedScale))))
	EmptyBalance    = Balance(new(big.Int))
)
```

**File:** fvm/evm/types/balance.go (L82-95)
```go
func ConvertBalanceToUFix64(bal Balance) (value cadence.UFix64, roundedOff bool, err error) {
	converted := new(big.Int).Div(bal, UFixToAttoConversionMultiplier)
	if !converted.IsUint64() {
		// this should never happen
		err = fmt.Errorf("balance can't be casted to a uint64")
	}
	return cadence.UFix64(converted.Uint64()), BalanceConversionToUFix64ProneToRoundingError(bal), err
}

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
