### Title
Sub-Minimum attoFlow Balance Permanently Locked in COA — Cannot Be Withdrawn to Cadence - (File: fvm/evm/types/balance.go)

---

### Summary

The Flow EVM bridge enforces a hard minimum withdrawal amount of `1e10 attoFlow` (= `1e-8 FLOW`) due to the precision mismatch between EVM's 18-decimal attoFlow representation and Cadence's 8-decimal `UFix64`. EVM gas fee deductions operate at full 18-decimal precision and can reduce a Cadence-Owned Account (COA)'s EVM balance to a value below this threshold. Once below `1e10 attoFlow`, the remaining balance is permanently irrecoverable to Cadence — a direct structural analog to the BasketFacet `MIN_AMOUNT` exit-lock.

---

### Finding Description

The conversion multiplier between EVM attoFlow and Cadence UFix64 is:

```
UFixToAttoConversionMultiplier = 10^(18 - 8) = 10^10 = 1e10
```

`AttoFlowBalanceIsValidForFlowVault` enforces that any withdrawal amount must be **at least** `1e10 attoFlow`:

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
``` [1](#0-0) 

This check is enforced in two places in the withdrawal path:

1. **Emulator layer** (`withdrawFrom`): returns `ErrWithdrawBalanceRounding` if the requested amount is below `1e10 attoFlow`. [2](#0-1) 

2. **Cadence host function** (`newInternalEVMTypeWithdrawFunction`): panics with `ErrWithdrawBalanceRounding` if the amount is below `1e10 attoFlow`. [3](#0-2) 

The error itself is defined as:

```go
ErrWithdrawBalanceRounding = errors.New("withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow")
``` [4](#0-3) 

**How sub-minimum dust accumulates:**

EVM gas fees are charged at full 18-decimal attoFlow precision. After a COA executes EVM transactions (calls, deploys), the gas cost deducted from the COA's EVM balance can leave a remainder that is not a multiple of `1e10`. Additionally, when a user requests to withdraw an amount with a sub-`1e10` attoFlow remainder (e.g., `1230000789912345678` attoFlow), the truncation in `newInternalEVMTypeWithdrawFunction` at line 784 silently discards the remainder:

```go
value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))
``` [5](#0-4) 

The test "test coa withdraw with remainder truncation" confirms this: withdrawing `1230000789912345678` attoFlow only returns `1.23000078` FLOW, leaving `9912345678` attoFlow (`< 1e10`) permanently stranded in the COA's EVM balance. [6](#0-5) 

The `CadenceOwnedAccount.withdraw` function in the EVM contract has no mechanism to sweep or recover sub-minimum dust: [7](#0-6) 

---

### Impact Explanation

FLOW tokens deposited into a COA's EVM balance can become permanently irrecoverable to Cadence if the balance (or its remainder after a partial withdrawal) falls below `1e10 attoFlow`. The funds remain in the EVM state but cannot be bridged back. This is a **cross-VM asset loss**: the tokens exist on-chain but are inaccessible to their owner. The maximum locked amount per COA is `9,999,999,999 attoFlow` ≈ `0.00000001 FLOW`. While small per account, this is a structural, permanent loss with no recovery path — directly analogous to the `MIN_AMOUNT` lock in BasketFacet.sol.

---

### Likelihood Explanation

Any COA that executes EVM transactions paying gas fees is susceptible. Gas costs are denominated in attoFlow at 18-decimal precision, and the probability that the resulting balance remainder is exactly a multiple of `1e10` is negligible. Every active COA user who attempts a full withdrawal will encounter this. The entry path requires only a standard unprivileged Cadence transaction calling `cadenceOwnedAccount.withdraw(balance:)`.

---

### Recommendation

1. **Document the limitation at the protocol level** — the current inline comment in `contract.cdc` is insufficient; users have no way to know their balance has irrecoverable dust until they attempt a full exit.
2. **Provide a dust-sweep mechanism** — allow sub-minimum balances to be donated to the fee vault or burned, so users can fully exit their COA.
3. **Round up on full-balance withdrawal** — when the requested amount equals the COA's full balance and the remainder is sub-minimum, consider rounding the withdrawal up to the nearest `1e10` attoFlow boundary (absorbing the dust into the returned vault) rather than silently truncating.

---

### Proof of Concept

```cadence
import EVM from <EVMAddress>
import FlowToken from <FlowTokenAddress>

transaction() {
    prepare(account: auth(BorrowValue) &Account) {
        // 1. Create a COA and deposit FLOW
        let coa <- EVM.createCadenceOwnedAccount()
        let vault <- account.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)!
            .withdraw(amount: 1.0) as! @FlowToken.Vault
        coa.deposit(from: <-vault)

        // 2. Execute an EVM call that consumes gas, leaving sub-1e10 attoFlow dust
        //    (gas deduction leaves e.g. 5_000_000_000 attoFlow = 0.000000005 FLOW)

        // 3. Attempt to withdraw the remaining dust — this panics:
        //    "withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow"
        let dustBalance = coa.balance()  // e.g. Balance(attoflow: 5_000_000_000)
        let recovered <- coa.withdraw(balance: dustBalance)  // PANICS — dust is permanently locked

        destroy recovered
        destroy coa
    }
}
```

The root cause is `AttoFlowBalanceIsValidForFlowVault` returning `false` for any balance below `1e10 attoFlow`, with no alternative recovery path provided by the protocol. [8](#0-7) [9](#0-8)

### Citations

**File:** fvm/evm/types/balance.go (L12-16)
```go
var (
	AttoScale                      = 18
	UFixedScale                    = fixedpoint.Fix64Scale
	UFixedToAttoConversionScale    = AttoScale - UFixedScale
	UFixToAttoConversionMultiplier = new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(UFixedToAttoConversionScale)), nil)
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

**File:** fvm/evm/impl/impl.go (L778-781)
```go
			// check balance is not prone to rounding error
			if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
				panic(types.ErrWithdrawBalanceRounding)
			}
```

**File:** fvm/evm/impl/impl.go (L783-785)
```go
			// this is where rounding from Atto scale to UFix scale happens.
			value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
			amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))
```

**File:** fvm/evm/types/errors.go (L100-102)
```go
	// ErrWithdrawBalanceRounding is returned when withdraw call has a balance that could
	// result in rounding error, i.e. the balance contains fractions smaller than 10^8 Flow (smallest unit allowed to transfer).
	ErrWithdrawBalanceRounding = errors.New("withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow")
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
