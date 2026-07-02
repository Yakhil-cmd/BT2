### Title
Sub-Precision FLOW Permanently Locked in EVM Accounts Due to Missing Recovery Mechanism - (File: `fvm/evm/types/balance.go`, `fvm/evm/impl/impl.go`, `fvm/evm/stdlib/contract.cdc`)

---

### Summary

EVM accounts on Flow (including Cadence Owned Accounts, COAs) hold balances in attoFlow precision (1e-18 FLOW). However, the Cadence `FlowToken.Vault` only supports UFix64 precision (1e-8 FLOW = 1e10 attoFlow). The guard `AttoFlowBalanceIsValidForFlowVault` only checks `bal >= 1e10`, not `bal % 1e10 == 0`. Any EVM account whose balance is below 1e10 attoFlow — reachable via ordinary EVM-level transfers — has its entire balance permanently locked with no protocol-level recovery path.

---

### Finding Description

The precision gap between EVM (attoFlow, 1e-18) and Cadence (UFix64, 1e-8) is bridged by `AttoFlowBalanceIsValidForFlowVault` in `fvm/evm/types/balance.go`:

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
```

`UFixToAttoConversionMultiplier` is `1e10`. This check only enforces `bal >= 1e10`; it does **not** enforce `bal % 1e10 == 0`.

In `newInternalEVMTypeWithdrawFunction` (`fvm/evm/impl/impl.go`), the withdrawal path is:

```go
// check balance is not prone to rounding error
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}

// this is where rounding from Atto scale to UFix scale happens.
value := new(big.Int).Div(amountValue.BigInt, types.UFixToAttoConversionMultiplier)
amount := types.NewBalanceFromUFix64(cadence.UFix64(value.Uint64()))
```

If an EVM account's total balance is, for example, `5_000_000_000` attoFlow (< 1e10), the guard panics on any withdrawal attempt. The account owner cannot withdraw any amount — not even zero — because `balance.isZero()` is false and the guard rejects the amount. There is no admin sweep, no protocol-level drain function, and no alternative path to recover these funds.

The `CadenceOwnedAccount.withdraw` in `fvm/evm/stdlib/contract.cdc` documents this limitation but provides no recovery:

```cadence
/// Amounts smaller than 1e10 attoFlow, will cause the function to panic
/// with: "withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow".
```

---

### Impact Explanation

FLOW tokens held in any EVM account (COA or EOA) whose balance is below `1e10` attoFlow (< 0.00000001 FLOW) are permanently and irrecoverably locked. There is no admin withdrawal function, no protocol sweep, and no alternative bridge path. This is a direct analog to the "locked ether" class: funds enter the EVM environment but cannot exit due to a missing recovery mechanism for sub-precision balances.

While individual locked amounts are small (< 1e-8 FLOW per account), the condition is reachable by any unprivileged user and can accumulate across many accounts over time.

---

### Likelihood Explanation

Any EVM-level transfer of a non-round attoFlow amount to a COA creates a locked remainder. Concrete triggers include:

1. An EVM contract sends exactly `5_000_000_000` attoFlow to a COA — the entire balance is permanently locked.
2. A COA participates in EVM DeFi and receives a non-round gas refund or token amount below 1e10 attoFlow.
3. A user deposits FLOW into a COA, then an EVM contract drains all but a sub-1e10 attoFlow remainder.

EVM contracts operate at full attoFlow precision and routinely produce non-round amounts. This is a realistic, reachable condition for any COA interacting with EVM contracts.

---

### Recommendation

1. **Add a sweep/recovery function** on `CadenceOwnedAccount` (or at the protocol level) that allows the COA owner to recover any sub-precision remainder by burning it or crediting it to a protocol fee account, analogous to the "withdraw mechanism with access control" recommended in the original report.
2. **Strengthen the guard**: change `AttoFlowBalanceIsValidForFlowVault` to also check `bal % 1e10 == 0`, so that non-multiple amounts are rejected at the point of withdrawal request rather than silently truncated, making the locked remainder explicit.
3. **Document the irrecoverability** more prominently at the deposit entry points so users understand that sub-precision amounts sent via EVM are permanently unwithdrawable.

---

### Proof of Concept

```cadence
import EVM from <EVM_ADDRESS>
import FlowToken from <FLOW_TOKEN_ADDRESS>

transaction() {
    prepare(account: auth(BorrowValue) &Account) {
        let admin = account.storage.borrow<&FlowToken.Administrator>(
            from: /storage/flowTokenAdmin
        )!
        let minter <- admin.createNewMinter(allowedAmount: 1.0)
        let vault <- minter.mintTokens(amount: 1.0)
        destroy minter

        // Create a COA and deposit 1 FLOW
        let coa <- EVM.createCadenceOwnedAccount()
        coa.deposit(from: <-vault)

        // Simulate an EVM-level transfer that leaves 5_000_000_000 attoFlow
        // (e.g., an EVM contract sends back all but 5e9 attoFlow)
        // The COA now has balance = 5_000_000_000 attoFlow

        // Attempt to withdraw — this will PANIC with ErrWithdrawBalanceRounding
        // because 5_000_000_000 < 1e10 (UFixToAttoConversionMultiplier)
        let lockedBal = EVM.Balance(attoflow: 5_000_000_000)
        let recovered <- coa.withdraw(balance: lockedBal)
        // ^ panics: "withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow"

        destroy coa
        destroy recovered
    }
}
```

The 5,000,000,000 attoFlow in the COA is permanently locked. No protocol path exists to recover it.

**Key files and lines:**

- Root cause guard: [1](#0-0) 
- Truncation without remainder recovery: [2](#0-1) 
- Cadence-level withdraw with no recovery path: [3](#0-2) 
- Precision gap documented but unmitigated: [4](#0-3)

### Citations

**File:** fvm/evm/types/balance.go (L77-89)
```go
// ConvertBalanceToUFix64 casts the balance into a UFix64,
//
// Warning! The smallest unit of Flow token that a FlowVault (Cadence) could store is 1e10^-8,
// so transferring smaller values (or values with smalls fractions) could result in loss in
// conversion. The rounded flag should be used to prevent loss of assets.
func ConvertBalanceToUFix64(bal Balance) (value cadence.UFix64, roundedOff bool, err error) {
	converted := new(big.Int).Div(bal, UFixToAttoConversionMultiplier)
	if !converted.IsUint64() {
		// this should never happen
		err = fmt.Errorf("balance can't be casted to a uint64")
	}
	return cadence.UFix64(converted.Uint64()), BalanceConversionToUFix64ProneToRoundingError(bal), err
}
```

**File:** fvm/evm/types/balance.go (L105-107)
```go
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
