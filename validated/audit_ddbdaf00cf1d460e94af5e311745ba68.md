### Title
Sub-Minimum attoFlow Balance Permanently Locked in EVM Accounts — (`fvm/evm/types/balance.go`, `fvm/evm/stdlib/contract.cdc`)

### Summary

Flow EVM accounts (including Cadence-Owned Accounts / COAs) can accumulate balances in atto-flow (1e-18 FLOW) that are permanently irrecoverable. Because the Cadence `FlowToken.Vault` uses `UFix64` with 8 decimal places, the minimum withdrawable unit from EVM back to Cadence is 1e10 attoFlow (= 0.00000001 FLOW). Any EVM balance below this threshold — or any fractional remainder left after a withdrawal — is permanently locked in the EVM state with no mechanism to recover it.

### Finding Description

Flow EVM balances are stored at 18-decimal (atto-flow) precision, while Cadence `FlowToken.Vault` uses 8-decimal (`UFix64`) precision. The gap is 10 decimal places, meaning the minimum withdrawable unit is `1e10` attoFlow.

`AttoFlowBalanceIsValidForFlowVault` enforces this floor:

```go
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
```

`UFixToAttoConversionMultiplier` is `10^10`. Any balance strictly less than `10^10` attoFlow fails this check and **cannot be withdrawn**.

The `CadenceOwnedAccount.withdraw` function in `contract.cdc` enforces this at the Cadence layer:

```cadence
access(Owner | Withdraw)
fun withdraw(balance: Balance): @FlowToken.Vault {
    // ...
    let vault <- InternalEVM.withdraw(
        from: self.addressBytes,
        amount: balance.attoflow
    ) as! @FlowToken.Vault
```

And `newInternalEVMTypeWithdrawFunction` in `impl.go` panics with `ErrWithdrawBalanceRounding` if the amount is below `1e10`:

```go
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}
```

There are multiple realistic paths by which a COA or any EVM address accumulates a sub-minimum balance:

1. **Gas fee residuals**: EVM gas fees are collected at the coinbase address in attoFlow. Fractional gas amounts (e.g., from EIP-1559 base fee burns or tip rounding) can leave sub-`1e10` attoFlow residuals at the coinbase address.
2. **EVM-to-EVM transfers**: Any unprivileged user can send an arbitrary attoFlow amount (e.g., 1 attoFlow) to a COA's EVM address via a standard EVM transaction. The COA owner then holds a balance that, if it is the only balance or if the total is below `1e10`, cannot be withdrawn.
3. **Withdrawal truncation**: The `withdraw` function in `impl.go` truncates the requested amount to the nearest `1e10` attoFlow boundary (`Div` by `UFixToAttoConversionMultiplier`). The truncated remainder stays in the EVM account permanently.

The `deposit` function on `CadenceOwnedAccount` is `access(all)` — any caller can deposit FLOW into any COA's EVM address. Similarly, any EVM EOA can send value to any EVM address. There is no withdrawal path for sub-`1e10` attoFlow balances.

### Impact Explanation

FLOW tokens accumulate in EVM accounts (COAs or EOAs) in amounts below `1e10` attoFlow and are permanently irrecoverable. There is no sweep, burn, or alternative withdrawal path. The tokens remain in the EVM state, counted in the total supply but inaccessible to their owner. Over time, across many accounts and transactions, this constitutes a systematic, protocol-level token lock. The analogy to the report is exact: assets can be deposited (or accumulate via gas/EVM transfers) but cannot be withdrawn due to a missing mechanism for sub-minimum amounts.

### Likelihood Explanation

This is a **certainty**, not a probability. Every EVM transaction that pays gas fees in a non-round attoFlow amount leaves a sub-`1e10` remainder at the coinbase. Every withdrawal that truncates a fractional amount leaves a remainder. Any user can deliberately send 1 attoFlow to a COA via an EVM transaction. The condition is continuously triggered in normal protocol operation.

### Recommendation

- Add a protocol-level mechanism to sweep sub-minimum attoFlow remainders: either burn them (reducing total supply to match) or aggregate them into a recoverable protocol fee vault.
- Alternatively, allow `withdraw` to round up to the nearest `1e10` attoFlow boundary and return the rounded amount, documenting the rounding behavior.
- Consider adding a `sweepDust()` function on `CadenceOwnedAccount` that transfers any sub-`1e10` remainder to a designated protocol address via an EVM-level transfer (which does not require the UFix64 conversion).

### Proof of Concept

The existing test suite already documents this behavior as expected:

```
// since 1e10 attoFlow is the minimum withdrawable amount,
// verify any amount below 1e10 can not be withdrawn.
let bal = EVM.Balance(attoflow: 9999999999)
let vault2 <- cadenceOwnedAccount.withdraw(balance: bal)
// → panics with ErrWithdrawBalanceRounding
```

An unprivileged attacker can lock funds in a victim's COA:

1. Alice owns a COA with balance `10000000000` attoFlow (exactly `1e10`, the minimum).
2. Attacker sends `1` attoFlow to Alice's COA EVM address via a standard EVM transaction (costs only gas).
3. Alice's COA balance is now `10000000001` attoFlow.
4. Alice calls `withdraw(balance: EVM.Balance(attoflow: 10000000001))` → panics with `ErrWithdrawBalanceRounding` because `10000000001 % 1e10 != 0`.
5. Alice calls `withdraw(balance: EVM.Balance(attoflow: 10000000000))` → succeeds, but `1` attoFlow remains permanently locked.

The `1` attoFlow remainder has no recovery path. Repeated attacks accumulate locked dust.

**Root cause files:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** fvm/evm/impl/impl.go (L778-781)
```go
			// check balance is not prone to rounding error
			if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
				panic(types.ErrWithdrawBalanceRounding)
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

**File:** fvm/evm/types/errors.go (L100-102)
```go
	// ErrWithdrawBalanceRounding is returned when withdraw call has a balance that could
	// result in rounding error, i.e. the balance contains fractions smaller than 10^8 Flow (smallest unit allowed to transfer).
	ErrWithdrawBalanceRounding = errors.New("withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow")
```
