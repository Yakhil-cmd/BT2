### Title
Sub-Minimum FLOW Permanently Locked in COA via Unrestricted `receive()` - (File: `fvm/evm/handler/coa/coa.sol`)

### Summary
The COA (Cadence Owned Account) EVM contract exposes a `receive() external payable` function that accepts any amount of FLOW (as EVM native currency), including amounts below the minimum withdrawable threshold of 1e10 attoFlow. Because the only withdrawal path — `CadenceOwnedAccount.withdraw()` in `fvm/evm/stdlib/contract.cdc` — enforces this minimum via `AttoFlowBalanceIsValidForFlowVault`, any sub-minimum FLOW balance accumulated in a COA via EVM-side transfers is permanently irrecoverable. There is no alternative withdrawal mechanism.

### Finding Description

The COA Solidity contract deployed at each COA's EVM address contains an unconditional payable fallback:

```solidity
// fvm/evm/handler/coa/coa.sol, line 65
receive() external payable  {
}
```

This function accepts any amount of FLOW sent to the COA address from EVM, with no lower bound.

The only path to move FLOW out of a COA back to Cadence is `CadenceOwnedAccount.withdraw()` in `fvm/evm/stdlib/contract.cdc`, which delegates to `InternalEVM.withdraw()` implemented in `fvm/evm/impl/impl.go`. That implementation enforces:

```go
// fvm/evm/impl/impl.go, line 779
if !types.AttoFlowBalanceIsValidForFlowVault(amountValue.BigInt) {
    panic(types.ErrWithdrawBalanceRounding)
}
```

where `AttoFlowBalanceIsValidForFlowVault` is:

```go
// fvm/evm/types/balance.go, line 105-106
func AttoFlowBalanceIsValidForFlowVault(bal *big.Int) bool {
    return bal.Cmp(UFixToAttoConversionMultiplier) >= 0
}
```

`UFixToAttoConversionMultiplier` = 10^(18−8) = **1e10**. Any requested withdrawal amount strictly less than 1e10 attoFlow panics with `ErrWithdrawBalanceRounding` (`"withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow"`).

This means:
- If a COA's entire EVM balance is < 1e10 attoFlow (e.g., exactly 1 attoFlow was sent via EVM), **100% of that balance is permanently stuck** — no withdrawal call can succeed.
- If a COA has a balance that is not a multiple of 1e10 attoFlow (e.g., 1.5e10 attoFlow), the sub-1e10 remainder (5e9 attoFlow) is permanently stuck after the owner withdraws the rounded-down portion.

The `receive()` function is confirmed payable in the ABI:

```json
// fvm/evm/handler/coa/coa_abi.json, line 208-211
{
    "stateMutability": "payable",
    "type": "receive"
}
```

### Impact Explanation

Any FLOW tokens sent to a COA address via an EVM transaction in an amount < 1e10 attoFlow (= 0.00000001 FLOW) are permanently locked in the COA with no recovery path. The `CadenceOwnedAccount` resource provides no escape hatch — there is no `sweepDust()`, no EVM-side withdrawal function, and no protocol-level mechanism to reclaim sub-minimum balances. The funds are provably unrecoverable: the EVM state records the balance, but the Cadence withdrawal layer categorically rejects any attempt to move it.

The maximum stuck amount per attack is bounded by 9,999,999,999 attoFlow ≈ 0.00000001 FLOW (negligible monetary value at current prices), but the loss is **permanent and irreversible** — a cross-VM asset loss.

### Likelihood Explanation

Any unprivileged EVM transaction sender can trigger this by sending a standard EVM value transfer of 1–9,999,999,999 attoFlow to any known COA address. COA addresses are publicly discoverable on-chain. The attack requires no special permissions, no staked nodes, and no compromised keys. The attacker only spends gas. The attack is trivially repeatable against any COA.

### Recommendation

1. **Remove or restrict `receive()`**: If the COA contract does not need to accept arbitrary EVM-side FLOW transfers, remove the `receive() external payable` function from `coa.sol`. COA deposits from Cadence go through `InternalEVM.deposit()` directly at the state level and do not require a payable fallback.
2. **Alternatively, add a dust-sweep mechanism**: Introduce a protocol-level path (e.g., a Cadence system transaction or a COA method) that can sweep sub-minimum balances by burning them or crediting them to a fee pool, preventing permanent lock-up.
3. **Add a minimum-value guard in `receive()`**: If the `receive()` function must remain, add a `require(msg.value >= 1e10)` guard to reject sub-minimum deposits at the EVM layer before they can accumulate.

### Proof of Concept

1. Alice creates a COA: `EVM.createCadenceOwnedAccount()` → COA address `0xCOA`.
2. Bob (any EVM EOA) sends 5,000,000,000 attoFlow (5e9, below the 1e10 minimum) to `0xCOA` via a standard EVM transfer. The COA's `receive()` accepts it silently.
3. Alice's COA now has a balance of 5e9 attoFlow.
4. Alice attempts to withdraw: `coa.withdraw(balance: EVM.Balance(attoflow: 5000000000))`.
5. `AttoFlowBalanceIsValidForFlowVault(5e9)` returns `false` (5e9 < 1e10), causing a panic: `"withdraw failed! smallest unit allowed to transfer is 1e10 attoFlow"`.
6. Alice has no other withdrawal path. The 5e9 attoFlow is permanently locked.

This behavior is confirmed by the existing test at `fvm/evm/evm_test.go:2274` ("test coa withdraw with rounding error"), which demonstrates that a balance of 9,999,999,999 attoFlow cannot be withdrawn and the transaction errors with `ErrWithdrawBalanceRounding`.

---

**Relevant file references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** fvm/evm/handler/coa/coa.sol (L65-66)
```text
    receive() external payable  {
    }
```

**File:** fvm/evm/handler/coa/coa_abi.json (L208-211)
```json
	{
		"stateMutability": "payable",
		"type": "receive"
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
