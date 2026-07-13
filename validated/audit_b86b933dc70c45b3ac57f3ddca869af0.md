The vulnerability is real and concrete. Let me confirm the exact lines before writing the finding.

The `TransferMethodName` case in `bank.go` at lines 167–200 is the root cause:

- **Line 175**: `sender := args[0].(common.Address)` — taken from attacker-controlled calldata
- **Line 181**: `from := sdk.AccAddress(sender.Bytes())` — used as the debit account
- **Line 186**: `denom := EVMDenom(contract.Caller())` — denom is `evm/<callerContract>`
- **Line 192**: `bc.bankKeeper.SendCoins(ctx, from, to, ...)` — no check that `from == contract.Caller()`

There is zero authorization guard between `sender` (arg 0) and `contract.Caller()`. Compare this to `utils.go` lines 46–49, which explicitly enforces `caller == signer` for other precompile paths — that guard is entirely absent from the `transfer` branch.

---

### Title
Unauthorized `SendCoins` via missing `from == Caller()` check in `BankContract.Run` — (`x/cronos/keeper/precompiles/bank.go`)

### Summary
The `transfer` method of the bank precompile derives the **denom** from `contract.Caller()` but derives the **sender** from an arbitrary first ABI argument, with no check that the two match. Any EVM contract can therefore drain another account's `evm/<callerContract>` balance without that account's authorization.

### Finding Description
In `BankContract.Run`, the `TransferMethodName` branch unpacks three arguments: `sender`, `recipient`, `amount`. [1](#0-0) 

`from` is set to `sdk.AccAddress(sender.Bytes())` — fully attacker-controlled — while the denom is fixed to `EVMDenom(contract.Caller())`. [2](#0-1) 

`SendCoins(ctx, from, to, ...)` is then called with no check that `from` equals the calling contract's address. [3](#0-2) 

The `exec` helper in `utils.go` shows the correct pattern — it explicitly rejects calls where the message signer differs from `e.caller` — but that guard is never applied to the `transfer` branch. [4](#0-3) 

### Impact Explanation
**Critical — Unauthorized token transfer.**

An attacker contract controls the denom namespace `evm/<attackerContract>`. Any address that legitimately holds tokens in that namespace (received via `mint`, DEX trade, airdrop, etc.) can have their entire balance drained to an arbitrary recipient by a single precompile call, with no signature or approval from the victim.

### Likelihood Explanation
The attack requires no special privilege: any deployed EVM contract can call the bank precompile at address `0x0000…0064`. The only precondition is that the victim holds a non-zero balance of `evm/<attackerContract>` tokens, which the attacker can arrange by minting to the victim first.

### Recommendation
Add an authorization check immediately after unpacking arguments in the `TransferMethodName` branch:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the caller")
}
```

This mirrors the invariant already enforced in `utils.go` (`exec`) for other precompile paths.

### Proof of Concept

1. **Attacker deploys** contract `A` (address `0xATK`).
2. **Attacker calls** `bank.mint(victimAddr, 1000)` from `A` → victim receives `1000 evm/0xATK`.
3. **Attacker calls** `bank.transfer(victimAddr, attackerEOA, 1000)` from `A`.
   - `denom = evm/0xATK` (from `contract.Caller()`)
   - `from = victimAddr` (from arg 0, no check)
   - `SendCoins(victim → attackerEOA, 1000 evm/0xATK)` executes successfully.
4. **Assert**: victim balance of `evm/0xATK` = 0; attacker balance = 1000. No victim signature was ever required.

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L175-181)
```go
		sender := args[0].(common.Address)
		recipient := args[1].(common.Address)
		amount := args[2].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		from := sdk.AccAddress(sender.Bytes())
```

**File:** x/cronos/keeper/precompiles/bank.go (L186-194)
```go
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
				return errorsmod.Wrap(err, "fail to send coins in precompiled contract")
			}
```

**File:** x/cronos/keeper/precompiles/utils.go (L46-49)
```go
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```
