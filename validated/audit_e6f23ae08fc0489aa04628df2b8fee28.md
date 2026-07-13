### Title
Unauthorized Token Transfer via Bank Precompile `transfer` Method — (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary
The `transfer` method of the `BankContract` precompile accepts an arbitrary `sender` address as a caller-supplied ABI argument and passes it directly to `bankKeeper.SendCoins` without verifying that the EVM caller (`contract.Caller()`) matches the specified sender. Any unprivileged EVM contract can therefore drain `evm/<attacker_contract>` denomination tokens from any victim address that holds them, with no authorization from the victim.

---

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles the `transfer` method as follows:

```go
sender    := args[0].(common.Address)   // fully attacker-controlled
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)

from  := sdk.AccAddress(sender.Bytes()) // derived from attacker input
to    := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())    // evm/<calling_contract_address>

bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no guard of the form `contract.Caller() == sender`. The `from` address used in `SendCoins` is taken entirely from the ABI-encoded input, not from the authenticated EVM caller. The only constraint is that the denomination is `evm/<contract.Caller()>`, meaning the tokens being moved are those of the calling contract's own denomination — but the *source account* is freely chosen by the attacker.

---

### Impact Explanation
**Critical — Unauthorized transfer of precompile-controlled assets.**

A malicious EVM contract `M` deployed at address `0xM` can call the bank precompile's `transfer(victim, attacker, amount)`. This moves `evm/0xM` tokens from `victim`'s bank account to `attacker`'s bank account. The victim never signed or authorized this transfer. Any user who holds a balance of `evm/0xM` (e.g., received via the `mint` method of the same contract, or via a CRC20 conversion flow that mints native bank coins under that denom) is fully exposed. The attacker can drain the entire balance in a single transaction.

---

### Likelihood Explanation
Any unprivileged EVM account can deploy a contract and immediately exploit this. No special role, leaked key, or governance action is required. The precompile is reachable from any EVM transaction. Likelihood is high wherever `evm/<denom>` balances exist for victim addresses.

---

### Recommendation
Enforce that the `sender` argument matches the authenticated EVM caller before executing the transfer:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the caller")
}
```

This mirrors the authorization model used by the `mint`/`burn` paths, where the denom is already scoped to `contract.Caller()` and no external address is accepted as the acting party.

---

### Proof of Concept

1. Deploy a malicious contract `Exploit` at address `0xEXPLOIT`.
2. Victim `0xVICTIM` holds a balance of `evm/0xEXPLOIT` tokens (e.g., previously minted by `Exploit` and sent to them, or received via any transfer).
3. `Exploit` calls the bank precompile at address `0x0000...0064` with:
   ```
   transfer(0xVICTIM, 0xATTACKER, victimBalance)
   ```
4. Inside `Run`, `sender = 0xVICTIM`, `denom = evm/0xEXPLOIT`, `from = sdk.AccAddress(0xVICTIM)`.
5. `bankKeeper.SendCoins(ctx, 0xVICTIM, 0xATTACKER, [{evm/0xEXPLOIT, victimBalance}])` executes successfully.
6. Victim's entire `evm/0xEXPLOIT` balance is transferred to the attacker with no signature or consent from the victim.

Relevant code: [1](#0-0)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L175-192)
```go
		sender := args[0].(common.Address)
		recipient := args[1].(common.Address)
		amount := args[2].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		from := sdk.AccAddress(sender.Bytes())
		to := sdk.AccAddress(recipient.Bytes())
		if err := bc.checkBlockedAddr(to); err != nil {
			return nil, err
		}
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
```
