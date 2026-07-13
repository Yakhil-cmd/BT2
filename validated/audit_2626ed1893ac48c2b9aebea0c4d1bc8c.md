### Title
Missing Caller Authorization in Bank Precompile `transfer` Method Allows Unauthorized Native Token Drain - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts a user-supplied `sender` address and executes `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that `sender == contract.Caller()`. Any EVM contract can therefore transfer `evm/<contract_address>`-denominated native tokens from an arbitrary victim address to an attacker-controlled address with no authorization from the token holder.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` case of `BankContract.Run` unpacks three ABI arguments — `sender`, `recipient`, and `amount` — and immediately uses the caller-supplied `sender` as the `from` address in a native bank transfer:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())          // evm/<calling_contract>
amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no check of the form `sender == contract.Caller()`, no allowance lookup, and no signature verification. The only guard present is `checkBlockedAddr(to)`, which only prevents sending to module-blocked addresses. [2](#0-1) 

The denom is derived from `contract.Caller()` (the EVM address of the contract invoking the precompile), so the tokens at risk are the native Cosmos SDK coins denominated `evm/<calling_contract>`. These are the canonical native-layer representation of CRC20/CRC21 tokens managed through the bank precompile. [3](#0-2) 

### Impact Explanation
**Critical — Unauthorized transfer of CRC20/CRC21 native token balances.**

Any EVM contract that exposes a path where an attacker controls the `sender` argument passed to the bank precompile's `transfer` method can drain the victim's entire `evm/<contract>` native balance. Because the bank precompile is the authoritative minting/burning/transfer layer for all CRC20/CRC21 tokens whose native denom follows the `evm/` prefix, a successful exploit results in an unauthorized balance change for those assets — matching the Critical impact class (unauthorized transfer of CRC20/CRC21 assets).

### Likelihood Explanation
The bank precompile is the intended backend for CRC20/CRC21 contracts. Any such contract that implements a `transferFrom`-style function and forwards the caller-supplied `from` address directly to `bankPrecompile.transfer(from, to, amount)` without first verifying allowances is immediately exploitable. Because the bank precompile provides no safety net, the entire authorization burden falls on every contract that calls it, and a single contract that omits the allowance check exposes all its token holders.

### Recommendation
Add an explicit authorization check inside the `TransferMethodName` case before calling `bankKeeper.SendCoins`:

```go
// Enforce that only the calling contract may debit the sender,
// or implement an on-chain allowance table in the precompile.
if sender != contract.Caller() {
    return nil, errors.New("bank precompile: transfer sender must equal caller")
}
```

Alternatively, implement an ERC20-style allowance mapping inside the bank precompile so that `transferFrom`-style delegation is possible without removing the authorization check entirely.

### Proof of Concept

1. A legitimate CRC20 contract `0xLEGIT` is deployed and uses the bank precompile to manage `evm/0xLEGIT` tokens. Users accumulate balances of this denom.
2. `0xLEGIT` (or any contract the attacker can call) contains a function that forwards a caller-supplied `from` address to `bankPrecompile.transfer(from, attacker, balance)` — for example, a `transferFrom` that skips the allowance check.
3. The attacker calls that function with `from = victim`.
4. The bank precompile executes `bankKeeper.SendCoins(ctx, victim, attacker, {evm/0xLEGIT: balance})` with no authorization check.
5. The victim's entire `evm/0xLEGIT` native balance is transferred to the attacker in a single transaction.

The root cause — the missing `sender == contract.Caller()` guard — is located at: [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L167-200)
```go
	case TransferMethodName:
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
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
				return errorsmod.Wrap(err, "fail to send coins in precompiled contract")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return method.Outputs.Pack(true)
```
