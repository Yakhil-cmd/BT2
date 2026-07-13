### Title
Bank Precompile `transfer` Accepts Arbitrary Sender — Unauthorized Native Token Transfer from Any Holder - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary

The `BankContract` precompile's `transfer` method accepts the `sender` address as a caller-supplied argument and performs no check that `sender == contract.Caller()`. Any EVM contract can therefore drain native `evm/<contract>` denom tokens from any address that holds them, without the holder's authorization.

### Finding Description

The bank precompile at `x/cronos/keeper/precompiles/bank.go` exposes four methods: `mint`, `burn`, `balanceOf`, and `transfer`. The denom managed by a calling contract is correctly scoped to `evm/<contract.Caller()>`:

```go
denom := EVMDenom(contract.Caller())
``` [1](#0-0) 

For `mint`, this is fine — the contract mints its own denom to a recipient. But for `transfer`, the `sender` (the address funds are moved **from**) is taken directly from the ABI-decoded call arguments, not from `contract.Caller()`:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
...
if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
``` [2](#0-1) 

There is no check that `sender == contract.Caller()` or that the holder has approved the transfer. The only guard present is a blocked-address check on the **recipient**, not on the sender's authorization: [3](#0-2) 

The same root cause exists in the `burn` path: the address to burn **from** is the caller-supplied `recipient` argument (confusingly named), not `contract.Caller()`: [4](#0-3) 

### Impact Explanation

**Critical — Unauthorized transfer of precompile-controlled native assets.**

Any contract can call `bank.transfer(victim, attacker, amount)` and move `evm/<contract_address>` denom tokens out of `victim`'s account without their consent. The Cosmos SDK `bankKeeper.SendCoins` call executes unconditionally once the precompile accepts the arguments.

This matches the Critical impact category: *unauthorized transfer of precompile-controlled assets*.

### Likelihood Explanation

The bank precompile is a live, callable EVM precompile at address `0x0000000000000000000000000000000000000064`. Any deployed contract can call it. A realistic attack path:

1. Attacker deploys a contract that offers yield or token functionality, causing users to hold `evm/<attacker_contract>` native tokens (e.g., via `bank.mint`).
2. Attacker calls `bank.transfer(victim, attacker, balance)` from the same contract.
3. All victim balances of that denom are drained with no approval required.

Additionally, any legitimate contract whose users hold its native denom is at risk if the contract owner turns malicious or if the contract itself has a function that forwards a caller-controlled `sender` argument to the bank precompile.

### Recommendation

In the `transfer` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    if sender != contract.Caller() {
        return nil, errors.New("sender must be the caller")
    }
    ...
```

Similarly, in the `burn` case, enforce that the address being burned from equals `contract.Caller()`, or remove the address argument entirely and always burn from `contract.Caller()`.

### Proof of Concept

1. Attacker deploys `MaliciousToken` contract. Users call `bank.mint(user, 1000)` from it, receiving 1000 `evm/<MaliciousToken>` native tokens.
2. Attacker calls the following from `MaliciousToken`:
   ```solidity
   IBankModule(0x64).transfer(victimAddress, attackerAddress, 1000);
   ```
3. The bank precompile executes `bankKeeper.SendCoins(victim, attacker, 1000 evm/<MaliciousToken>)` with no authorization check.
4. Victim's native token balance is zero; attacker holds 1000 tokens.

The attacker transferred native tokens from the victim without any signature, approval, or ownership proof — an exact structural analog to the fee-tier spoofing bug where the wrong key was checked, allowing privilege escalation without owning the required asset. [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L121-148)
```go
		recipient := args[0].(common.Address)
		amount := args[1].(*big.Int)
		if amount.Sign() <= 0 {
			return nil, errors.New("invalid amount")
		}
		addr := sdk.AccAddress(recipient.Bytes())
		if err := bc.checkBlockedAddr(addr); err != nil {
			return nil, err
		}
		denom := EVMDenom(contract.Caller())
		amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
		err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
			if method.Name == "mint" {
				if err := bc.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to mint coins in precompiled contract")
				}
				if err := bc.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send mint coins to account")
				}
			} else {
				if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send burn coins to module")
				}
				if err := bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to burn coins in precompiled contract")
```

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
