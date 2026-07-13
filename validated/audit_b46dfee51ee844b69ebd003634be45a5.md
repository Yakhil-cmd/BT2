### Title
Unauthorized Token Transfer via Missing Caller Authorization in Bank Precompile `transfer` Method - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method of the bank precompile (`BankContract.Run`) accepts an arbitrary `sender` address as an ABI-decoded input argument and directly calls `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that `contract.Caller()` equals `sender`. Any EVM contract can invoke this precompile with a victim's address as `sender` and the attacker's address as `recipient`, draining the victim's entire native bank balance of the denom `"evm/" + attacker_contract_address`.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles the `TransferMethodName` case as follows:

```go
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    ...
    sender    := args[0].(common.Address)   // ← arbitrary, caller-supplied
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
    from  := sdk.AccAddress(sender.Bytes())
    to    := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())    // "evm/" + calling contract address
    amt   := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
    err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
        ...
        bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)) // ← from is arbitrary
        ...
    })
```

There is no guard of the form `if contract.Caller() != sender { return error }`. The only check performed is `checkBlockedAddr(to)`, which only prevents sending to module-blocked addresses.

The same structural flaw exists in the `BurnMethodName` branch: `recipient` (args[0]) is the address whose tokens are burned via `SendCoinsFromAccountToModule(ctx, addr, ...)`, again without verifying `contract.Caller() == recipient`.

### Impact Explanation

**Critical — Unauthorized transfer of EVM-denominated native bank assets.**

The denom is `"evm/" + contract.Caller().Hex()`. A contract at address `0xATTACKER` controls the denom `evm/0xATTACKER`. Any user who holds a balance of that denom (e.g., because the attacker's contract previously called `bank.mint(victim, amount)` to distribute tokens) is fully exposed. The attacker calls:

```
bankPrecompile.transfer(victim_address, attacker_address, victim_balance)
```

from `MaliciousContract`, and `bankKeeper.SendCoins` executes the transfer unconditionally. The victim's entire `evm/0xATTACKER` balance is moved to the attacker with no signature or approval from the victim.

### Likelihood Explanation

The bank precompile at address `0x0000000000000000000000000000000000000064` is reachable by any deployed EVM contract with a single `CALL` opcode. No special privilege, governance action, or key material is required. Any contract that has ever minted `evm/<contract>` tokens to users can immediately exploit this to reclaim (steal) those tokens. The attack is atomic within a single transaction and requires no front-running.

### Recommendation

Add a caller-authorization check at the top of the `TransferMethodName` case (and symmetrically for `BurnMethodName`) before executing the state change:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    // Enforce that only the token-contract itself may initiate a transfer
    // on behalf of a given sender address.
    if contract.Caller() != sender {
        return nil, errors.New("caller is not authorized to transfer on behalf of sender")
    }
    ...
```

For `burn`, the analogous guard is `contract.Caller() != recipient` (the address being burned from).

### Proof of Concept

1. Attacker deploys `MaliciousContract` at `0xATTACKER`.
2. `MaliciousContract` calls `bank.mint(victim, 1_000_000)` — this credits `1_000_000 evm/0xATTACKER` to the victim's native bank account.
3. Later, `MaliciousContract` calls `bank.transfer(victim, attacker_EOA, 1_000_000)` on the bank precompile (`0x64`).
4. Inside `BankContract.Run`, `sender = victim`, `from = sdk.AccAddress(victim)`, `denom = "evm/0xATTACKER"`. No authorization check fires.
5. `bankKeeper.SendCoins(ctx, victim, attacker_EOA, 1_000_000 evm/0xATTACKER)` executes successfully.
6. Victim's balance drops to 0; attacker's balance increases by `1_000_000 evm/0xATTACKER`. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L113-156)
```go
	case MintMethodName, BurnMethodName:
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
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
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return method.Outputs.Pack(true)
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
