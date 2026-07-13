### Title
Arbitrary `sender` in Bank Precompile `transfer` Enables Unauthorized Native Token Drain — (`File: x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `transfer` method of the Cronos bank precompile (address `0x64`) accepts the `sender` address as a **caller-supplied calldata argument** and passes it directly to `bankKeeper.SendCoins` as the `from` address, with no check that it equals `contract.Caller()`. Any EVM contract can therefore drain any account's native `evm/<callerContract>` tokens by specifying an arbitrary victim as the sender.

---

### Finding Description

In `BankContract.Run`, the `TransferMethodName` branch unpacks `sender` from `args[0]` (calldata) and constructs `from` from it:

```go
sender := args[0].(common.Address)   // ← arbitrary, from calldata
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())  // "evm/" + callerContractAddress
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

`contract.Caller()` is used only to derive the **denom**, not to authenticate the sender. There is no guard of the form `sender == contract.Caller()` and no allowance/approval mechanism. The Cosmos SDK `SendCoins` call moves tokens from `from` (victim) to `to` (attacker) unconditionally.

The same structural flaw exists in the `BurnMethodName` branch, where `recipient` (the address to burn from) is also taken from calldata without verifying the caller is authorized to burn on behalf of that address:

```go
recipient := args[0].(common.Address)  // arbitrary burn target
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
bc.bankKeeper.BurnCoins(...)
``` [2](#0-1) 

The bank precompile is a registered production precompile at address `0x64`, callable by any EVM contract: [3](#0-2) 

The `IBankModule` interface exposes `transfer(address,address,uint256)` as a payable external function with no access restriction: [4](#0-3) 

---

### Impact Explanation

**Critical — Unauthorized transfer of native `evm/<contract>` assets.**

`evm/<callerContract>` is the Cosmos-native denom minted by the bank precompile's `mint` method. Any account that holds such tokens (e.g., after calling `mint` from a contract) can have those tokens drained by the same contract calling `transfer(victimAddr, attackerAddr, amount)`. The attacker controls both the calling contract and the calldata, so they fully control `from`, `to`, and `amount`. No victim consent or signature is required.

---

### Likelihood Explanation

**Medium.** The victim must hold native `evm/<attackerContract>` tokens. This is a realistic precondition: the bank precompile's `mint` function is the intended mechanism for contracts to issue native tokens to users, and any user who has minted such tokens is immediately vulnerable to the issuing contract draining them via `transfer`. A malicious or compromised contract operator can exploit this at any time after users have minted.

---

### Recommendation

In the `TransferMethodName` branch, enforce that the `sender` argument equals the EVM caller:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the caller")
}
```

Alternatively, implement an ERC20-style allowance mechanism so that a contract can only transfer tokens on behalf of an address that has explicitly approved it. Apply the same fix to the `BurnMethodName` branch for the burn-target address. [5](#0-4) 

---

### Proof of Concept

1. Attacker deploys `MaliciousToken` contract at address `0xABC`.
2. Victim calls `IBankModule(0x64).mint(victimAddr, 1000)` from `MaliciousToken` (or the contract does it on their behalf during onboarding). Victim now holds 1000 `evm/0xABC` native tokens.
3. Attacker calls a function on `MaliciousToken` that executes:
   ```solidity
   IBankModule(0x0000000000000000000000000000000000000064)
       .transfer(victimAddr, attackerAddr, 1000);
   ```
4. The bank precompile resolves `denom = "evm/0xABC"`, `from = victimAddr`, `to = attackerAddr`, and calls `bankKeeper.SendCoins(ctx, victimAddr, attackerAddr, 1000 evm/0xABC)`.
5. Victim's 1000 `evm/0xABC` tokens are transferred to the attacker with no victim authorization.

The same call pattern with `burn(victimAddr, 1000)` destroys the victim's tokens outright. [6](#0-5)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

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
