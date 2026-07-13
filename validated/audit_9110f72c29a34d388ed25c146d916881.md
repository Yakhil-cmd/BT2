### Title
Unauthorized Transfer and Burn of Native `evm/` Tokens via Arbitrary `sender` Parameter in Bank Precompile — (`File: x/cronos/keeper/precompiles/bank.go`)

### Summary

The `BankContract` precompile's `transfer` and `burn` methods accept an arbitrary address as the source/owner parameter and execute `bankKeeper.SendCoins` / `bankKeeper.SendCoinsFromAccountToModule` against that address without ever verifying that the EVM caller (`contract.Caller()`) is authorized to act on behalf of it. Any unprivileged EVM contract can drain or destroy another account's `evm/<contractAddress>` native tokens.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles two state-mutating methods:

**`transfer(sender, recipient, amount)`** — lines 167–200:

```go
sender := args[0].(common.Address)   // arbitrary, from calldata
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()`. Any EVM contract can supply an arbitrary victim address as `sender` and move that victim's `evm/<callerContract>` tokens to any destination.

**`burn(recipient, amount)`** — lines 113–156:

```go
recipient := args[0].(common.Address)  // arbitrary, from calldata
...
addr := sdk.AccAddress(recipient.Bytes())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

Again, no check that `recipient == contract.Caller()`. Any EVM contract can burn another account's `evm/<callerContract>` tokens without consent.

By contrast, the `relayer` and `ica` precompiles use the `exec` helper in `utils.go` which explicitly enforces `caller == signer`:

```go
if caller != e.caller {
    return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", ...)
}
```

The bank precompile has no equivalent guard.

### Impact Explanation

The denom operated on is `evm/<contract.Caller()>`. Any EVM contract that calls the bank precompile at address `0x0000000000000000000000000000000000000064` can:

1. **Steal** — call `transfer(victimAddr, attackerAddr, amount)` to move `evm/<maliciousContract>` tokens from victim to attacker.
2. **Destroy** — call `burn(victimAddr, amount)` to permanently destroy victim's `evm/<maliciousContract>` tokens.

These `evm/` denom tokens are real Cosmos bank module balances. They are minted by the same precompile's `mint` method and are the native representation of EVM-originated assets. Unauthorized transfer and burn of these assets is a **Critical** impact: unauthorized transfer/burn of precompile-controlled assets.

### Likelihood Explanation

The bank precompile is deployed at a fixed well-known address (`0x64`) and is callable by any EVM contract. No special privilege is required. An attacker deploys a contract, calls `bank.transfer(victim, attacker, amount)`, and the transfer executes unconditionally as long as the victim holds a non-zero balance of `evm/<attackerContract>`. Users accumulate such balances through normal `mint` interactions with the attacker's contract (e.g., a DeFi protocol that issues `evm/` tokens as receipts).

### Recommendation

Enforce that the `sender` argument in `transfer` and the `recipient` argument in `burn` must equal `contract.Caller()`. Concretely, add the following guard at the top of each case:

```go
// transfer case
if sender != contract.Caller() {
    return nil, errors.New("sender must be the caller")
}

// burn case
if recipient != contract.Caller() {
    return nil, errors.New("recipient must be the caller")
}
```

This mirrors the pattern already used in `utils.go` for the relayer and ICA precompiles.

### Proof of Concept

1. Victim calls `bank.mint(victimAddr, 1000)` from their own contract `VictimContract`, giving themselves 1000 `evm/VictimContract` tokens.
2. Attacker deploys `MaliciousContract` with a function:
   ```solidity
   function steal(address victim, address attacker, uint256 amount) external {
       // bank precompile at 0x64
       IBankModule(0x0000000000000000000000000000000000000064)
           .transfer(victim, attacker, amount);
   }
   ```
   But note: the denom is `evm/<MaliciousContract>`, not `evm/<VictimContract>`. So the attacker must target balances of `evm/<MaliciousContract>`.
3. More precisely: attacker deploys `MaliciousContract`, lures victim to call `bank.mint(victimAddr, 1000)` through `MaliciousContract` (e.g., as a staking receipt). Victim now holds 1000 `evm/MaliciousContract`.
4. Attacker calls `MaliciousContract.steal(victimAddr, attackerAddr, 1000)` → `bank.transfer(victimAddr, attackerAddr, 1000)` executes, moving 1000 `evm/MaliciousContract` from victim to attacker with no authorization check.

The `burn` variant is identical but calls `bank.burn(victimAddr, 1000)` to destroy the victim's balance. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** x/cronos/keeper/precompiles/utils.go (L38-49)
```go
	signers, _, err := e.cdc.GetMsgV1Signers(msg)
	if err != nil {
		return nil, fmt.Errorf("fail to get signers %w", err)
	}

	if len(signers) != 1 {
		return nil, errors.New("don't support multi-signers message")
	}
	caller := common.BytesToAddress(signers[0])
	if caller != e.caller {
		return nil, fmt.Errorf("caller is not authenticated: expected %s, got %s", e.caller.Hex(), caller.Hex())
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
