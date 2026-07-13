### Title
Bank Precompile `transfer` and `burn` Methods Allow Unauthorized Native Token Drain from Arbitrary User Accounts - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract.Run()` precompile in `x/cronos/keeper/precompiles/bank.go` handles `transfer(address sender, address recipient, uint256 amount)` and `burn(address addr, uint256 amount)` without verifying that the `sender`/`addr` argument equals `contract.Caller()`. Any unprivileged EVM contract can therefore transfer or burn `evm/<callerContract>` native tokens from any user's account without that user's consent.

### Finding Description

In `BankContract.Run()`, the `TransferMethodName` case decodes `sender` directly from calldata and passes it as the `from` address to `bankKeeper.SendCoins`:

```go
// x/cronos/keeper/precompiles/bank.go L175-L192
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
// ...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
// ...
denom := EVMDenom(contract.Caller())
// ...
if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
```

There is **no check** that `sender == contract.Caller()`. The denom is correctly scoped to `evm/<callerContract>`, but the `from` account is fully attacker-controlled.

The same flaw exists in the `BurnMethodName` branch: `recipient` (the address whose tokens are burned) is taken from calldata without verifying it equals `contract.Caller()`:

```go
// x/cronos/keeper/precompiles/bank.go L121-L144
recipient := args[0].(common.Address)
// ...
addr := sdk.AccAddress(recipient.Bytes())
// ...
if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt)); err != nil {
```

By contrast, the other precompile path in `utils.go` (`exec()`) correctly enforces `caller == signer`:

```go
// x/cronos/keeper/precompiles/utils.go L46-L48
caller := common.BytesToAddress(signers[0])
if caller != e.caller {
    return nil, fmt.Errorf("caller is not authenticated: ...")
```

The bank precompile's `transfer` and `burn` paths have no equivalent guard.

### Impact Explanation

**Critical** — Unauthorized transfer and burn of `evm/<contract>` native tokens.

`evm/<contractAddress>` tokens are real Cosmos bank module native tokens. They are minted when a contract calls `bank.mint(userAddr, amount)` and represent real value held by users. Any contract that has issued such tokens to users can, in the same transaction or a later one, call `bank.transfer(victimAddr, attackerAddr, balance)` or `bank.burn(victimAddr, balance)` to drain or destroy those tokens from any holder without their authorization.

This matches the Critical impact class: *Unauthorized transfer or balance/accounting change for precompile-controlled assets*.

### Likelihood Explanation

**High.** The entry path requires only deploying an EVM contract and calling the bank precompile at `0x0000000000000000000000000000000000000064`. No privileged keys, governance access, or leaked secrets are needed. Any user who holds `evm/<contractAddress>` tokens — obtained through normal interaction with a contract that uses the bank precompile — is exposed to the full balance being drained by that contract at any time.

### Recommendation

In the `TransferMethodName` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("sender must be the calling contract")
}
```

In the `BurnMethodName` case, enforce that the `recipient` (burn target) equals `contract.Caller()`:

```go
if recipient != contract.Caller() {
    return nil, errors.New("burn target must be the calling contract")
}
```

This mirrors the authorization model already used in `utils.go` (`exec()`) and in the CRC20/CRC21 contracts (`require(msg.sender == module_address)`).

### Proof of Concept

1. Attacker deploys `MaliciousContract` at address `0xATK`.
2. Users legitimately receive `evm/0xATK` native tokens (e.g., via `bank.mint` called from `0xATK`).
3. `MaliciousContract` executes:
   ```solidity
   IBankModule bank = IBankModule(0x0000000000000000000000000000000000000064);
   // drain victim's evm/0xATK tokens to attacker
   bank.transfer(victimAddress, attackerAddress, victimBalance);
   ```
4. `BankContract.Run()` decodes `sender = victimAddress`, `denom = evm/0xATK`, and calls `bankKeeper.SendCoins(ctx, victimAddress, attackerAddress, coins)` — no authorization check is performed.
5. All `evm/0xATK` tokens are transferred from the victim to the attacker without the victim's consent.

The same flow applies to `bank.burn(victimAddress, victimBalance)` to permanently destroy victim tokens. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** x/cronos/keeper/precompiles/utils.go (L46-49)
```go
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
