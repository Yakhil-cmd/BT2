### Title
Unauthorized Transfer and Burn of `evm/` Denom Tokens via Bank Precompile `transfer` and `burn` Without Caller Authorization - (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `BankContract` precompile at `0x0000000000000000000000000000000000000064` exposes `transfer(sender, recipient, amount)` and `burn(addr, amount)` methods. Both methods accept an arbitrary address as the source of funds but never verify that `contract.Caller()` equals that address. Any smart contract can therefore drain or destroy `evm/<callerContract>` native bank tokens held by any victim without the victim's consent.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles three mutating methods. For `transfer`:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
// ...
from := sdk.AccAddress(sender.Bytes())
// ...
denom := EVMDenom(contract.Caller())
// ...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

The `sender` address is taken directly from the ABI-decoded calldata. There is no check that `sender == contract.Caller()`. The denom is scoped to `contract.Caller()` (i.e., `evm/<callerContractAddress>`), so the calling contract is the issuer of those tokens — but it can freely move them from **any** holder to **any** recipient.

The same flaw exists in the `burn` branch:

```go
recipient := args[0].(common.Address)   // misleadingly named; this is the address to burn FROM
// ...
addr := sdk.AccAddress(recipient.Bytes())
// ...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt))
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt))
```

Again, `addr` is caller-supplied and never validated against `contract.Caller()`.

The `mint` method is intentionally unrestricted (the contract is the issuer), but `transfer` and `burn` must enforce that the source address has authorized the operation.

### Impact Explanation
Any contract that has previously minted `evm/<contractAddress>` tokens to users can, at any time and without user consent:
- Call `bank.transfer(victimAddress, attackerAddress, balance)` to steal all of a victim's holdings of that denom.
- Call `bank.burn(victimAddress, balance)` to destroy a victim's holdings.

These are native Cosmos bank module tokens (`evm/` denom) managed exclusively by the precompile. There is no ERC20 `approve`/`allowance` mechanism protecting them. The impact is **Critical**: unauthorized transfer and burn of precompile-controlled assets.

### Likelihood Explanation
Any unprivileged user can deploy a contract and call the bank precompile directly. The only precondition is that victims hold `evm/<attackerContract>` tokens — a realistic scenario for any DeFi protocol built on top of the bank precompile (e.g., a contract that issues `evm/` denom tokens as receipts or LP shares). The attacker controls the issuing contract and can execute the drain at any time.

### Recommendation
In the `transfer` case, enforce that the `sender` argument equals `contract.Caller()`:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be caller")
}
```

In the `burn` case, enforce that the address being burned from equals `contract.Caller()`:

```go
if recipient != contract.Caller() {
    return nil, errors.New("burn: can only burn from caller")
}
```

If the design intent is to allow a contract to burn tokens from arbitrary holders (e.g., for redemption flows), an explicit on-chain allowance mechanism must be introduced before permitting third-party burns.

### Proof of Concept

1. Attacker deploys `DrainContract` at address `0xATK`.
2. `DrainContract` calls `bank.mint(victim, 1000)` — victim now holds 1000 `evm/0xATK` tokens (e.g., as part of a yield protocol).
3. Attacker calls `DrainContract.drain(victim, attacker)`, which internally calls:
   ```solidity
   IBankModule(0x64).transfer(victim, attacker, 1000);
   ```
4. `BankContract.Run` decodes `sender = victim`, `recipient = attacker`, `denom = "evm/0xATK"`.
5. No caller check is performed. `bankKeeper.SendCoins(victim → attacker, 1000 evm/0xATK)` executes.
6. Victim's 1000 `evm/0xATK` tokens are transferred to the attacker without any approval.

The same flow with `bank.burn(victim, 1000)` destroys the victim's balance entirely. [1](#0-0) [2](#0-1) [3](#0-2)

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
