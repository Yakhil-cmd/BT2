After a thorough review of the Cronos codebase, I found a valid analog vulnerability.

---

### Title
Missing Caller Authorization Check in Bank Precompile `transfer` and `burn` Methods — (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` and `burn` methods accept arbitrary `sender`/`recipient` addresses without verifying that the calling contract is authorized to move tokens from those addresses. Any EVM contract can drain or destroy `evm/<contract>` native bank-module tokens held by any address, without the token holder's consent.

### Finding Description

In `BankContract.Run()`, the `TransferMethodName` case unpacks `sender` and `recipient` from the ABI-encoded call arguments and directly invokes `bankKeeper.SendCoins`:

```go
// x/cronos/keeper/precompiles/bank.go  lines 175-192
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())          // "evm/<callerContract>"
amt   := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

`from` is an **attacker-controlled** value; there is no check that `sender == contract.Caller()` or that `sender` has approved the transfer. The same pattern applies to `BurnMethodName`, where `addr` (the address whose tokens are burned) is taken directly from the call argument with no authorization check:

```go
// x/cronos/keeper/precompiles/bank.go  lines 121-149
recipient := args[0].(common.Address)
...
addr := sdk.AccAddress(recipient.Bytes())
...
// burn path:
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)
``` [2](#0-1) 

The denom `evm/<callerContract>` is derived from `contract.Caller()`, so only contract `C` can manipulate `evm/C` tokens — but it can do so against **any** address that holds them.

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

Any EVM contract that uses the bank precompile can:
- Call `bank.transfer(victimAddress, attackerAddress, amount)` to drain `evm/<contract>` tokens from `victimAddress` to an attacker-controlled address.
- Call `bank.burn(victimAddress, amount)` to destroy `evm/<contract>` tokens held by `victimAddress`.

Both operations execute against the victim's bank-module balance without any consent or approval from the victim. This falls squarely within the allowed Critical impact: *"Unauthorized transfer, burn … for … precompile-controlled assets."*

### Likelihood Explanation

Any unprivileged user can deploy an EVM contract and call the bank precompile. The realistic attack surface is:
1. A legitimate DeFi protocol deploys contract `C` and mints `evm/C` tokens to users (LP tokens, reward tokens, collateral receipts).
2. The contract (or a malicious upgrade/reentrancy path) calls `bank.transfer(user, attacker, amount)` or `bank.burn(user, amount)`.
3. User funds are drained or destroyed with no on-chain authorization from the user.

No admin keys, governance votes, or cryptographic breaks are required. The entry path is a standard EVM call to the precompile at address `0x0000…0064`. [3](#0-2) 

### Recommendation

In `TransferMethodName`, add a guard before `SendCoins`:

```go
if sender != contract.Caller() {
    return nil, errors.New("bank precompile: transfer sender must be the calling contract")
}
```

In `BurnMethodName`, add a guard before `SendCoinsFromAccountToModule`:

```go
if recipient != contract.Caller() {
    return nil, errors.New("bank precompile: burn target must be the calling contract")
}
```

This restricts each contract to moving only tokens it directly holds, matching the authorization model users expect.

### Proof of Concept

1. Attacker deploys contract `C` (unprivileged).
2. `C` calls `bank.mint(victimAddress, 1000)` — victim now holds 1000 `evm/C` tokens.
3. `C` calls `bank.transfer(victimAddress, attackerAddress, 1000)`.
4. `BankContract.Run` executes `bankKeeper.SendCoins(ctx, victimAddr, attackerAddr, [{denom:"evm/C", amount:1000}])` with no authorization check.
5. Victim's 1000 `evm/C` tokens are transferred to the attacker without the victim's consent.

The same steps apply to `bank.burn(victimAddress, 1000)`, which destroys the victim's tokens outright.

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L32-33)
```go
	bankContractAddress     = common.BytesToAddress([]byte{100})
	bankGasRequiredByMethod = map[[4]byte]uint64{}
```

**File:** x/cronos/keeper/precompiles/bank.go (L121-152)
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
```

**File:** x/cronos/keeper/precompiles/bank.go (L175-196)
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
				return errorsmod.Wrap(err, "fail to send coins in precompiled contract")
			}
			return nil
		})
```
