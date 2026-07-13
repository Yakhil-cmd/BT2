### Title
Unauthorized Token Transfer via Unvalidated `sender` Argument in Bank Precompile `transfer` Method - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `transfer` method in the bank precompile accepts an arbitrary `sender` address as a call argument without validating it against the calling contract address. Any contract can transfer `evm/0x{contractAddress}`-denominated native tokens from any holder's account to any destination without the holder's consent.

### Finding Description
In `x/cronos/keeper/precompiles/bank.go`, the `TransferMethodName` case in `Run()` unpacks `sender` directly from the ABI-encoded call arguments and uses it as the `from` address in `bankKeeper.SendCoins`:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to := sdk.AccAddress(recipient.Bytes())
if err := bc.checkBlockedAddr(to); err != nil {   // only `to` is checked
    return nil, err
}
denom := EVMDenom(contract.Caller())              // denom tied to calling contract
amt := sdk.NewCoin(denom, sdkmath.NewIntFromBigInt(amount))
err = stateDB.ExecuteNativeAction(precompileAddr, nil, func(ctx sdk.Context) error {
    ...
    if err := bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt)); err != nil {
``` [1](#0-0) 

There is no check that `sender == contract.Caller()`, no allowance mechanism, and no validation that the `from` address has authorized the transfer. The denom is `evm/0x{callerAddress}`, so the contract can only move tokens of its own denom — but it can do so from **any** address that holds those tokens.

By contrast, the `mint` and `burn` cases operate on a caller-supplied `recipient` address but the economic action (minting/burning) is always attributed to the module, not to an arbitrary third-party account. Only `transfer` silently promotes an untrusted argument to the role of fund source. [2](#0-1) 

### Impact Explanation
A malicious contract can execute a two-step rug-pull against any holder of its denom:

1. **Seed victims** — call `bank.mint(victimAddress, N)` to distribute `evm/0x{maliciousContract}` tokens to users (e.g., as a yield reward or airdrop).
2. **Drain victims** — call `bank.transfer(victimAddress, attackerAddress, N)` in a single transaction to move all tokens out of the victim's account without any approval.

This is an unauthorized transfer of precompile-controlled assets, matching the Critical impact tier: *"Unauthorized … transfer … for … precompile-controlled assets."*

### Likelihood Explanation
The attack requires no special privilege. Any unprivileged user can deploy a contract and call the bank precompile. The two-step attack is executable in a single block after token distribution. No key leakage, governance action, or validator compromise is needed.

### Recommendation
Enforce that the `sender` argument equals `contract.Caller()` before executing the transfer, mirroring the authorization model of ERC-20:

```go
case TransferMethodName:
    ...
    if sender != contract.Caller() {
        return nil, errors.New("transfer: sender must be the calling contract")
    }
```

Alternatively, implement an on-chain allowance table so that token holders can explicitly approve third-party transfers, consistent with the ERC-20 `approve`/`transferFrom` pattern.

### Proof of Concept

```
1. Attacker deploys MaliciousContract at 0xDEAD.
2. MaliciousContract calls bank.mint(victim, 1_000_000)
   → victim now holds 1_000_000 evm/0xDEAD tokens.
3. MaliciousContract calls bank.transfer(victim, attacker, 1_000_000)
   → SendCoins(victim → attacker, evm/0xDEAD) executes with no victim consent.
   → victim balance: 0; attacker balance: 1_000_000 evm/0xDEAD.
```

No signature, allowance, or governance approval from the victim is required at any step.

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
