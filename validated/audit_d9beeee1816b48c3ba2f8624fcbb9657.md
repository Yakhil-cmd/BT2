### Title
Bank Precompile `transfer` Lacks Caller-Sender Authorization — (`x/cronos/keeper/precompiles/bank.go`)

### Summary
The bank precompile's `transfer` method accepts an arbitrary `sender` address as a user-supplied argument and calls `bankKeeper.SendCoins(ctx, from, to, ...)` with no check that the calling EVM contract is authorized to spend from `sender`. Any EVM contract can drain any holder's `evm/<callerAddress>` native-bank tokens without the holder's consent.

### Finding Description
In `bank.go`, the `TransferMethodName` case unpacks three arguments — `sender`, `recipient`, `amount` — and derives the denom from `contract.Caller()`:

```go
sender := args[0].(common.Address)
recipient := args[1].(common.Address)
amount := args[2].(*big.Int)
...
from := sdk.AccAddress(sender.Bytes())
to   := sdk.AccAddress(recipient.Bytes())
...
denom := EVMDenom(contract.Caller())          // "evm/<callerAddress>"
amt   := sdk.NewCoin(denom, ...)
...
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [1](#0-0) 

There is no guard of the form `require sender == contract.Caller()` and no ERC-20-style allowance check. The only validation is that `amount > 0` and the recipient is not a blocked address. [1](#0-0) 

The `mint` path, by contrast, always credits `recipient` from the module account — the caller cannot choose an arbitrary debit source there. The `transfer` path uniquely breaks this invariant by accepting a caller-supplied `from` address. [2](#0-1) 

This is the direct Cronos analog to the external report's `onlyPermit` / `isAuthorized` over-permission pattern: just as the Fuji `owner` could call `updateState()` / `mint` / `burn` on behalf of vaults it should not control, here the calling EVM contract can move tokens out of any holder's account for the contract's own denom — a role that should belong exclusively to the token holder.

### Impact Explanation
**Critical — Unauthorized transfer of precompile-controlled assets.**

`evm/<contractAddress>` tokens are native Cosmos bank-module coins managed entirely through the bank precompile. Any EVM contract that has previously minted these tokens to users can, at any later time, call `transfer(victimAddress, attackerAddress, fullBalance)` and atomically drain every holder's balance. No victim signature, approval, or interaction is required at drain time.

### Likelihood Explanation
The attack is fully unprivileged: deploying an EVM contract on Cronos requires no special permission. The attacker controls both the `mint` step (building up victim balances) and the `transfer` step (draining them). The precompile is live and callable from any EVM transaction.

### Recommendation
Add an authorization check inside the `TransferMethodName` case so that the calling contract may only debit its own address:

```go
if sender != contract.Caller() {
    return nil, errors.New("transfer: caller is not the sender")
}
```

Alternatively, implement an on-chain allowance mapping (analogous to ERC-20 `approve`/`transferFrom`) so that a contract may debit a third-party address only after that address has explicitly approved the amount.

### Proof of Concept
1. Attacker deploys `MaliciousToken` at address `0xA`.
2. `MaliciousToken` calls `bank.mint(victim, 1_000_000)` — victim now holds `1_000_000 evm/0xA` native coins.
3. At any later block, `MaliciousToken` calls `bank.transfer(victim, attacker, 1_000_000)`.
4. `bank.go` sets `denom = "evm/0xA"`, `from = victim`, `to = attacker`, and executes `bankKeeper.SendCoins` — victim's entire balance is transferred with no victim authorization. [1](#0-0)

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
