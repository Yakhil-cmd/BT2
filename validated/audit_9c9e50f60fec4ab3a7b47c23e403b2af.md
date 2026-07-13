### Title
Unauthorized Native Token Transfer/Burn via Bank Precompile `transfer` and `burn` Methods - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `BankContract` precompile's `transfer` and `burn` methods accept an arbitrary `sender`/`recipient` address from calldata and act on that address's native `evm/<caller>` token balance without verifying that the EVM caller (`contract.Caller()`) is authorized to act on behalf of that address. Any EVM contract can drain or destroy another account's native `evm/` denom tokens without consent.

### Finding Description

In `x/cronos/keeper/precompiles/bank.go`, the `Run` function handles two state-mutating methods:

**`burn` (lines 113–156):** The address to burn from is taken directly from calldata as `args[0]` (`recipient`). There is no check that this address equals `contract.Caller()`.

```go
recipient := args[0].(common.Address)   // arbitrary address from calldata
...
addr := sdk.AccAddress(recipient.Bytes())
...
// burns from addr, not from contract.Caller()
bc.bankKeeper.SendCoinsFromAccountToModule(ctx, addr, types.ModuleName, ...)
bc.bankKeeper.BurnCoins(ctx, types.ModuleName, ...)
``` [1](#0-0) 

**`transfer` (lines 167–200):** The `sender` address is taken from calldata as `args[0]`. There is no check that `sender == contract.Caller()`.

```go
sender := args[0].(common.Address)   // arbitrary address from calldata
...
from := sdk.AccAddress(sender.Bytes())
...
// transfers from `from`, not from contract.Caller()
bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
``` [2](#0-1) 

The denom operated on is `evm/<contract.Caller()>` — the native Cosmos bank representation of the EVM token issued by the calling contract. [3](#0-2) 

### Impact Explanation

**Critical — Unauthorized transfer/burn of precompile-controlled assets.**

Any EVM contract can call `bankPrecompile.transfer(victimAddress, attackerAddress, amount)` or `bankPrecompile.burn(victimAddress, amount)`. The precompile will execute `bankKeeper.SendCoins` or `bankKeeper.SendCoinsFromAccountToModule` using the victim's Cosmos address as the source, moving or destroying the victim's `evm/<callerContract>` native tokens without any authorization from the victim. This is a direct unauthorized balance change for precompile-controlled assets.

### Likelihood Explanation

Any unprivileged EVM contract can reach this path. No special permissions, leaked keys, or admin access are required. The only precondition is that the victim holds `evm/<attackerContract>` tokens — a realistic scenario for any token contract that has minted native-side balances via `bank.mint()`.

### Recommendation

In both the `burn` and `transfer` cases, verify that the address being acted upon is the EVM caller itself:

- For `burn`: require `recipient == contract.Caller()`, i.e., a contract may only burn its own (the caller's) native tokens.
- For `transfer`: require `sender == contract.Caller()`, i.e., a contract may only transfer tokens from its own address.

```go
// In burn case:
if recipient != contract.Caller() {
    return nil, errors.New("burn: caller is not the token owner")
}

// In transfer case:
if sender != contract.Caller() {
    return nil, errors.New("transfer: caller is not the sender")
}
```

### Proof of Concept

1. Attacker deploys malicious EVM contract `M` on Cronos.
2. Victim interacts with `M` and accumulates `evm/<M>` native bank tokens (e.g., via `M` calling `bankPrecompile.mint(victimAddress, 1000)`).
3. Attacker calls a function on `M` that executes:
   ```solidity
   IBankModule(0x0000000000000000000000000000000000000064)
       .transfer(victimAddress, attackerAddress, 1000);
   ```
4. The bank precompile receives the call with `contract.Caller() == address(M)`, computes denom `evm/<M>`, and calls `bankKeeper.SendCoins(ctx, victimCosmosAddr, attackerCosmosAddr, coins)` — no authorization check is performed.
5. Victim's 1000 `evm/<M>` tokens are transferred to the attacker's Cosmos address without the victim's consent.

The same path applies to `burn`: replace step 3 with `bank.burn(victimAddress, 1000)` to destroy the victim's tokens. [4](#0-3)

### Citations

**File:** x/cronos/keeper/precompiles/bank.go (L103-204)
```go
func (bc *BankContract) Run(evm *vm.EVM, contract *vm.Contract, readonly bool) ([]byte, error) {
	// parse input
	methodID := contract.Input[:4]
	method, err := bankABI.MethodById(methodID)
	if err != nil {
		return nil, err
	}
	stateDB := evm.StateDB.(ExtStateDB)
	precompileAddr := bc.Address()
	switch method.Name {
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
	case BalanceOfMethodName:
		args, err := method.Inputs.Unpack(contract.Input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		token := args[0].(common.Address)
		addr := args[1].(common.Address)
		// query from storage
		balance := bc.bankKeeper.GetBalance(stateDB.Context(), sdk.AccAddress(addr.Bytes()), EVMDenom(token)).Amount.BigInt()
		return method.Outputs.Pack(balance)
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
	default:
		return nil, errors.New("unknown method")
	}
}
```
