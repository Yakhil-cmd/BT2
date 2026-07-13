### Title
Missing Sender Authorization in Bank Precompile `transfer` Allows Unconditional Drain of Any Token Holder - (File: `x/cronos/keeper/precompiles/bank.go`)

### Summary
The `transfer` method in `BankContract.Run()` accepts an arbitrary `sender` address from ABI-decoded calldata without verifying it equals `contract.Caller()`. Any EVM contract can transfer `evm/<callerAddress>` native-bank tokens out of any holder's account without that holder's consent, enabling a complete rug-pull of all holders of the calling contract's denom.

### Finding Description
In `BankContract.Run()`, the `transfer` branch decodes `sender` directly from the ABI input and passes it as the `from` address to `bankKeeper.SendCoins`:

```go
// x/cronos/keeper/precompiles/bank.go  L167-L200
case TransferMethodName:
    ...
    sender    := args[0].(common.Address)   // ← user-supplied, never validated
    recipient := args[1].(common.Address)
    amount    := args[2].(*big.Int)
    ...
    from := sdk.AccAddress(sender.Bytes())  // ← arbitrary address
    to   := sdk.AccAddress(recipient.Bytes())
    ...
    denom := EVMDenom(contract.Caller())    // evm/<callerAddress>
    ...
    bc.bankKeeper.SendCoins(ctx, from, to, sdk.NewCoins(amt))
```

There is no check that `sender == contract.Caller()` and no allowance/approval mechanism. The denom is scoped to `evm/<callerAddress>`, so the calling contract has unconditional authority to move tokens out of **any** account that holds that denom. The `mint` and `burn` branches share the same pattern — `recipient` (the target of the burn) is also user-supplied with no caller-equality check — but `transfer` is the direct theft vector. [1](#0-0) 

The `mint` and `burn` cases derive the denom from `contract.Caller()` as well, but the `transfer` case is uniquely dangerous because it moves value *from* an arbitrary third-party address: [2](#0-1) [3](#0-2) 

### Impact Explanation
**Critical — Unauthorized transfer of precompile-controlled assets.**

Any EVM contract at address `A` can call `bank.transfer(victimAddress, attackerAddress, N)` and the precompile will execute `bankKeeper.SendCoins(victimAddress, attackerAddress, evm/A coins)` with no consent from `victimAddress`. All holders of `evm/A` tokens can be drained in a single transaction. This matches the allowed Critical impact: *"Unauthorized transfer … for … precompile-controlled assets."*

### Likelihood Explanation
The `evm/` denom is minted by contracts that call `bank.mint`. Any contract that has previously minted `evm/<address>` tokens to users (e.g., as part of a DeFi protocol, liquidity pool, or wrapped-asset scheme) can later call `transfer` to reclaim all of those tokens from every holder. The attacker needs only to deploy a contract and have users hold its associated denom — a realistic scenario for any token built on the bank precompile.

### Recommendation
Add a caller-equality guard in the `transfer` branch before executing `SendCoins`:

```go
case TransferMethodName:
    ...
    sender := args[0].(common.Address)
    if sender != contract.Caller() {
        return nil, errors.New("sender must equal caller")
    }
    ...
```

Alternatively, remove the `sender` argument entirely and derive `from` from `contract.Caller()`, consistent with how `denom` is already derived. If third-party-initiated transfers are intentional, an on-chain allowance mapping (analogous to ERC-20 `approve`/`transferFrom`) must be introduced.

### Proof of Concept

1. Attacker deploys `MaliciousToken` at address `A`.
2. `MaliciousToken` calls `bank.mint(alice, 1_000_000)` — Alice now holds `1 000 000 evm/A` tokens.
3. Alice uses these tokens in a DeFi protocol, believing she controls them.
4. Attacker calls `bank.transfer(alice, attacker, 1_000_000)` from `MaliciousToken`.
5. The precompile executes `bankKeeper.SendCoins(alice, attacker, 1_000_000 evm/A)` — no approval from Alice, no revert.
6. Alice's entire balance is stolen in one transaction.

The same call can be looped over every holder address in a single block, draining all `evm/A` balances atomically. [4](#0-3)

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
